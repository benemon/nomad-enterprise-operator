# Disaster Recovery Runbook

Recovery procedures for operator-managed Nomad Enterprise clusters.
Commands assume the cluster is named `nomad` in namespace `nomad-system`;
substitute your values.

## Before any restore: two checks

**1. Version compatibility.**

> You can only restore snapshots to the same Nomad Enterprise version
> which took the backup.

*- HashiCorp Validated Design: Nomad Enterprise Operating Guide*

The operator records this for you:

```sh
# What version are snapshots currently being taken against?
kubectl get nomadsnapshot <name> -o jsonpath='{.status.nomadVersion}'
# For a one-shot artifact: the version frozen at completion
kubectl get nomadsnapshot <name> -o jsonpath='{.status.lastSnapshot.nomadVersion}'
# The restore-target cluster must match:
kubectl get nomadcluster nomad -o jsonpath='{.status.nomadVersion}'
```

**2. Keyring reachability.** What a snapshot needs at restore time
depends on the keyring of the cluster that took it:

- **`aead` (the default)**: the snapshot restores with no external
  dependency; treat the artifact itself as key material (see
  [Keyrings](../guides/keyrings.md)).
- **External KMS keyring**: the restoring cluster needs the same
  `spec.server.keyrings` entries and reachability to at least one of
  them. Restore-time key semantics are Nomad's - see [Nomad key
  management](https://developer.hashicorp.com/nomad/docs/manage/key-management).

## Scenario 1: Lost Raft quorum

Symptoms: `Ready=False` with reason `AutopilotUnhealthy`, leader
election failing, writes rejected.

If the pods are gone but their PVCs survive (node failure, eviction),
recovery is automatic: the StatefulSet reschedules pods onto the same
PVCs and Raft re-forms. Verify rather than intervene:

```sh
kubectl get pods -l app.kubernetes.io/instance=nomad
kubectl get nomadcluster nomad -o jsonpath='{.status.autopilot}'
```

If a **majority of PVCs are lost**, the Raft log is unrecoverable in
place. On multi-server clusters, do not attempt peers.json surgery
inside the StatefulSet - recover by restore: treat it as Scenario 4
(delete the cluster, recreate, restore the latest snapshot).
Single-server clusters are the exception: the start wrapper performs
the peers.json repair itself when a lone server boots with a stale
Raft address (see [single-server address
healing](../guides/scaling.md#single-server-address-healing)).

## Scenario 2: One replica's PVC lost or corrupted

A single lost replica is within Raft fault tolerance (3- and 5-server
clusters). Replace the member; the survivors replicate state to it:

```sh
kubectl delete pvc data-nomad-2 audit-nomad-2 --wait=false
kubectl delete pod nomad-2
# The StatefulSet recreates the pod; fresh PVCs provision; the
# server rejoins and catches up from the leader.
kubectl get nomadcluster nomad -o jsonpath='{.status.autopilot.healthy}'
```

Audit is enabled by default, so each replica carries an `audit-` PVC
beside its `data-` PVC. Delete both for the replaced member.

Autopilot (`cleanup_dead_servers`, operator-owned) removes the stale
Raft entry for the old instance automatically.

## Scenario 3: Accidental CR deletion

Under the default `reclaimPolicy: Delete`, deleting the NomadCluster
removes every labelled PVC with it, data and audit both - recovery is
restore-from-snapshot (Scenario 4). Keep a `NomadSnapshot` schedule
running; it is the recovery mechanism this operator supports.

**If you opted into `reclaimPolicy: Retain`**: the PVCs survive.
A recreated single-server cluster recovers automatically since
operator 0.4.1: the start wrapper detects the lone server's stale
Raft address and repairs it at boot (see [single-server address
healing](../guides/scaling.md#single-server-address-healing)). A
recreated multi-server cluster does not recover automatically. The
recreated pods adopt the old Raft state, which pins peer addresses to
the previous pods' IPs; no member of the new cluster appears in the
stored configuration, no leader can be elected, and the pods
crash-loop (enforced audit blocks the health endpoint while
leaderless, so probes restart the pods before any recovery could
complete). Recovery from retained multi-server PVCs requires Nomad's
manual [outage recovery
procedure](https://developer.hashicorp.com/nomad/docs/manage/outage-recovery),
performed against the crash-looping pods' current IPs and node IDs.
Where a snapshot exists, prefer Scenario 4. It is simpler and
validated end-to-end.

## Scenario 4: Deletion with reclaimPolicy: Delete - restore from snapshot

With `Delete`, the PVCs are gone; recovery is restore-from-snapshot
into a fresh cluster.

1. Create a new NomadCluster. Match the snapshot's Nomad version and,
   if the source cluster used external KMS keyrings, the same
   `spec.server.keyrings` (see the checks above).
2. Wait for `Ready`, then copy the snapshot artifact to a server pod
   and restore:

    ```sh
    kubectl cp ./nomad.snap nomad-0:/tmp/nomad.snap
    kubectl exec nomad-0 -- env NOMAD_TOKEN=$MGMT_TOKEN \
      nomad operator snapshot restore /tmp/nomad.snap
    ```

3. **The restore replaces ACL state.** The restored Raft data contains
   the *source* cluster's ACL tokens and policies; the new cluster's
   operator-minted tokens stop working the moment the restore lands.
   If you hold a management token from the source cluster, delete the
   new cluster's `<cluster>-acl-bootstrap`,
   `<cluster>-operator-management`, and `<cluster>-operator-status`
   Secrets and recreate the bootstrap Secret with the source token
   (key `secret-id`) so the operator can re-mint its tokens; without
   one, use Nomad's ACL bootstrap-reset procedure (write the reset
   index to a server's data directory per Nomad's documentation, then
   delete the operator token Secrets to trigger re-bootstrap). The
   restore path has been validated end-to-end on ACL-disabled
   clusters; the ACL re-sync steps follow Nomad's documented
   behaviour and have not been exercised by this operator's test
   suite.

To extract individual items without touching production:

> To pull individual items from a backup, restore the snapshot to an
> isolated cluster and use the API to retrieve individual items.

*- HashiCorp Validated Design: Nomad Enterprise Operating Guide*

The same-version and keyring-reachability checks apply to the isolated
cluster too.

## Scenario 5: Operator-state loss

Scenarios 1–4 cover the *cluster's* data. The operator also keeps its
own working state in Secrets and ConfigMaps alongside the cluster, and
losing those has consequences ranging from "nothing" to "permanent
data loss" - deleting and redeploying the operator does **not** recover
them. Every operator-created object carries the labels
`app.kubernetes.io/managed-by=nomad-operator` and
`app.kubernetes.io/instance=<cluster>`.

### Custody table

Three custody classes: **self-heals** (the operator regenerates an
equivalent object; loss is harmless), **regenerates destructively**
(the operator regenerates it, but the *new* value diverges from what
the running cluster or its data needs - regeneration is itself the
damage), and **not regenerable** (the operator cannot recreate the
contents; recovery needs a backup or manual procedure).

| Object | Holds | Custody class | On loss |
|---|---|---|---|
| `nomad-keyring-token` Secret | Operator-minted Vault tokens, one key per login-method keyring entry | Self-heals | Next reconcile re-mints and republishes the config (rolls pods once) |
| `nomad-tls` Secret | Server certificate issued from the CA | Self-heals | Reissued from `nomad-ca` |
| `nomad-ca-bundle` ConfigMap | CA trust bundle | Self-heals | Re-derived from `nomad-ca` |
| `nomad-config` Secret | Rendered server config; embeds the gossip key and inline keyring tokens | Self-heals | Re-rendered - *provided* `nomad-gossip` survives |
| `nomad-keyring-state` ConfigMap | Keyring state machine: active/retiring entries and phase | Self-heals **only when `status.keyring.phase` is `Ready`** | Steady state: re-seeded from the spec, no migration, no data loss. Mid-migration: see warning below - retiring entries are forgotten and keys wrapped only by them become **permanently undecryptable** |
| `nomad-gossip` Secret | Serf gossip encryption key | Regenerates destructively | A fresh random key is generated; it no longer matches the ring the running pods formed. The next rolling restart strands new pods outside the old ring - partial outage. Repair-in-place below |
| `nomad-ca` Secret | Operator-generated CA; during rotation also the next/previous CA material (`tls-next.crt/key`, `tls-previous.crt`) | Regenerates destructively | A new CA is generated and everything reissues; anything holding the old bundle distrusts the cluster until refreshed. Mid-rotation loss strands pods on an untrusted chain |
| `nomad-acl-bootstrap`, `nomad-operator-management`, `nomad-operator-status` Secrets | ACL bootstrap and operator management tokens | Not regenerable | Raft is already bootstrapped, so re-bootstrap is rejected (HTTP 400) and the operator permanently loses ACL management. Recover with a held management token or Nomad's bootstrap-reset procedure - see the ACL note in Scenario 4 |

(User-provided Secrets - the license, a user CA, user Vault tokens -
are your custody, not the operator's; they are not in this table.)

### Backup

!!! warning
    Since operator 0.4.1, scaling down deletes the removed ordinals'
    data **and audit** PVCs. That reclamation is permanent and is not
    covered by any snapshot: `NomadSnapshot` captures Raft state, not
    audit logs. Ship audit logs off-cluster if you need them past a
    scale-down.

Capture the operator-state objects by label selector; include them in
any namespace backup tooling (Velero and similar) explicitly:

```sh
kubectl get secret,configmap -n nomad-system \
  -l app.kubernetes.io/managed-by=nomad-operator,app.kubernetes.io/instance=nomad \
  -o yaml > nomad-operator-state.yaml
```

The output contains live credentials and the gossip key - treat the
file as key material.

### Restore

Recreate lost objects with **exactly the same names** in the cluster's
namespace. If the operator has already regenerated an object (gossip,
CA), do not fight the reconciler - pause it first:

```sh
kubectl scale deploy nomad-enterprise-operator-controller-manager \
  -n nomad-enterprise-operator-system --replicas=0
kubectl apply -f nomad-operator-state.yaml   # or recreate the single object
kubectl scale deploy nomad-enterprise-operator-controller-manager \
  -n nomad-enterprise-operator-system --replicas=1
```

**Gossip key repair-in-place** (no backup, pods still running): the
rendered config embeds the ring's current key, so it can be
reconstructed rather than regenerated. With the operator scaled down,
extract `encrypt = "..."` from the config Secret and recreate the
gossip Secret with it:

```sh
KEY=$(kubectl get secret nomad-config -o jsonpath='{.data.server\.hcl}' \
  | base64 -d | sed -n 's/.*encrypt *= *"\([^"]*\)".*/\1/p')
kubectl create secret generic nomad-gossip --from-literal=gossip-key="$KEY"
```

### Warnings

- **Never delete `<cluster>-keyring-state` while
  `status.keyring.phase` is not `Ready`.** The re-seeded state forgets
  the retiring entries and their credentials; after key cleanup, data
  wrapped only by those entries is permanently undecryptable. (The
  re-seed semantics are pinned by unit test in both the safe and the
  destructive case.)
- **Back up the gossip Secret before any namespace backup-restore
  exercise.** It is the one object that regenerates silently into a
  value the running cluster cannot use, and the damage surfaces only
  at the *next* rolling restart - long after the restore looked
  successful.
