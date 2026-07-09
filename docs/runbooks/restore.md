# Runbook: Restoring a Nomad Cluster from a Snapshot

Audience: a human operator restoring Raft state into an
operator-managed NomadCluster from a snapshot taken by a NomadSnapshot
resource. This runbook covers the operator-specific mechanics —
Secrets, addresses, and reconciler behaviour. For the semantics of
`nomad operator snapshot restore` itself, see the upstream Nomad
documentation.

A restore **replaces the cluster's entire Raft state** — jobs,
allocations metadata, ACLs, everything — with the state at snapshot
time. Read [Operator behaviour during restore](#operator-behaviour-during-restore)
before you start: tokens minted after the snapshot was taken will no
longer exist after the restore.

## Snapshot retrieval

The snapshot agent writes files named `nomad-<timestamp>.snap` under
the configured target. Pull the snapshot you want to a working
directory. In each example, substitute values from your NomadSnapshot's
`spec.target`.

**S3** (`spec.target.s3`):

```sh
aws s3 ls s3://<bucket>/                       # find the latest .snap
aws s3 cp s3://<bucket>/nomad-<timestamp>.snap ./restore.snap
```

**GCS** (`spec.target.gcs`):

```sh
gcloud storage ls gs://<bucket>/
gcloud storage cp gs://<bucket>/nomad-<timestamp>.snap ./restore.snap
```

**Azure Blob** (`spec.target.azure`):

```sh
az storage blob list --account-name <accountName> --container-name <container> -o table
az storage blob download --account-name <accountName> --container-name <container> \
  --name nomad-<timestamp>.snap --file ./restore.snap
```

**Local PVC** (`spec.target.local`): the PVC is named
`<snapshot>-snapshots` and mounted at `spec.target.local.path`
(default `/snapshots`) in the agent pod. If no agent pod is running,
mount the PVC into a temporary pod first.

```sh
kubectl get pods -n <ns> -l app.kubernetes.io/instance=<snapshot-name>
kubectl exec -n <ns> <agent-pod> -- ls /snapshots
kubectl cp <ns>/<agent-pod>:/snapshots/nomad-<timestamp>.snap ./restore.snap
```

## Authentication

Restore requires a token with `operator:write`. Use the operator's
management token (`<cluster>-operator-management`, created by the
operator at ACL bootstrap):

```sh
NOMAD_TOKEN=$(kubectl get secret <cluster>-operator-management -n <ns> \
  -o jsonpath='{.data.secret-id}' | base64 -d)
```

Fallback: the bootstrap token in `<cluster>-acl-bootstrap` (same
`secret-id` key) is a full management token. Prefer the management
token; reach for bootstrap only if the management token predates the
snapshot you are restoring (see the last section).

## Reachability

The cluster API is at `https://<cluster>-internal.<ns>.svc:4646` from
inside the Kubernetes cluster (or the LoadBalancer address in
`status.advertiseAddress` from outside). mTLS is always on; the CA
certificate lives in the `<cluster>-tls` Secret under `ca.crt`:

```sh
kubectl get secret <cluster>-tls -n <ns> -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt
```

## Pre-restore checks

Do not restore into a cluster in flux. Verify all three:

```sh
# 1. A Raft leader exists (empty means no leader — fix that first)
kubectl get nomadcluster <cluster> -n <ns> -o jsonpath='{.status.leaderAddress}'

# 2. Ready condition is True
kubectl get nomadcluster <cluster> -n <ns> \
  -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'

# 3. No in-flight scale-down (must print nothing)
kubectl get nomadcluster <cluster> -n <ns> -o jsonpath='{.status.scaleDown}'
```

Also pause any recurring NomadSnapshot agents targeting this cluster
(delete the NomadSnapshot or scale its `<snapshot>-snapshot-agent`
Deployment to zero) so a scheduled snapshot doesn't capture
mid-restore state.

## Restore execution example

Illustrative only — the operator deliberately ships no restore Job
template; restore is a deliberate human action. From a pod inside the
cluster (the Nomad image already has the CLI):

```sh
kubectl run nomad-restore -n <ns> --rm -it --restart=Never \
  --image=<same image as the cluster, e.g. hashicorp/nomad-enterprise:2.0.0-ent> \
  --overrides='{"spec":{"volumes":[{"name":"tls","secret":{"secretName":"<cluster>-tls"}}],
    "containers":[{"name":"nomad-restore","image":"<image>","stdin":true,"tty":true,
    "command":["sh"],
    "env":[{"name":"NOMAD_ADDR","value":"https://<cluster>-internal.<ns>.svc:4646"},
           {"name":"NOMAD_CACERT","value":"/tls/ca.crt"},
           {"name":"NOMAD_TOKEN","value":"<token from Authentication step>"}],
    "volumeMounts":[{"name":"tls","mountPath":"/tls","readOnly":true}]}]}}' \
  -- sh

# then, inside the pod (copy restore.snap in via kubectl cp first):
nomad operator snapshot restore restore.snap
```

The restore is submitted to the leader and replicated to all peers; a
rolling restart is not required.

## Post-restore verification

```sh
# Leader present and peers agree
kubectl get nomadcluster <cluster> -n <ns> -o jsonpath='{.status.leaderAddress}'
kubectl get nomadcluster <cluster> -n <ns> -o jsonpath='{.status.autopilot}'

# Status re-enriched by the operator (license, version, autopilot) —
# lastReconcileTime advances within the 5-minute steady-state cadence
kubectl get nomadcluster <cluster> -n <ns> -o jsonpath='{.status.lastReconcileTime}'

# Nomad-side sanity from inside the restore pod
nomad server members
nomad job status
```

Verify workload state matches your expectation of the snapshot's point
in time, not the pre-restore present.

## Operator behaviour during restore

**The NomadClusterReconciler does not need to be paused.** Definitive
reasoning:

- The operator's Kubernetes-side writes (StatefulSet, ConfigMaps,
  Secrets, PDB) are unaffected by Raft contents and do not interfere
  with the restore pod.
- Its Nomad-side reads (health, license, autopilot, version probes)
  are non-fatal by design; a brief failure window during the restore
  produces at most a transient status blip.
- Its Nomad-side writes are limited to the operator-owned ACL policies
  (reconciled by diff each pass) and Raft peer removal during
  scale-down. The pre-restore checks above ensure no scale-down is in
  flight.

**What a restore does to operator tokens — read this.** A snapshot
contains the ACL state at snapshot time. Restoring it deletes any
tokens and policies created *after* the snapshot. Consequences:

- The bootstrap token survives (it predates every snapshot the cluster
  ever took) — this is one of the reasons its Secret is kept until
  cluster deletion.
- The operator's management/status tokens and any snapshot-agent
  tokens survive only if they existed at snapshot time. If they were
  re-minted after, the Kubernetes Secrets now hold **invalidated
  tokens**, and operator API calls will start failing with permission
  errors.
- Recovery: delete the affected Secrets and let the operator re-mint
  from the bootstrap token on the next reconcile:

  ```sh
  kubectl delete secret <cluster>-operator-management <cluster>-operator-status -n <ns>
  kubectl delete secret <snapshot>-snapshot-token -n <ns>   # per NomadSnapshot, if any
  ```

  The operator-owned ACL *policies* need no action — the policy
  reconciler rewrites them to desired state on the next pass.
