# NomadSnapshot reference

A `NomadSnapshot` takes Raft snapshots of a `NomadCluster` in the same
or different namespace, storing them in a local PVC, S3, GCS, or Azure
Blob backend. It runs in one of two modes, selected by whether
`spec.schedule` is present:

- **Recurring** (`schedule` set): a long-lived snapshot-agent
  Deployment takes a snapshot every `schedule.interval`.
  `status.operation` is `Deployment`; `status.nextScheduled` projects
  the next run.
- **One-shot** (`schedule` omitted): a Job runs the agent once
  (`interval = "0"`), takes a single snapshot, and exits.
  `status.operation` is `Job` and `status.phase` walks
  `Running → Succeeded|Failed`. One NomadSnapshot without a schedule
  performs one snapshot; delete and recreate it (or toggle modes) for
  another.

Editing `spec.schedule` on/off switches modes: the operator deletes the
old mode's workload and creates the new one. The switch is **rejected
at admission while a one-shot Job is still running** (wait for
`status.phase` to leave `Running`). Target configuration is identical
across modes.

Changing `spec.target` or `spec.schedule` on a recurring NomadSnapshot
updates the agent config and rolls the Deployment automatically - the
pod template carries a `checksum/config` annotation, so the agent
always runs the current config. The rendered config is stored in the
`<snapshot>-snapshot-config` Secret because S3 and Azure credentials are
part of the provider stanza. Its name is reported in
`status.configSecretName`. A failed one-shot Job sets the
`Degraded` condition and emits a `SnapshotDegraded` Warning Event.

**Restore compatibility.** Snapshots restore only to the same Nomad
version that took them. `status.nomadVersion` mirrors the referenced
cluster's version (what snapshots are currently taken against - it
follows upgrades); for one-shot artifacts,
`status.lastSnapshot.nomadVersion` is frozen at Job completion. Check
one of these against the restore-target cluster before restoring. The
full restore procedure is in the
[disaster-recovery runbook](../runbooks/disaster-recovery.md).

## Spec

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `clusterRef.name` | `string` | | Name of the target NomadCluster. **Immutable** - retargeting would orphan the minted ACL credentials, so delete and recreate instead (the finalizer cleans up) |
| `clusterRef.namespace` | `string` | | Not supported (admission-rejected): the NomadCluster must be in the NomadSnapshot's own namespace, because the agent pod mounts the cluster's TLS Secret and pods cannot mount Secrets across namespaces |
| `schedule` | `object` | | Optional. Present = recurring agent Deployment; omitted = one-shot Job |
| `schedule.interval` | `string` | `1h` | Interval between snapshots. Must be a Go duration string (e.g. `1h`, `90m`, `1h30m`) - pattern-validated at admission |
| `schedule.retain` | `int` | `24` | Number of snapshots to retain (minimum 1) |
| `schedule.stale` | `bool` | `false` | Allow reading from a non-leader for snapshots |
| `resources` | `ResourceRequirements` | | CPU/memory requests and limits for the snapshot agent |
| `nodeSelector` | `map[string]string` | | Node selector for the snapshot agent pod |
| `tolerations` | `[]Toleration` | | Tolerations for the snapshot agent pod |

## Storage Targets

Exactly one target must be specified.

**Local PVC** (`spec.target.local`):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | `string` | `/snapshots` | Path within the PVC |
| `size` | `string` | `10Gi` | PVC size |
| `storageClassName` | `string` | | Storage class. Uses cluster default if empty |

**S3** (`spec.target.s3`):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bucket` | `string` | | S3 bucket name |
| `region` | `string` | | AWS region |
| `endpoint` | `string` | | Endpoint URL for S3-compatible storage |
| `forcePathStyle` | `bool` | `false` | Force path-style URLs |
| `credentialsSecretRef.name` | `string` | | Secret with `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. Falls back to ambient AWS identity if omitted |

**GCS** (`spec.target.gcs`):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bucket` | `string` | | GCS bucket name |
| `credentialsSecretRef.name` | `string` | | Secret with `GOOGLE_APPLICATION_CREDENTIALS`. Falls back to ambient GCP identity if omitted |

**Azure Blob** (`spec.target.azure`):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `container` | `string` | | Azure container name |
| `accountName` | `string` | | Storage account name |
| `credentialsSecretRef.name` | `string` | | Secret with `AZURE_BLOB_ACCOUNT_KEY` |

Credential delivery is provider-specific because the snapshot agent's
backends expose different authentication surfaces:

| Provider | Settings and credential delivery |
|----------|----------------------------------|
| S3 | `bucket`, `region`, endpoint settings, `access_key_id`, and `secret_access_key` are rendered together in `aws_storage`. When `credentialsSecretRef` is omitted, the AWS SDK uses ambient identity. |
| Azure Blob | `account_name`, `account_key`, and `container_name` are rendered together in `azure_blob_storage`. The agent does not read an Azure account-key environment variable. |
| GCS | Agent-imposed exception: `google_storage` accepts only `bucket`. A referenced service-account key remains mounted as a file with `GOOGLE_APPLICATION_CREDENTIALS`; when omitted, Application Default Credentials use ambient identity. |

The operator reads referenced credential Secrets before rendering. A
missing Secret reports `Ready=False` with reason
`CredentialsSecretNotFound`; an absent or empty required key reports
`CredentialsSecretInvalid`. Secret changes enqueue reconciliation. For
S3 and Azure, the credentials are included in `checksum/config`, so
rotation rolls a recurring Deployment onto the new config.

### Credential custody

Because the agent reads credentials from its
config file only, the operator embeds the values from
`credentialsSecretRef` into the rendered `<snapshot>-snapshot-config`
Secret. The same credentials therefore exist in two Secrets in the
namespace: the one you manage, and the rendered artifact. Both are
Secret-class objects - plan etcd encryption and namespace RBAC
accordingly, and treat access to either as access to the storage
backend. Rotation flows from your Secret; the rendered copy converges
within one reconcile. The server configuration Secret follows the same
custody model for the gossip key and keyring tokens. The full trust
boundary and threat inventory is in the
[threat model](../threat-model/README.md).

Ambient identity for S3 and GCS targets carries the same pod-identity
caveat as [server keyrings](../guides/keyrings.md): node-level
identities work without extra wiring, while IRSA and GKE Workload
Identity require out-of-band annotation of the ServiceAccount.

## Snapshot ACL Token

Snapshots **require ACLs** on the referenced NomadCluster
(`spec.server.acl.enabled: true`, the default): the agent authenticates
with a dedicated token the operator mints. A cluster with ACLs disabled
is reported as a terminal misconfiguration - `Ready=False` with reason
`ACLsDisabled` and a Warning Event. It is not reported as a transient wait.

The operator creates a dedicated ACL policy with `snapshot-save` and
`license-read` capabilities and a token bound to that policy. The token
is stored in the `<snapshot>-snapshot-token` Secret; if the operator
re-mints it (for example after an out-of-band deletion in Nomad), a
`checksum/secrets` annotation rolls the recurring agent onto the new
token. The policy name is tracked in `status.policyName`. Both the
token and policy are cleaned up from Nomad when the NomadSnapshot is
deleted.

## Example

```yaml
apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadSnapshot
metadata:
  name: nomad-backup
spec:
  clusterRef:
    name: nomad
  schedule:
    interval: "1h"
    retain: 24
  target:
    local:
      size: 10Gi
```


