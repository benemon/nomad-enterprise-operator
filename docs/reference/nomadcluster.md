# NomadCluster reference

## Top-level Spec

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `replicas` | `int` | `3` | Number of Nomad server replicas. Must be 1, 3, or 5 |
| `image.repository` | `string` | `hashicorp/nomad` | Container image repository |
| `image.tag` | `string` | `2.0.5-ent` | Container image tag. **Pinned to a concrete patch version** (not a floating tag) - see [Image version pinning](../operations/versions.md) |
| `image.digest` | `string` | - | Optional content digest (`sha256:…`). When set, the image reference is `repository@digest` and `tag` is ignored - see [Image version pinning](../operations/versions.md) |
| `image.pullPolicy` | `string` | `Always` | Image pull policy (`Always`, `IfNotPresent`, `Never`) |
| `license.secretName` | `string` | | Name of secret containing the Nomad license, stored under the key `license` (operator-owned). Mutually exclusive with `value` |
| `license.value` | `string` | | Inline license content. The operator creates a managed secret. Mutually exclusive with `secretName` |
| `topology.region` | `string` | `global` | Nomad region name |
| `topology.datacenter` | `string` | | Nomad datacenter name. Defaults to the namespace |
| `persistence.size` | `string` | `10Gi` | Data volume size. Set to empty string to use emptyDir |
| `persistence.storageClassName` | `string` | | Storage class for the data PVC. Uses cluster default if empty |
| `persistence.reclaimPolicy` | `Retain` \| `Delete` | `Delete` | What happens to data PVCs on cluster deletion. `Delete` (default) removes the PVCs with the cluster. `Retain` keeps them - but note that a fully recreated cluster does **not** recover automatically against retained data (Raft pins peer addresses to pod IPs, which change on recreation); recovery is via [NomadSnapshot restore](../runbooks/disaster-recovery.md). The value at deletion time wins |
| `resources` | `ResourceRequirements` | | Standard Kubernetes CPU/memory requests and limits |
| `imagePullSecrets` | `[]LocalObjectReference` | | Image pull secrets for private registries |
| `nodeSelector` | `map[string]string` | | Node selector for pod scheduling |
| `tolerations` | `[]Toleration` | | Tolerations for pod scheduling |
| `topologySpreadConstraints` | `[]TopologySpreadConstraint` | | Topology spread constraints |

## Server Configuration (`spec.server`)

Server-scoped configuration is split across the subsections below:
[TLS](#tls-specservertls), [ACL](#acl-specserveracl),
[Audit](#audit-specserveraudit),
[Garbage Collection](#garbage-collection-specservergc),
[Keyrings](../guides/keyrings.md), and
[Vault Workload Identity](../guides/workload-identity.md).

## TLS (`spec.server.tls`)

mTLS is always enabled. The operator generates and manages all certificates automatically. The only user-facing decision is which CA to use.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.tls.ca.secretName` | `string` | | Secret containing a user-provided CA (`tls.crt` and `tls.key`). If omitted, the operator generates a self-signed CA |
| `server.tls.ca.secretKeys.certificate` | `string` | `tls.crt` | Key name for the CA certificate in the CA secret |
| `server.tls.ca.secretKeys.privateKey` | `string` | `tls.key` | Key name for the CA private key in the CA secret |

See [TLS Configuration](../guides/tls.md) for details.

## ACL (`spec.server.acl`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.acl.enabled` | `bool` | `true` | Enable Nomad ACLs. The operator auto-bootstraps; the token is always stored in `<name>-acl-bootstrap` (operator-owned) |

See [ACL Configuration](../guides/acls.md) for details.

## Autopilot

Autopilot is operator-owned and not configurable:
`cleanup_dead_servers = true` (required for Serf cleanup delegation),
`last_contact_threshold = 200ms`, `max_trailing_logs = 250`,
`server_stabilization_time = 10s` - Nomad's own defaults.

## Audit (`spec.server.audit`)

Delivery guarantee (`enforced`), format (`json`), and rotation
(`24h` × 15 files) are operator-owned. Ship logs with a
sidecar if you need different retention.

Two [audit filters](https://developer.hashicorp.com/nomad/docs/configuration/audit)
ship by default: the `/v1/metrics` endpoint and the `OperationReceived`
half of every `GET`. These drop high-volume, low-value events so
enforced delivery is not gated on scrape traffic under load. The filter
set is operator-owned and not user-configurable.

Audit storage is independent of data storage: when audit is enabled the
StatefulSet always carries a dedicated audit PVC sized per
`server.audit.size`, even when `spec.persistence.size` is empty and
Raft data runs on `emptyDir`. Audit logs survive pod restarts in every
configuration, but a removed ordinal's audit PVC is reclaimed on
scale-down along with its data PVC.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.audit.enabled` | `bool` | `true` | Enable audit logging. Auto-creates a dedicated audit PVC (independent of `spec.persistence`); requires `server.audit.size` |
| `server.audit.size` | `string` | `5Gi` | Audit volume size |
| `server.audit.storageClassName` | `string` | | Storage class for the audit PVC |

## Garbage Collection (`spec.server.gc`)

How long terminal job/eval/alloc history is kept before Nomad garbage
collects it. Every field is optional; an unset field inherits Nomad's
own default, and those defaults are asymmetric by design - batch history
(24h) is kept far longer than disposable non-batch eval state (1h). Tune
these down for high-churn dispatch workloads: dead batch state
accumulates in Raft between GC runs and is the dominant driver of server
memory growth under sustained dispatch load. Only the three history
thresholds are exposed; node, deployment, CSI, and ACL GC keep Nomad's
defaults. Values are Nomad durations (`s`/`m`/`h`, e.g. `30m`, `2h`).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.gc.jobHistory` | `string` | Nomad `4h` | Minimum retention of a dead job (`job_gc_threshold`) |
| `server.gc.batchEvalHistory` | `string` | Nomad `24h` | Minimum retention of a terminal batch evaluation and its allocations (`batch_eval_gc_threshold`) |
| `server.gc.evalHistory` | `string` | Nomad `1h` | Minimum retention of a terminal non-batch evaluation and its allocations (`eval_gc_threshold`) |


## Gossip Encryption (`spec.gossip`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `gossip.secretName` | `string` | | Name of existing secret containing the gossip key under the key `gossip-key` (operator-owned). Auto-generated if empty |

## Services (`spec.services`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `services.external.type` | `string` | `LoadBalancer` | External service type (`LoadBalancer` or `NodePort`) |
| `services.external.loadBalancerIP` | `string` | | Requested IP for LoadBalancer |
| `services.external.annotations` | `map[string]string` | | Annotations on the external service |

## OpenShift (`spec.openshift`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `openshift.enabled` | `bool` | `false` | **Effectively required on OpenShift.** Switches the pod securityContext from a fixed non-root UID to SCC-assigned identity - without it, OpenShift's `restricted-v2` admission rejects the server pods outright and the cluster never schedules. Also enables OpenShift-specific resources (Routes); if true on a cluster without Route CRDs, the operator emits a `RouteCRDMissing` Warning Event and skips Route creation. Set it at creation time: toggling it later requires operator ≥ 0.2.1 to converge the running StatefulSet |
| `openshift.route.enabled` | `bool` | `false` | Create an OpenShift Route. Always uses `reencrypt` termination with `Redirect` |
| `openshift.route.host` | `string` | | Custom hostname. Auto-generated if empty |
| `openshift.route.tls.certificateSecretName` | `string` | | Secret containing a custom external-facing certificate. If omitted, the platform wildcard certificate is used |
| `openshift.route.tls.secretKeys.certificate` | `string` | `tls.crt` | Key name for the certificate in the Route certificate Secret |
| `openshift.route.tls.secretKeys.privateKey` | `string` | `tls.key` | Key name for the private key in the Route certificate Secret |


## Monitoring (`spec.monitoring`)

See the [monitoring guide](../guides/monitoring.md) for the field table,
scrape behaviour, and shipped alerts.

## Spec invariants

The operator ships **no admission webhook** - every invariant is either
CRD-native (enum, pattern, default, or CEL `x-kubernetes-validations`
rule, all enforced by the API server at admission) or enforced by the
operator at reconcile time and surfaced on the `Ready` condition.

Rejected at admission (API server, no operator involvement):

| Invariant | Mechanism |
|-----------|-----------|
| `spec.replicas` must be 1, 3, or 5 | enum |
| Exactly one of `spec.license.secretName` / `spec.license.value` is set | CEL (two rules: at least one, mutually exclusive) |
| `spec.replicas` cannot change while a scale-down is in progress (`status.scaleDown.removedPeers` non-empty) | CEL transition rule |
| `spec.image.tag` matches `^[A-Za-z0-9._-]+$` | pattern |
| `spec.image.digest` matches `^sha256:[a-f0-9]{64}$` | pattern |
| `spec.image.pullPolicy` ∈ Always/IfNotPresent/Never; `spec.services.*.type` ∈ LoadBalancer/NodePort; `spec.persistence.reclaimPolicy` ∈ Retain/Delete | enum |
| Each `keyrings[]` entry configures exactly one provider; entry names unique; at most 8 entries | CEL + listType=map |
| `transit.auth.method` ∈ token/kubernetes/jwt, with exactly the matching per-method block; `mount` required unless `method: token` | enum + CEL |
| `vaults[]` entry names match `^[a-zA-Z][a-zA-Z0-9_-]*$`, unique, at most 8 entries | pattern + listType=map |
| `vaults[].defaultIdentity` requires non-empty `audiences`; `ttl` matches the Nomad duration pattern | required + MinItems + pattern |

Enforced at reconcile time (visible via `kubectl get nomadcluster` and
the `Ready` condition, not an admission error):

| Invariant | Behaviour when violated |
|-----------|------------------------|
| Scaling from ≥ 3 replicas to below 3 requires the `nomad.hashicorp.com/accept-degraded-quorum: "true"` annotation | Scale-down does not start; `Ready` reason `DegradedQuorumNotAccepted`. Operator-side because CRD CEL cannot read `metadata.annotations` |
| Scale-down requires a Raft leader | Scale-down pauses; `Ready` reason `ScaleDownBlocked` |
| `audit.enabled=true` requires `audit.size` | Never violated in practice: `audit.size` defaults to `5Gi` at admission, and the operator falls back to `5Gi` if the field is explicitly cleared |
| Multiple transit keyring entries require a distinct non-empty `keyIDPrefix` on each | `Ready` reason `KeyringInvalid` |
| `spec.trustBundle` references a missing ConfigMap | `Ready` reason `TrustBundleConfigMapNotFound` |

Not validated: the existence of the Secret named by
`spec.license.secretName` is not checked at admission (a missing Secret
surfaces at reconcile time). Anti-affinity has no user-facing knob to
validate - it is operator-owned (see
[Pod placement](../guides/scaling.md#pod-placement)).


## Status

The `NomadCluster` status is available via `kubectl get nomadcluster` or `kubectl get nc`:

```
NAME              PHASE     READY   DESIRED   ADVERTISE        AGE
nomad-enterprise  Running   3       3         10.96.0.15       5m
```

## Status Fields

| Field | Description |
|-------|-------------|
| `status.phase` | Cluster lifecycle phase: `Pending`, `Creating`, `Running`, `Failed` |
| `status.readyReplicas` | Number of ready Nomad server pods |
| `status.currentReplicas` | Current number of Nomad server pods |
| `status.leaderAddress` | Raft leader host:port (RPC address). For the Raft server ID, see `status.autopilot.servers[]` |
| `status.advertiseAddress` | Resolved LoadBalancer address |
| `status.gossipKeySecretName` | Name of the gossip key secret |
| `status.aclBootstrapped` | Whether ACL bootstrap has completed |
| `status.aclBootstrapSecretName` | Secret containing the bootstrap token |
| `status.operatorStatusSecretName` | Secret containing the operator status token |
| `status.operatorStatusPolicyName` | Nomad ACL policy for the operator status token |
| `status.routeHost` | Assigned OpenShift Route hostname |
| `status.certificateAuthority.source` | `operator-generated` or `user-provided` |
| `status.certificateAuthority.expiryTime` | CA certificate expiry |
| `status.certificateAuthority.subject` | CA certificate subject DN |
| `status.nomadVersion` | Nomad agent version observed via `/v1/agent/self` (e.g. `1.11.0+ent`); empty until the first successful probe |
| `status.keyring` | Keyring set state: `phase` (`Ready`/`Introducing`/`Rotating`/`Retiring`/`Degraded`), `active[]`, `retiring[]`, `retirementPending` for the old-key cleanup tail, and `tokenExpiry` for operator-managed Vault tokens |
| `status.license.valid` | Whether the Nomad license is valid |
| `status.license.expirationTime` | License expiry time |
| `status.license.features` | Licensed features |
| `status.autopilot.healthy` | Whether autopilot considers the cluster healthy |
| `status.autopilot.failureTolerance` | Number of server failures the cluster can tolerate |
| `status.autopilot.voters` | Number of voting servers |
| `status.autopilot.servers[]` | Per-server health details |

## Conditions

`status.conditions[]` contains exactly **one** condition, type `Ready`.
Everything a per-resource condition used to say lives in the status
sub-fields above - the condition tells you *whether* the cluster is
healthy; the sub-fields tell you *why*. `Ready=True` requires the
StatefulSet at its desired ready replica count, a valid license, and
healthy autopilot (an unreachable probe does not fail Ready - the
sub-field keeps its last-known value).

`Ready=False` reasons:

| Reason | Meaning |
|--------|---------|
| `WaitingForReplicas` | StatefulSet below its desired ready count |
| `LicenseExpired` | Nomad Enterprise license invalid - see `status.license` |
| `AutopilotUnhealthy` | Raft autopilot reports unhealthy - see `status.autopilot` |
| `LicenseSecretNotFound` | `spec.license.secretName` references a Secret that does not exist - create it; the operator re-reconciles the moment it appears |
| `TrustBundleConfigMapNotFound` | `spec.trustBundle.configMapRef.name` references a ConfigMap that does not exist |
| `CredentialsSecretNotFound` | A NomadSnapshot target references a Secret that does not exist |
| `CredentialsSecretInvalid` | A NomadSnapshot target's credential Secret is missing a required key or contains an empty value |
| `LicenseSecretInvalid` | The license Secret exists but is missing the `license` key |
| `CAExpired` | The CA certificate has expired; TLS handshakes fail cluster-wide - see `status.certificateAuthority`. Takes precedence over `WaitingForReplicas` so the cascading pod failures are attributed to their cause |
| `PhaseFailed` | A reconcile phase errored; the message names the phase |
| `Reconciling` | A phase requested requeue (generic wait) |
| `WaitingForNomadAPI` | Pods are ready but the Nomad API is not answering yet (ordinary during first boot); ACL bootstrap retries shortly |
| `ScaleDownBlocked` | Scale-down waiting on a Raft leader |
| `DegradedQuorumNotAccepted` | Scale-down below 3 replicas lacks the [opt-in annotation](../guides/scaling.md#scaling-down) |
| `KeyringInvalid` | Keyring spec fails reconcile-time validation (e.g. multi-transit without distinct `keyIDPrefix`) |
| `KeyringRotationPending` | A keyring migration is waiting to rotate or clean up root keys; the message carries the underlying cause |
| `KeyringVaultLoginFailed` | Vault login for a keyring entry failed; the message names the entry |
| `KeyringVaultReviewerDenied` | Vault cannot validate ServiceAccount tokens - see [Who needs `system:auth-delegator`](../guides/keyrings.md#who-needs-systemauth-delegator) |
| `KeyringCredentialsUnavailable` | A keyring entry's credentials Secret is missing or malformed; the message names the entry and Secret |


