[![E2E Tests](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/test-e2e.yml/badge.svg)](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/test-e2e.yml)
[![Lint](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/lint.yml/badge.svg)](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/lint.yml)
[![Tests](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/test.yml/badge.svg)](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/test.yml)

# nomad-enterprise-operator

> **Community Project** - This operator is not maintained or supported by
> HashiCorp. It is an independent community project. The `nomad.hashicorp.com`
> API group used by CRDs in this project is a structural identifier inherited
> from the Nomad ecosystem, not an endorsement or affiliation.

A Kubernetes operator for deploying and managing HashiCorp Nomad Enterprise server clusters on OpenShift and Kubernetes. It manages the full lifecycle through two custom resources: `NomadCluster` for server clusters and `NomadSnapshot` for automated Raft snapshots.

## Contributing

Contributions follow the workflow and standards defined in [`CONTRIBUTING.md`](CONTRIBUTING.md). Work is tracked in [`bd`](https://github.com/gastownhall/beads) (issue prefix: `neo-`); the full backlog is mirrored in [`docs/bd-backlog-2026-06-06.md`](docs/bd-backlog-2026-06-06.md). Per-issue templates: [`.bd/issue-template.md`](.bd/issue-template.md); PR descriptions: [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md).

## Security posture

The v1alpha2 release is deliberately scoped: it prioritises operational stability, runtime security, developer maintainability, and value delivery. Some supply-chain hardening is **deliberately deferred** to a future release:

- **Container images are not signed** (no cosign signatures attached). Verification by signature is not available against the upstream-published images.
- **No SBOM** is attached to releases. Software composition analysis must be performed against the image itself by the consumer's tooling.

For environments with CISO-gated container-image requirements (signed images, SBOM, provenance attestation), the recommended workaround is:

1. Pull the upstream image (`quay.io/benjamin_holmes/nomad-enterprise-operator:v<version>`).
2. Scan with your preferred scanner (Trivy, Snyk, Grype, etc.).
3. Re-tag and push to your internal registry; sign per your organisation's policy (cosign, notation, etc.).
4. Deploy from the internal-registry tag; override the operator image in the deployment manifest.

The operator's runtime is compatible with any image that exposes the same entrypoint and binary contract, so this fork-and-sign workflow does not require code changes. See the design review's §4.6 and platform-engineer review's §3.8 / §3.3 for the full discussion of this deferral.

### Bootstrap token Secret lifecycle

The ACL bootstrap token Secret (`<cluster>-acl-bootstrap`) deliberately
has **no ownerReference** to its NomadCluster. If it did, Kubernetes
garbage collection could remove it during cluster deletion before the
operator's finalizer has used the token for Nomad-side ACL cleanup.
Instead the Secret carries the label
`nomad.hashicorp.com/cluster: <cluster>` and the finalizer deletes it
explicitly — last, after the (best-effort) Nomad-side cleanup.

The consequence: if the finalizer never completes — operator
uninstalled before the cluster was deleted, namespace force-deleted
with the finalizer stripped, etc. — the bootstrap Secret is orphaned
with **no garbage collection**. It contains a Nomad management token,
so orphans are worth sweeping for. List all bootstrap Secrets and
cross-reference against live clusters:

```sh
kubectl get secrets -A -l nomad.hashicorp.com/cluster
kubectl get nomadclusters -A
```

Any Secret whose `nomad.hashicorp.com/cluster` label names a cluster
that no longer exists can be deleted (the token it holds died with the
cluster). The operator does not scan for orphans itself — that would
require a periodic cluster-wide sweep, which is out of scope.

## Prerequisites

- Go v1.25.0+ (development only)
- Docker v17.03+
- kubectl v1.11.3+
- Access to a Kubernetes v1.11.3+ cluster
- A Nomad Enterprise license

## Getting Started

### Container Images

All images are published to quay.io:

| Image | Description |
|-------|-------------|
| `quay.io/benjamin_holmes/nomad-enterprise-operator:v<version>` | Operator controller |
| `quay.io/benjamin_holmes/nomad-enterprise-operator-bundle:v<version>` | OLM bundle |
| `quay.io/benjamin_holmes/nomad-enterprise-operator-catalog:v<version>` | OLM catalog |

### Install on OpenShift (OLM)

1. Create a CatalogSource to make the operator available in OperatorHub:

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: nomad-enterprise-operator-catalog
  namespace: openshift-marketplace
spec:
  sourceType: grpc
  image: quay.io/benjamin_holmes/nomad-enterprise-operator-catalog:v<version>
  displayName: Nomad Enterprise Operator
  publisher: benemon
  updateStrategy:
    registryPoll:
      interval: 30m
```

2. Create a namespace and OperatorGroup for the operator:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: nomad-enterprise-operator-system
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: nomad-enterprise-operator
  namespace: nomad-enterprise-operator-system
spec:
  targetNamespaces:
    - nomad-enterprise-operator-system
```

3. Create a Subscription to install the operator:

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: nomad-enterprise-operator
  namespace: nomad-enterprise-operator-system
spec:
  channel: alpha
  name: nomad-enterprise-operator
  source: nomad-enterprise-operator-catalog
  sourceNamespace: openshift-marketplace
  installPlanApproval: Automatic
```

Alternatively, once the CatalogSource is created, the operator appears in
the OpenShift console under **OperatorHub** and can be installed from the UI.
The suggested namespace `nomad-enterprise-operator-system` will be pre-filled.

### Install with YAML manifests

Build and apply the consolidated installer:

```sh
make build-installer IMG=quay.io/benjamin_holmes/nomad-enterprise-operator:v<version>
kubectl apply -f dist/install.yaml
```

### Minimal Example

The only required field is `license`. Everything else uses sensible defaults (3 replicas, ACLs enabled, auto-generated gossip key, 10Gi persistent storage):

```yaml
apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: nomad
spec:
  license:
    secretName: nomad-license
```

### Uninstall

```sh
kubectl delete -k config/samples/
make uninstall
make undeploy
```

## NomadCluster CRD Reference

### Top-level Spec

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `replicas` | `int` | `3` | Number of Nomad server replicas. Must be 1, 3, or 5 |
| `image.repository` | `string` | `hashicorp/nomad` | Container image repository |
| `image.tag` | `string` | `2.0.0-ent` | Container image tag. **Pinned to a concrete patch version** (not a floating tag) — see [Image version pinning](#image-version-pinning) |
| `image.pullPolicy` | `string` | `Always` | Image pull policy (`Always`, `IfNotPresent`, `Never`) |
| `license.secretName` | `string` | | Name of secret containing the Nomad license, stored under the key `license` (operator-owned per ADR 0003). Mutually exclusive with `value` |
| `license.value` | `string` | | Inline license content. The operator creates a managed secret. Mutually exclusive with `secretName` |
| `topology.region` | `string` | `global` | Nomad region name |
| `topology.datacenter` | `string` | | Nomad datacenter name. Defaults to the namespace |
| `persistence.size` | `string` | `10Gi` | Data volume size. Set to empty string to use emptyDir |
| `persistence.storageClassName` | `string` | | Storage class for the data PVC. Uses cluster default if empty |
| `persistence.reclaimPolicy` | `Retain` \| `Delete` | `Retain` | What happens to data PVCs on cluster deletion. `Retain` (default) preserves Raft state so an accidentally deleted cluster can be recreated against its old data; `Delete` removes the PVCs with the cluster. The value at deletion time wins |
| `resources` | `ResourceRequirements` | | Standard Kubernetes CPU/memory requests and limits |
| `imagePullSecrets` | `[]LocalObjectReference` | | Image pull secrets for private registries |
| `nodeSelector` | `map[string]string` | | Node selector for pod scheduling |
| `tolerations` | `[]Toleration` | | Tolerations for pod scheduling |
| `topologySpreadConstraints` | `[]TopologySpreadConstraint` | | Topology spread constraints |

### Server Configuration (`spec.server`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|

### TLS (`spec.server.tls`)

mTLS is always enabled. The operator generates and manages all certificates automatically. The only user-facing decision is which CA to use.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.tls.ca.secretName` | `string` | | Secret containing a user-provided CA (`tls.crt` and `tls.key`). If omitted, the operator generates a self-signed CA |
| `server.tls.ca.secretKeys.certificate` | `string` | `tls.crt` | Key name for the CA certificate in the CA secret |
| `server.tls.ca.secretKeys.privateKey` | `string` | `tls.key` | Key name for the CA private key in the CA secret |

See [TLS Configuration](#tls-configuration) for details.

### ACL (`spec.server.acl`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.acl.enabled` | `bool` | `true` | Enable Nomad ACLs. The operator auto-bootstraps; the token is always stored in `<name>-acl-bootstrap` (operator-owned per ADR 0003) |

See [ACL Configuration](#acl-configuration) for details.

### Autopilot

Autopilot is operator-owned per ADR 0003 and not configurable:
`cleanup_dead_servers = true` (required for Serf cleanup delegation),
`last_contact_threshold = 200ms`, `max_trailing_logs = 250`,
`server_stabilization_time = 10s` — Nomad's own defaults.

### Audit (`spec.server.audit`)

Delivery guarantee (`enforced`), format (`json`), and rotation
(`24h` × 15 files) are operator-owned per ADR 0003. Ship logs with a
sidecar if you need different retention.

Audit storage is independent of data storage: when audit is enabled the
StatefulSet always carries a dedicated audit PVC sized per
`server.audit.size`, even when `spec.persistence.size` is empty and
Raft data runs on `emptyDir`. Audit logs survive pod restarts in every
configuration. The operator emits a one-shot `AuditPVCCreated` Event
(debounced via `status.auditPVCMigrated`) the first time the audit PVC
binds.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.audit.enabled` | `bool` | `true` | Enable audit logging. Auto-creates a dedicated audit PVC (independent of `spec.persistence`); requires `server.audit.size` |
| `server.audit.size` | `string` | `5Gi` | Audit volume size |
| `server.audit.storageClassName` | `string` | | Storage class for the audit PVC |

### Gossip Encryption (`spec.gossip`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `gossip.secretName` | `string` | | Name of existing secret containing the gossip key under the key `gossip-key` (operator-owned per ADR 0003). Auto-generated if empty |

### Services (`spec.services`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `services.external.type` | `string` | `LoadBalancer` | External service type (`LoadBalancer` or `NodePort`) |
| `services.external.loadBalancerIP` | `string` | | Requested IP for LoadBalancer |
| `services.external.annotations` | `map[string]string` | | Annotations on the external service |

### OpenShift (`spec.openshift`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `openshift.enabled` | `bool` | `false` | Enable OpenShift-specific resources (Routes). If true on a cluster without Route CRDs, the operator emits a `RouteCRDMissing` Warning Event and skips Route creation |
| `openshift.route.enabled` | `bool` | `false` | Create an OpenShift Route. Always uses `reencrypt` termination with `Redirect` |
| `openshift.route.host` | `string` | | Custom hostname. Auto-generated if empty |
| `openshift.route.tls.certificateSecretName` | `string` | | Secret containing a custom external-facing certificate. If omitted, the platform wildcard certificate is used |
| `openshift.route.tls.secretKeys.certificate` | `string` | `tls.crt` | Key name for the certificate in the Route certificate Secret |
| `openshift.route.tls.secretKeys.privateKey` | `string` | `tls.key` | Key name for the private key in the Route certificate Secret |

### Monitoring (`spec.monitoring`)

ServiceMonitor and PrometheusRule are created when monitoring is enabled
AND the Prometheus Operator CRDs (`monitoring.coreos.com/v1`) are installed
— on any Kubernetes distribution, independent of `openshift.enabled`.
Clusters without the CRDs skip monitoring resources cleanly.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `monitoring.enabled` | `bool` | `true` | Create ServiceMonitor |
| `monitoring.prometheusRulesEnabled` | `bool` | `false` | Create PrometheusRule |

Scrape cadence is operator-owned per ADR 0003 (30s interval, 10s
timeout); ServiceMonitor label/relabel customisation belongs in
Prometheus configuration.

### Pod placement

Pod anti-affinity is operator-owned per ADR 0003: preferred scheduling,
weight 100, `kubernetes.io/hostname` topology, applied when
`replicas >= 3`. For multi-zone distribution use the standard
`spec.topologySpreadConstraints` field.

### Spec invariants

The operator ships **no admission webhook** — every invariant is either
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
| `spec.image.pullPolicy` ∈ Always/IfNotPresent/Never; `spec.services.*.type` ∈ LoadBalancer/NodePort; `spec.persistence.reclaimPolicy` ∈ Retain/Delete | enum |

Enforced at reconcile time (visible via `kubectl get nomadcluster` and
the `Ready` condition, not an admission error):

| Invariant | Behaviour when violated |
|-----------|------------------------|
| Scaling from ≥ 3 replicas to below 3 requires the `nomad.hashicorp.com/accept-degraded-quorum: "true"` annotation | Scale-down does not start; `Ready` reason `DegradedQuorumNotAccepted`. Operator-side because CRD CEL cannot read `metadata.annotations` |
| Scale-down requires a Raft leader | Scale-down pauses; `Ready` reason `ScaleDownBlocked` |
| `audit.enabled=true` requires `audit.size` | Never violated in practice: `audit.size` defaults to `5Gi` at admission, and the operator falls back to `5Gi` if the field is explicitly cleared |

Not validated: the existence of the Secret named by
`spec.license.secretName` is not checked at admission (a missing Secret
surfaces at reconcile time). Anti-affinity has no user-facing knob to
validate — it is operator-owned per ADR 0003 (see
[Pod placement](#pod-placement)).

## Image version pinning

The default value of `spec.image.tag` is a **concrete patch version** (e.g. `2.0.0-ent`), not a floating tag like `1.11-ent` or `2-ent`. This is a deliberate safety measure for Raft cluster integrity.

Upgrading a cluster to a new Nomad version is a user-driven
`spec.image.tag` change. **Snapshot before you upgrade** — the operator
deliberately does not do it for you. The full procedure, including the
pre-upgrade one-shot snapshot and rollback guidance, is in
[docs/runbooks/upgrade.md](docs/runbooks/upgrade.md).

**Why a pinned default matters.** Nomad is a Raft consensus cluster. A floating tag (one that resolves to "whatever the latest patch happens to be at this instant") combined with the operator's default `imagePullPolicy: Always` means a registry-side retag during a rolling restart can produce version-mismatched peers. Two servers running 2.0.3 and one server running 2.0.4 may interact in ways that produce silent quorum loss or replication anomalies. By pinning the default to a single concrete version per operator release, every server in every Raft cluster runs the same Nomad binary unless the user explicitly opts out.

**How to override.** Set `spec.image.tag` to your desired version (concrete or floating) at the CR level:

```yaml
spec:
  image:
    tag: "2.0.4-ent"   # or any other tag your environment requires
```

**Operator release cadence.** Each operator release ships with the default tag updated to the most recent known-good Nomad Enterprise patch release. The release procedure is documented in [`docs/release-process.md`](docs/release-process.md) §1. Upgrade behaviour: existing NomadClusters that do not override `spec.image.tag` receive the new default on next reconcile, which triggers a rolling restart of the StatefulSet.

## TLS Configuration

mTLS is always enabled — no configuration is required. The operator automatically:

- Generates a self-signed ECDSA P-256 CA (or uses a user-provided CA)
- Issues server certificates with correct Nomad SANs (`server.<region>.nomad`, pod FQDNs, service FQDNs)
- Issues an operator client certificate for mTLS when querying the Nomad API
- Distributes a CA bundle ConfigMap for external consumers
- Rotates certificates approaching expiry (30-day warning window)
- Configures `verify_server_hostname = true` in the Nomad HCL for RPC mTLS
- Sets `verify_https_client = false` — the HTTP API is TLS-encrypted but does not require client certificates, allowing the UI, CLI, and OpenShift Routes to connect without distributing client certs. ACLs handle authorization
- Sets OpenShift Routes to `reencrypt` termination with the CA as `destinationCACertificate`

### Generated Secrets

The operator creates the following resources in the cluster namespace:

| Resource | Kind | Description |
|----------|------|-------------|
| `<cluster>-ca` | Secret | CA certificate and private key (`tls.crt`, `tls.key`). Not created when using a user-provided CA |
| `<cluster>-tls` | Secret | Server certificate and key (`tls.crt`, `tls.key`, `ca.crt`) |
| `<cluster>-operator-client` | Secret | Operator client certificate for mTLS API calls (`tls.crt`, `tls.key`, `ca.crt`) |
| `<cluster>-ca-bundle` | ConfigMap | CA certificate for external consumers |

### Operator-managed CA (default)

A minimal CR gets full mTLS with zero TLS configuration:

```yaml
apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: nomad
spec:
  license:
    secretName: nomad-license
```

**CA lifetime and renewal.** The operator-generated CA is valid for
**2 years** — deliberately short so a leaked or compromised CA key has a
bounded blast radius (the CA private key lives in a namespace Secret;
anyone who can read it can mint certificates trusted by the cluster
until the CA expires). The trade-off is a renewal obligation:

- `status.certificateAuthority.expiryTime` — when the CA expires.
- `status.certificateAuthority.renewalRequiredBy` — expiry minus the
  30-day renewal window. When this deadline passes, the operator emits
  a one-shot Warning Event with reason `CARenewalRequired` (debounced
  across operator restarts). The `Ready` condition stays `True` — a CA
  due for renewal is an operator obligation, not a cluster failure.

To renew, delete the `<cluster>-ca` Secret; the operator generates a
fresh CA and reissues server certificates from it on the next
reconcile. Plan a rolling restart — peers must converge on the new
trust root.

### User-provided CA

Supply your own CA and the operator issues certificates from it. The CA secret must contain a certificate and private key.

```yaml
apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: nomad
spec:
  license:
    secretName: nomad-license
  server:
    tls:
      ca:
        secretName: my-ca-secret  # must contain tls.crt and tls.key
```

## ACL Configuration

ACLs are enabled by default (`server.acl.enabled: true`). When the StatefulSet becomes ready, the operator bootstraps the ACL system and provisions **three tokens**, each in its own Secret:

| Secret | Capabilities | Used for |
|--------|--------------|----------|
| `<cluster>-acl-bootstrap` | full management (Nomad bootstrap token) | Minting the management token at bootstrap, and revoking the derived tokens/policies on cluster deletion. Nothing else — day-2 operations never use it. |
| `<cluster>-operator-management` | `acl:write`, `operator:write` | All day-2 management writes: keeping the operator-owned ACL policies in their desired state, and Raft peer removal during scale-down. |
| `<cluster>-operator-status` | `operator:read`, `agent:read` | All day-2 read-only queries: autopilot health, license status, leader, agent-version probe. |

The principle is least privilege per concern: the bootstrap token is
effectively sealed after minting the management token; writes ride the
management token; reads ride the status token. The operator also keeps
the three operator-owned policies (`anonymous`,
`<cluster>-operator-management`, `<cluster>-operator-status`) in their
desired state on every reconcile — manual edits to them are reverted.

On cluster deletion, the finalizer revokes the management and status
tokens and deletes their policies from Nomad (authenticating with the
bootstrap token, whose Secret is deliberately deleted last — see
[Bootstrap token Secret lifecycle](#bootstrap-token-secret-lifecycle)).

## Pod Disruption Budget

For HA clusters (`spec.replicas ≥ 3`) the operator owns a `policy/v1` PodDisruptionBudget named after the cluster, with `maxUnavailable = replicas/2` (integer division: 1 for `N=3`, 2 for `N=5`). This bounds voluntary disruptions — node drains, upgrades, and rolling rollouts — so a Raft quorum is always preserved.

For single-instance clusters (`spec.replicas = 1`) no PDB is created. Single-instance clusters are not HA, and a PDB with `maxUnavailable: 0` would block all voluntary disruption (preventing routine node maintenance) without providing any quorum benefit.

The PDB is operator-owned with no spec field; scaling from `N=3` to `N=5` updates `maxUnavailable` in place, and scaling down to `N=1` deletes the PDB. Out-of-band PDB deletions are recreated on the next reconcile.

## Scaling down

To scale a cluster down, patch `spec.replicas` to the desired count. The operator removes one Raft peer per reconcile (highest ordinal first), verifies the removal against the new peer list, records the removed server ID in `status.scaleDown.removedPeers`, and only patches `sts.spec.replicas` once every required peer has been removed. The recorded list persists across operator restarts so a crashed operator never re-removes a peer.

Scaling from 3 or more replicas down to fewer than 3 sacrifices Raft
fault tolerance, so the operator refuses to start until you opt in by
annotating the cluster with
`nomad.hashicorp.com/accept-degraded-quorum: "true"`. Until then the
`Ready` condition reports reason `DegradedQuorumNotAccepted`.

PVCs for removed ordinals are **not deleted** by the operator. `spec.persistence.reclaimPolicy` governs cluster-*delete* behaviour only — scale-down preserves PVCs in every case so a subsequent scale-up can re-attach to existing data.

Two operational rules:

- **Do not `kubectl delete pod <cluster>-N` directly.** The operator's scale-down contract is "user adjusts `spec.replicas`." Out-of-band pod deletion does not trigger Raft peer removal; the dead Raft entry sits there until Nomad autopilot's `cleanupDeadServers` eventually removes it (if enabled).
- **Serf gossip cleanup is delegated to autopilot.** The operator does not call `nomad server force-leave`. With the default `autopilot.cleanupDeadServers: true`, stale Serf members are removed within `autopilot.lastContactThreshold × N` intervals after the pod terminates. If you disable `cleanupDeadServers`, run `nomad server force-leave <name>` manually after a scale-down.

## OIDC Authentication

The operator no longer reconciles OIDC authentication. Earlier versions
managed a Keycloak realm and Nomad ACL auth method via `spec.oidc`; that
field has been removed. Configure Nomad SSO out-of-band with the
[Terraform Provider for Nomad](https://registry.terraform.io/providers/hashicorp/nomad/latest)
(`nomad_acl_auth_method`, `nomad_acl_binding_rule`, `nomad_acl_role`,
`nomad_acl_policy`), which covers the full auth-method lifecycle against
any OIDC identity provider.

See [docs/migration-oidc-to-terraform.md](docs/migration-oidc-to-terraform.md)
for a worked migration guide, including a complete
`nomad_acl_auth_method` example and the steps to clean up
operator-managed OIDC resources from existing clusters.

## NomadSnapshot CRD Reference

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
updates the agent config and rolls the Deployment automatically — the
pod template carries a `checksum/config` annotation, so the agent
always runs the current config. A failed one-shot Job sets the
`Degraded` condition and emits a `SnapshotDegraded` Warning Event.

For restoring from a snapshot, see
[docs/runbooks/restore.md](docs/runbooks/restore.md).

### Spec

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `clusterRef.name` | `string` | | Name of the target NomadCluster |
| `clusterRef.namespace` | `string` | | Namespace of the target NomadCluster. Defaults to the NomadSnapshot's namespace |
| `schedule` | `object` | | Optional. Present = recurring agent Deployment; omitted = one-shot Job |
| `schedule.interval` | `string` | `1h` | Interval between snapshots (e.g. `1h`, `24h`) |
| `schedule.retain` | `int` | `24` | Number of snapshots to retain (minimum 1) |
| `schedule.stale` | `bool` | `false` | Allow reading from a non-leader for snapshots |
| `resources` | `ResourceRequirements` | | CPU/memory requests and limits for the snapshot agent |
| `nodeSelector` | `map[string]string` | | Node selector for the snapshot agent pod |
| `tolerations` | `[]Toleration` | | Tolerations for the snapshot agent pod |

### Storage Targets

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
| `credentialsSecretRef.name` | `string` | | Secret with `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. Uses IAM/IRSA if omitted |

**GCS** (`spec.target.gcs`):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bucket` | `string` | | GCS bucket name |
| `credentialsSecretRef.name` | `string` | | Secret with `GOOGLE_APPLICATION_CREDENTIALS`. Uses workload identity if omitted |

**Azure Blob** (`spec.target.azure`):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `container` | `string` | | Azure container name |
| `accountName` | `string` | | Storage account name |
| `credentialsSecretRef.name` | `string` | | Secret with `AZURE_BLOB_ACCOUNT_KEY` |

### Snapshot ACL Token

When ACLs are enabled on the referenced NomadCluster, the operator creates a dedicated ACL policy with `snapshot-save` and `license-read` capabilities and a token bound to that policy. The token is stored in the `<snapshot>-snapshot-token` Secret. The policy name is tracked in `status.policyName`. Both the token and policy are cleaned up from Nomad when the NomadSnapshot is deleted.

### Example

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

## Complete Example

A production NomadCluster with TLS, ACLs, and a snapshot schedule:

```yaml
apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: nomad-enterprise
spec:
  replicas: 3
  image:
    repository: hashicorp/nomad
    tag: "2.0.0-ent"
  license:
    secretName: nomad-license
  server:
    acl:
      enabled: true
    audit:
      enabled: true
  persistence:
    size: 10Gi
  resources:
    limits:
      cpu: "2"
      memory: 2Gi
    requests:
      cpu: 500m
      memory: 1Gi
---
apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadSnapshot
metadata:
  name: hourly-backup
spec:
  clusterRef:
    name: nomad-enterprise
  schedule:
    interval: "1h"
    retain: 24
  target:
    local:
      size: 10Gi
```

## Observability

### Cluster Status

The `NomadCluster` status is available via `kubectl get nomadcluster` or `kubectl get nc`:

```
NAME              PHASE     READY   DESIRED   ADVERTISE        AGE
nomad-enterprise  Running   3       3         10.96.0.15       5m
```

### Status Fields

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
| `status.license.valid` | Whether the Nomad license is valid |
| `status.license.expirationTime` | License expiry time |
| `status.license.features` | Licensed features |
| `status.autopilot.healthy` | Whether autopilot considers the cluster healthy |
| `status.autopilot.failureTolerance` | Number of server failures the cluster can tolerate |
| `status.autopilot.voters` | Number of voting servers |
| `status.autopilot.servers[]` | Per-server health details |

### Conditions

`status.conditions[]` contains exactly **one** condition, type `Ready`.
Everything a per-resource condition used to say lives in the status
sub-fields above — the condition tells you *whether* the cluster is
healthy; the sub-fields tell you *why*. `Ready=True` requires the
StatefulSet at its desired ready replica count, a valid license, and
healthy autopilot (an unreachable probe does not fail Ready — the
sub-field keeps its last-known value).

`Ready=False` reasons:

| Reason | Meaning |
|--------|---------|
| `WaitingForReplicas` | StatefulSet below its desired ready count |
| `LicenseExpired` | Nomad Enterprise license invalid — see `status.license` |
| `AutopilotUnhealthy` | Raft autopilot reports unhealthy — see `status.autopilot` |
| `PhaseFailed` | A reconcile phase errored; the message names the phase |
| `Reconciling` | A phase requested requeue (generic wait) |
| `ScaleDownBlocked` | Scale-down waiting on a Raft leader |
| `DegradedQuorumNotAccepted` | Scale-down below 3 replicas lacks the [opt-in annotation](#scaling-down) |

### Operator Metrics

The operator exports its own Prometheus metrics on the existing
`:8443/metrics` endpoint (HTTPS, kube-rbac-proxy-style auth via
ServiceAccount bearer token). When the Prometheus Operator CRDs are
installed, the operator creates a ServiceMonitor for itself
automatically; the declarative equivalent ships at
`config/prometheus/operator-monitor.yaml`.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nomad_operator_phase_duration_seconds` | Histogram | `cluster`, `namespace`, `phase` | Wall-clock duration of each reconciliation phase. Expected range: milliseconds (no-op phases) to low seconds (certificate issuance) |
| `nomad_operator_nomad_api_requests_total` | Counter | `method`, `outcome` | Nomad API requests issued by the operator. `outcome` is `success` or `error` |
| `nomad_operator_cert_expiry_timestamp_seconds` | Gauge | `cluster`, `namespace`, `cert` | NotAfter of each operator-managed certificate as a Unix timestamp. Alert when `< time() + 30d` |
| `nomad_operator_license_expiry_timestamp_seconds` | Gauge | `cluster`, `namespace` | Nomad Enterprise license expiration as a Unix timestamp |
| `nomad_operator_acl_bootstrap_failures_total` | Counter | `cluster`, `namespace` | Failed ACL bootstrap attempts. Any non-zero rate warrants investigation |
| `nomad_operator_scale_down_in_progress` | Gauge | `cluster`, `namespace` | 1 while a Raft scale-down operation is running, else 0 |
| `nomad_operator_nomad_version_info` | Gauge | `cluster`, `namespace`, `version` | Constant 1; the observed Nomad server version is carried as a label. The previous series is deleted on version change so each cluster exposes a single version label |

**Cardinality budget:** the operator is designed for ≤200 NomadClusters
per operator instance. Beyond that, the per-cluster label on
`nomad_operator_phase_duration_seconds` produces histogram cardinality
you should size your Prometheus storage for. Multi-instance operator
deployments (sharded by namespace) are not currently supported.

## Reconciliation Phases

The NomadCluster controller reconciles through a sequential phase pipeline:

1. **ServiceAccount** — creates the Nomad server ServiceAccount
2. **RBAC** — creates Roles and RoleBindings
3. **Gossip** — generates or resolves the gossip encryption key
4. **Services** — creates headless and external Kubernetes Services
5. **Advertise** — resolves the external LoadBalancer address
6. **Certificate** — generates CA and issues server/client certificates (after Advertise so the LoadBalancer IP is in the cert SANs)
7. **Secrets** — assembles the Nomad configuration secrets
8. **ConfigMap** — renders the Nomad HCL server configuration
9. **StatefulSet** — creates or updates the Nomad server StatefulSet
10. **PDB** — creates or updates the PodDisruptionBudget for `spec.replicas ≥ 3` (skipped for `replicas = 1`)
11. **ScaleDown** — removes Raft peers when `sts.spec.replicas` exceeds `spec.replicas`, one peer per reconcile, before patching the StatefulSet (see "Scaling down" below)
12. **Route** — creates OpenShift Route and resolves the admitted hostname (when enabled, gated on Route CRD availability)
13. **Monitoring** — creates ServiceMonitor and PrometheusRule (when enabled, gated on Prometheus Operator CRD availability)
14. **ACLBootstrap** — bootstraps ACLs and creates the operator status token (when ACLs enabled)
15. **ClusterStatus** — queries the Nomad API for leader, autopilot health, and license status

## Development

### Build and Deploy for Development

```sh
make docker-build docker-push IMG=quay.io/benjamin_holmes/nomad-enterprise-operator:v<version>
make install
make deploy IMG=quay.io/benjamin_holmes/nomad-enterprise-operator:v<version>
```

### Apply Sample Resources

```sh
kubectl apply -k config/samples/
```

### Run Tests

```sh
# Unit and integration tests
make test

# Linter
make lint

# End-to-end tests (requires Kind; creates and tears down a cluster)
make test-e2e
```

Run `make help` for all available targets.

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/benemon/nomad-enterprise-operator).

## License

Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
