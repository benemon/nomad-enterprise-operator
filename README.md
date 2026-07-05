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

Contribution guidelines will be published when the project opens for external contributions.

## Architectural boundaries

Two deliberate scope decisions define what this operator is:

**Server clusters only — bring your own clients.** The operator
deploys and manages Nomad **server** (control-plane) clusters.
HashiCorp does not support running Nomad clients as containers, so
client nodes are explicitly out of scope: provision your client fleet
on VMs or bare metal and point it at the cluster's advertised address
(`status.services`). Nothing in the CRD models clients, and nothing
will.

**Single region per cluster — no federation management (v1).** Each
NomadCluster CR is one Raft cluster in one region
(`spec.topology.region`). Multi-region federation — WAN gossip joins,
cross-region ACL replication — is not managed by the operator in v1.
Nomad itself supports federating operator-deployed clusters if you
expose the serf WAN port and configure the joins out-of-band; the
operator neither helps nor hinders. If federation management becomes a
real need, it will arrive as its own design cycle, not as a side
effect.

## Security posture

All workloads — the operator, Nomad server pods, and snapshot agents —
run under the Kubernetes Pod Security Standards **restricted** profile:
non-root (explicit UID/fsGroup on vanilla Kubernetes; SCC-assigned on
OpenShift), `RuntimeDefault` seccomp, no privilege escalation, all
capabilities dropped, and read-only root filesystems with explicit
writable mounts. The e2e suite runs in a namespace with
`pod-security.kubernetes.io/enforce=restricted` to keep this true.

Snapshot artifacts from `aead`-keyring clusters (the Nomad default)
contain cleartext key material — see
[Keyrings](#keyrings-specserverkeyrings) for why external KMS wrapping
is the production posture.

The v1alpha2 release is deliberately scoped: it prioritises operational stability, runtime security, developer maintainability, and value delivery. Some supply-chain hardening is **deliberately deferred** to a future release:

- **Container images are not signed** (no cosign signatures attached). Verification by signature is not available against the upstream-published images.
- **No SBOM** is attached to releases. Software composition analysis must be performed against the image itself by the consumer's tooling.

For environments with CISO-gated container-image requirements (signed images, SBOM, provenance attestation), the recommended workaround is:

1. Pull the upstream image (`quay.io/benjamin_holmes/nomad-enterprise-operator:v<version>`).
2. Scan with your preferred scanner (Trivy, Snyk, Grype, etc.).
3. Re-tag and push to your internal registry; sign per your organisation's policy (cosign, notation, etc.).
4. Deploy from the internal-registry tag; override the operator image in the deployment manifest.

The operator's runtime is compatible with any image that exposes the same entrypoint and binary contract, so this fork-and-sign workflow does not require code changes.

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

- Go v1.26+ (development only)
- Docker v20.10+
- kubectl v1.28+
- Access to a Kubernetes v1.28+ cluster (matches the CSV's
  minKubeVersion; the CRD CEL validation rules need a modern apiserver)
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

On kind or any cluster without a load-balancer implementation, also set
`spec.services.external.type: NodePort` — the default (`LoadBalancer`)
waits indefinitely for an IP. The CI-tested quickstart at
[config/samples/minimal/nomadcluster.yaml](config/samples/minimal/nomadcluster.yaml)
carries this and is verified end-to-end on every nightly run.

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
| `image.tag` | `string` | `2.0.3-ent` | Container image tag. **Pinned to a concrete patch version** (not a floating tag) — see [Image version pinning](#image-version-pinning) |
| `image.digest` | `string` | — | Optional content digest (`sha256:…`). When set, the image reference is `repository@digest` and `tag` is ignored — see [Image version pinning](#image-version-pinning) |
| `image.pullPolicy` | `string` | `Always` | Image pull policy (`Always`, `IfNotPresent`, `Never`) |
| `license.secretName` | `string` | | Name of secret containing the Nomad license, stored under the key `license` (operator-owned). Mutually exclusive with `value` |
| `license.value` | `string` | | Inline license content. The operator creates a managed secret. Mutually exclusive with `secretName` |
| `topology.region` | `string` | `global` | Nomad region name |
| `topology.datacenter` | `string` | | Nomad datacenter name. Defaults to the namespace |
| `persistence.size` | `string` | `10Gi` | Data volume size. Set to empty string to use emptyDir |
| `persistence.storageClassName` | `string` | | Storage class for the data PVC. Uses cluster default if empty |
| `persistence.reclaimPolicy` | `Retain` \| `Delete` | `Delete` | What happens to data PVCs on cluster deletion. `Delete` (default) removes the PVCs with the cluster. `Retain` keeps them — but note that a fully recreated cluster does **not** recover automatically against retained data (Raft pins peer addresses to pod IPs, which change on recreation); recovery is via [NomadSnapshot restore](docs/runbooks/disaster-recovery.md). The value at deletion time wins |
| `resources` | `ResourceRequirements` | | Standard Kubernetes CPU/memory requests and limits |
| `imagePullSecrets` | `[]LocalObjectReference` | | Image pull secrets for private registries |
| `nodeSelector` | `map[string]string` | | Node selector for pod scheduling |
| `tolerations` | `[]Toleration` | | Tolerations for pod scheduling |
| `topologySpreadConstraints` | `[]TopologySpreadConstraint` | | Topology spread constraints |

### Server Configuration (`spec.server`)

Server-scoped configuration is split across the subsections below:
[TLS](#tls-specservertls), [ACL](#acl-specserveracl),
[Audit](#audit-specserveraudit), and
[Keyrings](#keyrings-specserverkeyrings).

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
| `server.acl.enabled` | `bool` | `true` | Enable Nomad ACLs. The operator auto-bootstraps; the token is always stored in `<name>-acl-bootstrap` (operator-owned) |

See [ACL Configuration](#acl-configuration) for details.

### Autopilot

Autopilot is operator-owned and not configurable:
`cleanup_dead_servers = true` (required for Serf cleanup delegation),
`last_contact_threshold = 200ms`, `max_trailing_logs = 250`,
`server_stabilization_time = 10s` — Nomad's own defaults.

### Audit (`spec.server.audit`)

Delivery guarantee (`enforced`), format (`json`), and rotation
(`24h` × 15 files) are operator-owned. Ship logs with a
sidecar if you need different retention.

Audit storage is independent of data storage: when audit is enabled the
StatefulSet always carries a dedicated audit PVC sized per
`server.audit.size`, even when `spec.persistence.size` is empty and
Raft data runs on `emptyDir`. Audit logs survive pod restarts in every
configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.audit.enabled` | `bool` | `true` | Enable audit logging. Auto-creates a dedicated audit PVC (independent of `spec.persistence`); requires `server.audit.size` |
| `server.audit.size` | `string` | `5Gi` | Audit volume size |
| `server.audit.storageClassName` | `string` | | Storage class for the audit PVC |

### Keyrings (`spec.server.keyrings`)

Nomad's root encryption keys — which protect Variables and sign
workload identities — are wrapped by a **keyring**. The default (`aead`)
stores its key-encryption key **in cleartext inside Raft**, which means
every Raft snapshot carries usable key material:

> **Snapshot custody is key custody.** On an `aead` cluster (the
> default), anyone who can read a snapshot — including the object-store
> bucket a `NomadSnapshot` uploads to — can decrypt that cluster's
> Variables and mint workload identities. Configure an external KMS
> keyring before treating snapshot storage as anything less than a
> copy of your keys.

With an external KMS keyring, only *wrapped* keys ride Raft: snapshots
remain complete for disaster recovery and are safe at rest — a restore
decrypts if and only if the restoring cluster can reach the KMS.

Four providers are supported, singly or as an HA set (every listed
keyring wraps new keys; any one reachable keyring unwraps):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.keyrings[].name` | `string` | | Entry name (unique, ≤63 chars) |
| `server.keyrings[].awskms` | `object` | | AWS KMS: `kmsKeyID` (required), `region`, `endpoint`, `credentialsSecretRef` |
| `server.keyrings[].azurekeyvault` | `object` | | Azure Key Vault / Managed HSM: `vaultName`, `keyName`, `tenantID` (required), `environment`, `resource`, `credentialsSecretRef` |
| `server.keyrings[].gcpckms` | `object` | | GCP Cloud KMS: `project`, `region`, `keyRing`, `cryptoKey` (all required), `credentialsSecretRef` |
| `server.keyrings[].transit` | `object` | | Vault transit: `address`, `keyName`, `mountPath` (required), `namespace`, `keyIDPrefix`, `tlsServerName`, `caSecretRef`, `clientCertSecretRef`, `auth` (required) |

Cloud providers authenticate with ambient identity (IRSA, Workload
Identity, Managed Identity) when `credentialsSecretRef` is omitted, or
with static credentials from the referenced Secret. Rotating that
Secret rolls the server pods automatically. Same-type HA pairs — two
AWS KMS keys in different regions or accounts, two Azure vaults, two
GCP keys — carry their credentials per entry, so each member of the
pair may use a different identity.

**Changing the keyring set is a live migration.** Enable, disable,
provider change, and HA expand/contract all follow the same
operator-managed cycle: render the union of old and new keyrings, roll
the servers, rotate every root key under the new set, remove the old
keys, retire the demoted keyrings, and roll once more.
`status.keyring` reports `phase` (`Ready`, `Introducing`, `Rotating`,
`Retiring`), the `active` and `retiring` sets, and `tokenExpiry` when
the operator manages a Vault token. A cluster with keyrings removed
parks on an explicit `aead` keyring permanently — its keys are not
loadable by the implicit default, so the operator never collapses back.

#### Transit authentication (`transit.auth`)

The transit provider authenticates to Vault through one of **four
credential vectors**, selected by `auth.method`. The structure mirrors
the Vault Secrets Operator's `VaultAuth` (`method: token` is our
extension — VSO has no static-token method):

```yaml
# 1. Long-lived Vault token, minted and rotated by you
auth:
  method: token
  token:
    secretRef:
      name: my-vault-token        # Secret key: VAULT_TOKEN

# 2. Long-lived Kubernetes ServiceAccount token, minted by you,
#    exchanged for a Vault token at a kubernetes auth mount
auth:
  method: kubernetes
  mount: kubernetes
  kubernetes:
    role: nomad-keyring
    serviceAccountTokenSecretRef:
      name: my-sa-jwt             # Secret key: token

# 3. Ephemeral ServiceAccount token (RECOMMENDED) — the operator mints
#    a short-lived, audience-bound TokenRequest JWT for the cluster's
#    own ServiceAccount, uses it once to log in, and never stores it
auth:
  method: kubernetes
  mount: kubernetes
  kubernetes:
    role: nomad-keyring
    audiences: ["vault"]          # default
    tokenExpirationSeconds: 600   # default

# 4. ServiceAccount token validated as a JWT (no TokenReview) — the
#    jwt auth mount verifies the signature against the cluster's JWKS
auth:
  method: jwt
  mount: jwt
  jwt:
    role: nomad-keyring           # same source choice as kubernetes:
                                  # ephemeral default, or secretRef
```

For the login methods (2–4) the operator logs in per entry, renews the
token on the reconcile heartbeat (no pod restart), and re-mints on
failure or revocation (rolls pods). For `method: token` the lifecycle
is yours; rotating your Secret rolls the pods. In every vector the
resolved token is rendered inline into that entry's keyring block —
see below.

Transit HA works across **independent Vault clusters**: each entry
carries its own `address` and its own `auth` (any vector), so either
Vault surviving keeps the cluster's keys decryptable. Give each entry
a distinct `keyIDPrefix` — Nomad's wrapped-key disambiguation. Each
entry's resolved token is rendered inline into that entry's keyring
block in the generated server configuration, which the operator stores
as a Secret (the same custody class as the gossip key it also
carries); tokens never appear in the `NomadCluster` manifest.

#### Who needs `system:auth-delegator`

The kubernetes auth method validates ServiceAccount tokens via the
TokenReview API, and the identity making that call needs the
`system:auth-delegator` ClusterRole. Which identity that is depends on
the Vault mount configuration — **the operator never creates
ClusterRoleBindings**; grant it per this table:

| Mount configuration | TokenReview caller | Grant `auth-delegator` to |
|---------------------|--------------------|---------------------------|
| `token_reviewer_jwt` configured | that JWT's identity | the reviewer's ServiceAccount |
| No reviewer JWT; Vault runs in Kubernetes (default `disable_local_ca_jwt=false`) | Vault's own pod ServiceAccount | Vault's pod ServiceAccount |
| No reviewer JWT; Vault outside Kubernetes (or `disable_local_ca_jwt=true`) | the client's login JWT | the **cluster's** ServiceAccount — and the login JWT must be API-server-valid (vector 2, or vector 3 with API-server audience) |
| `jwt` auth method | nobody (JWKS signature check) | nobody |

The API-server-valid caveat in the last row is load-bearing: the
operator's default `audiences` is `["vault"]` (VSO convention), and a
`vault`-audience JWT cannot authenticate to the apiserver to perform
its own TokenReview — login fails with `permission denied`. Against
external Vault, either set `audiences: ["https://kubernetes.default.svc"]`
(and the matching `audience` on the Vault role), or configure a
`token_reviewer_jwt` on the auth method. Verified live against Vault
Enterprise on OpenShift.

A denied TokenReview surfaces on the cluster as the
`KeyringVaultReviewerDenied` condition reason with this table's
remediation.

### Gossip Encryption (`spec.gossip`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `gossip.secretName` | `string` | | Name of existing secret containing the gossip key under the key `gossip-key` (operator-owned). Auto-generated if empty |

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

Scrape cadence is operator-owned (30s interval, 10s
timeout); ServiceMonitor label/relabel customisation belongs in
Prometheus configuration.

The shipped PrometheusRule covers three concern groups: health
(leader loss, server down, job failures, memory, Raft backlog and
commit latency), lifecycle expiry (CA and server certificates,
license), and control-plane saturation. `NomadEvalsBlocked` and
`NomadPlanQueueBacklog` fire on the scale-trigger signals;
`NomadRaftCommitSlow` fires on the symptom of under-provisioned
storage or CPU. All expressions target metric names verified against
live Nomad 2.0.x telemetry. When the saturation alerts fire:

> Scale the servers vertically first; scale horizontally (3 → 5
> servers) when sustained scheduler saturation persists at the larger
> instance size.

*— HashiCorp Validated Design: Nomad Enterprise Operating Guide*

### Production sizing

The operator's defaults (requests `250m`/`512Mi`, limits `2`/`2Gi`)
are **dev-grade** — sized so a first cluster schedules on a laptop or
kind. For production, size the servers to these tiers:

> Small (dev-test and initial production): 2–4 CPU cores, 8–16 GB
> memory, 100+ GB disk, 3000+ IOPS, 75+ MB/s throughput.
> Large: 8–16 CPU cores, 32–64 GB memory, 200+ GB disk, 10000+ IOPS,
> 250+ MB/s throughput. Avoid burstable instance types.

*— HashiCorp Validated Design: Nomad Enterprise Solution Design Guide*

Set requests equal to limits — Guaranteed QoS is the Kubernetes
translation of avoiding burstable instances:

```yaml
spec:
  resources:
    requests:
      cpu: "4"
      memory: 16Gi
    limits:
      cpu: "4"
      memory: 16Gi
  persistence:
    size: 100Gi
    # storageClassName: <a class meeting the IOPS/throughput floor>
```

Storage IOPS and throughput are properties of the storageClass and
invisible to the operator — validating them is a user responsibility.
The operator alerts on the *symptom* instead: `NomadRaftCommitSlow`
fires when commit latency indicates the floor is not being met.

### Pod placement

Pod anti-affinity is operator-owned: preferred scheduling,
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
| `spec.image.digest` matches `^sha256:[a-f0-9]{64}$` | pattern |
| `spec.image.pullPolicy` ∈ Always/IfNotPresent/Never; `spec.services.*.type` ∈ LoadBalancer/NodePort; `spec.persistence.reclaimPolicy` ∈ Retain/Delete | enum |
| Each `keyrings[]` entry configures exactly one provider; entry names unique; at most 8 entries | CEL + listType=map |
| `transit.auth.method` ∈ token/kubernetes/jwt, with exactly the matching per-method block; `mount` required unless `method: token` | enum + CEL |

Enforced at reconcile time (visible via `kubectl get nomadcluster` and
the `Ready` condition, not an admission error):

| Invariant | Behaviour when violated |
|-----------|------------------------|
| Scaling from ≥ 3 replicas to below 3 requires the `nomad.hashicorp.com/accept-degraded-quorum: "true"` annotation | Scale-down does not start; `Ready` reason `DegradedQuorumNotAccepted`. Operator-side because CRD CEL cannot read `metadata.annotations` |
| Scale-down requires a Raft leader | Scale-down pauses; `Ready` reason `ScaleDownBlocked` |
| `audit.enabled=true` requires `audit.size` | Never violated in practice: `audit.size` defaults to `5Gi` at admission, and the operator falls back to `5Gi` if the field is explicitly cleared |
| Multiple transit keyring entries require a distinct non-empty `keyIDPrefix` on each | `Ready` reason `KeyringInvalid` |

Not validated: the existence of the Secret named by
`spec.license.secretName` is not checked at admission (a missing Secret
surfaces at reconcile time). Anti-affinity has no user-facing knob to
validate — it is operator-owned (see
[Pod placement](#pod-placement)).

## Image version pinning

The default value of `spec.image.tag` is a **concrete patch version** (e.g. `2.0.3-ent`), not a floating tag like `1.11-ent` or `2-ent`. This is a deliberate safety measure for Raft cluster integrity.

Upgrading a cluster to a new Nomad version is a user-driven
`spec.image.tag` change. **Snapshot before you upgrade** — the operator
deliberately does not do it for you. The full procedure, including the
pre-upgrade one-shot snapshot and rollback guidance, is in the
[disaster-recovery runbook](docs/runbooks/disaster-recovery.md). The short form: take a
one-shot `NomadSnapshot`, wait for `status.phase: Succeeded`, then patch
`spec.image.tag`; the operator rolls the StatefulSet one pod at a time
behind the PodDisruptionBudget.

**Why a pinned default matters.** Nomad is a Raft consensus cluster. A floating tag (one that resolves to "whatever the latest patch happens to be at this instant") combined with the operator's default `imagePullPolicy: Always` means a registry-side retag during a rolling restart can produce version-mismatched peers. Two servers running 2.0.3 and one server running 2.0.4 may interact in ways that produce silent quorum loss or replication anomalies. By pinning the default to a single concrete version per operator release, every server in every Raft cluster runs the same Nomad binary unless the user explicitly opts out.

**How to override.** Set `spec.image.tag` to your desired version (concrete or floating) at the CR level:

```yaml
spec:
  image:
    tag: "2.0.4-ent"   # or any other tag your environment requires
```

**Digest pinning (air-gapped/CISO environments).** For environments
that require content-addressed immutability — the fork-and-sign
workflows described under [Security posture](#security-posture) usually
end in a digest, not a tag — set `spec.image.digest`:

```yaml
spec:
  image:
    repository: registry.internal/nomad
    digest: "sha256:4f5c…"   # full 64-hex-char digest
```

When a digest is set, the image reference is `repository@digest` and
`spec.image.tag` is ignored (digest takes precedence). Digests are
immutable, so `pullPolicy: Always` becomes redundant — harmless, but
`IfNotPresent` avoids pointless registry round-trips. The snapshot
agent uses the same image reference as the cluster.

**Operator release cadence.** Each operator release ships with the default tag updated to the most recent known-good Nomad Enterprise patch release. Upgrade behaviour: existing NomadClusters that do not override `spec.image.tag` receive the new default on next reconcile, which triggers a rolling restart of the StatefulSet.

## Nomad version compatibility

The operator manages **Nomad Enterprise** servers (a license is the
one required field). Compatibility is stated in three tiers, and the
"tested" tier reports exactly what CI proves — nothing more:

| Tier | Versions | Evidence |
|------|----------|----------|
| Tested | `2.0.x-ent` (current default `2.0.3-ent`) | full e2e suite, nightly |
| Tested upgrade paths | `1.10-ent → 1.11-ent`, `1.11-ent → 2.0-ent` | nightly upgrade matrix: rolling upgrade with the Raft quorum floor asserted at every poll |
| Expected to work | `1.10.x-ent` and `1.11.x-ent` as running versions | upgrade-matrix clusters boot and serve on these lines, but the full suite does not run against them |
| Unsupported | anything below `1.10-ent`; Nomad CE | untested; CE lacks the licensed features the operator manages (audit, snapshot agent) |

Upgrade one minor version at a time (the matrix pairs are consecutive
for this reason). The matrix uses major.minor tags deliberately — each
run exercises the latest patch of each line, so the proof
self-maintains as patches ship; when a new Nomad minor GAs, a new pair
is appended to the nightly matrix and this table.

## TLS Configuration

mTLS is always enabled — no configuration is required. The operator automatically:

- Generates a self-signed ECDSA P-256 CA (or uses a user-provided CA)
- Issues server certificates with correct Nomad SANs (`server.<region>.nomad`, pod FQDNs, service FQDNs)
- Distributes a CA bundle ConfigMap for external consumers
- Rotates certificates approaching expiry (30-day warning window)
- Configures `verify_server_hostname = true` in the Nomad HCL for RPC mTLS
- Sets `verify_https_client = false` — the HTTP API is TLS-encrypted but does not require client certificates, allowing the UI, CLI, and OpenShift Routes to connect without distributing client certs. ACLs handle authorization
- Sets OpenShift Routes to `reencrypt` termination with the CA as `destinationCACertificate`

**A documented divergence from the validated design.** For load
balancers in front of Nomad, the guidance is:

> Use TLS passthrough — the load balancer forwards encrypted traffic
> without terminating it, and Nomad terminates TLS itself.

*— HashiCorp Validated Design: Nomad Enterprise Solution Design Guide*

The operator's OpenShift Route deliberately uses `reencrypt` instead:
the Route terminates with a platform (or user-supplied) certificate
and re-establishes TLS to Nomad, verifying the cluster CA as
`destinationCACertificate`. Traffic stays encrypted on every segment
— the difference is a verified re-termination at the Route rather
than blind passthrough — and in exchange the Route gets platform
hostname routing and certificate management. Clients that require an
unterminated TLS session to Nomad should use the external
LoadBalancer/NodePort Service directly rather than the Route.

### Generated Secrets

The operator creates the following resources in the cluster namespace:

| Resource | Kind | Description |
|----------|------|-------------|
| `<cluster>-ca` | Secret | CA certificate and private key (`tls.crt`, `tls.key`). Not created when using a user-provided CA |
| `<cluster>-tls` | Secret | Server certificate and key (`tls.crt`, `tls.key`, `ca.crt`) |
| `<cluster>-ca-bundle` | ConfigMap | CA certificate for external consumers |
| `<cluster>-config` | Secret | Rendered `server.hcl` — Secret-class because it carries the gossip encryption key and any inline keyring credentials |
| `<cluster>-keyring-token` | Secret | Operator-minted Vault tokens for keyring login vectors, one key per entry (operator-internal; pods consume tokens via the rendered config) |

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

**CA lifetime and rotation.** The operator-generated CA is valid for
**2 years** — deliberately short so a leaked or compromised CA key has a
bounded blast radius (the CA private key lives in a namespace Secret;
anyone who can read it can mint certificates trusted by the cluster
until the CA expires). **The operator rotates it automatically**: 30
days before expiry it introduces a new CA and walks the cluster through
a zero-trust-gap rollover —

1. *Introduce*: a new CA is generated and every pod is rolled onto a
   trust bundle containing **both** CAs (a `CARotationStarted` Event
   marks this).
2. *Cutover*: once every pod trusts both, the new CA becomes the
   signer, server certificates are reissued from it, and pods roll
   again (`CARotationCompleted`). The old CA's private key is
   destroyed; its certificate stays in the trust bundle.
3. *Retire*: when the old CA certificate finally expires it drops out
   of the trust bundle on its own.

Peers never disagree on the trust root at any point, and a mid-rotation
operator restart resumes where it left off (rotation state lives in the
`<cluster>-ca` Secret, not operator memory). Status signals:

- `status.certificateAuthority.expiryTime` — when the active CA expires.
- `status.certificateAuthority.renewalRequiredBy` — for
  operator-generated CAs, when rotation will start; for **user-provided
  CAs**, when *you* must renew — the operator never rotates a CA it
  does not own, and instead emits a one-shot `CARenewalRequired`
  Warning Event when this deadline passes. The `Ready` condition stays
  `True` either way.

To force an early rotation, delete the `<cluster>-ca` Secret; the
operator generates a fresh CA and reissues server certificates on the
next reconcile (this hard-cut path skips the dual-trust overlap — plan
a rolling restart).

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
| `<cluster>-operator-management` | management-type token | All day-2 management writes: keeping the operator-owned ACL policies in their desired state, minting the status token, and Raft peer removal during scale-down. Management-type because Nomad has no ACL-write policy grammar — only management tokens can write ACL state. |
| `<cluster>-operator-status` | `operator:read`, `agent:read` | All day-2 read-only queries: autopilot health, license status, leader, agent-version probe. |

The principle is separation per concern: the bootstrap token is
effectively sealed after minting the management token; writes ride the
management token (dedicated, independently revocable and rotatable —
delete its Secret to force a re-mint); reads ride the least-privilege
status token. The operator also keeps
the two operator-owned policies (`anonymous` and
`<cluster>-operator-status`) in their desired state on every
reconcile — manual edits to them are reverted. The management
credential has no policy: it is a management-type token, because Nomad
has no ACL-write policy grammar.

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

**Restore compatibility.** Snapshots restore only to the same Nomad
version that took them. `status.nomadVersion` mirrors the referenced
cluster's version (what snapshots are currently taken against — it
follows upgrades); for one-shot artifacts,
`status.lastSnapshot.nomadVersion` is frozen at Job completion. Check
one of these against the restore-target cluster before restoring. The
full restore procedure is in the
[disaster-recovery runbook](docs/runbooks/disaster-recovery.md).

### Spec

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `clusterRef.name` | `string` | | Name of the target NomadCluster |
| `clusterRef.namespace` | `string` | | Namespace of the target NomadCluster. Defaults to the NomadSnapshot's namespace |
| `schedule` | `object` | | Optional. Present = recurring agent Deployment; omitted = one-shot Job |
| `schedule.interval` | `string` | `1h` | Interval between snapshots. Must be a Go duration string (e.g. `1h`, `90m`, `1h30m`) — pattern-validated at admission |
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
    tag: "2.0.3-ent"
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
| `status.keyring` | Keyring set state: `phase` (`Ready`/`Introducing`/`Rotating`/`Retiring`), `active[]`, `retiring[]`, and `tokenExpiry` for operator-managed Vault tokens |
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
| `LicenseSecretNotFound` | `spec.license.secretName` references a Secret that does not exist — create it; the operator re-reconciles the moment it appears |
| `LicenseSecretInvalid` | The license Secret exists but is missing the `license` key |
| `CAExpired` | The CA certificate has expired; TLS handshakes fail cluster-wide — see `status.certificateAuthority`. Takes precedence over `WaitingForReplicas` so the cascading pod failures are attributed to their cause |
| `PhaseFailed` | A reconcile phase errored; the message names the phase |
| `Reconciling` | A phase requested requeue (generic wait) |
| `ScaleDownBlocked` | Scale-down waiting on a Raft leader |
| `DegradedQuorumNotAccepted` | Scale-down below 3 replicas lacks the [opt-in annotation](#scaling-down) |
| `KeyringInvalid` | Keyring spec fails reconcile-time validation (e.g. multi-transit without distinct `keyIDPrefix`) |
| `KeyringRotationPending` | A keyring migration is waiting to rotate or clean up root keys; the message carries the underlying cause |
| `KeyringVaultLoginFailed` | Vault login for a keyring entry failed; the message names the entry |
| `KeyringVaultReviewerDenied` | Vault cannot validate ServiceAccount tokens — see [Who needs `system:auth-delegator`](#who-needs-systemauth-delegator) |
| `KeyringCredentialsUnavailable` | A keyring entry's credentials Secret is missing or malformed; the message names the entry and Secret |

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
8. **Keyring** — reconciles the external-KMS keyring set: resolves per-entry credentials, manages Vault token lifecycles, and drives keyring migrations
9. **Config** — renders server.hcl into the `<cluster>-config` Secret (a Secret, not a ConfigMap: it carries the gossip key and inline keyring credentials)
10. **StatefulSet** — creates or updates the Nomad server StatefulSet
11. **PDB** — creates or updates the PodDisruptionBudget for `spec.replicas ≥ 3` (skipped for `replicas = 1`)
12. **ScaleDown** — removes Raft peers when `sts.spec.replicas` exceeds `spec.replicas`, one peer per reconcile, before patching the StatefulSet (see "Scaling down" below)
13. **Route** — creates OpenShift Route and resolves the admitted hostname (when enabled, gated on Route CRD availability)
14. **Monitoring** — creates ServiceMonitor and PrometheusRule (when enabled, gated on Prometheus Operator CRD availability)
15. **ACLBootstrap** — bootstraps ACLs and creates the operator status token (when ACLs enabled)
16. **ClusterStatus** — queries the Nomad API for leader, autopilot health, and license status

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
