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

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.audit.enabled` | `bool` | `true` | Enable audit logging. Auto-creates an audit volume |
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

## Image version pinning

The default value of `spec.image.tag` is a **concrete patch version** (e.g. `2.0.0-ent`), not a floating tag like `1.11-ent` or `2-ent`. This is a deliberate safety measure for Raft cluster integrity.

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

ACLs are enabled by default (`server.acl.enabled: true`). When the StatefulSet becomes ready, the operator:

1. Bootstraps the Nomad ACL system and stores the bootstrap token in the `<cluster>-acl-bootstrap` Secret.
2. Creates a dedicated least-privilege ACL policy with `operator:read` capabilities.
3. Creates a token bound to that policy and stores it in the `<cluster>-operator-status` Secret.
4. Uses the operator status token (not the bootstrap token) for all subsequent Nomad API queries (autopilot health, license status, leader election).

On cluster deletion, the operator revokes the operator status token and deletes the associated ACL policy from Nomad before removing Kubernetes resources.

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

A `NomadSnapshot` deploys a Nomad snapshot agent as a Deployment, targeting a `NomadCluster` in the same or different namespace. It supports local PVC, S3, GCS, and Azure Blob storage backends.

### Spec

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `clusterRef.name` | `string` | | Name of the target NomadCluster |
| `clusterRef.namespace` | `string` | | Namespace of the target NomadCluster. Defaults to the NomadSnapshot's namespace |
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

| Condition | Description |
|-----------|-------------|
| `Ready` | Overall cluster readiness |
| `GossipKeyReady` | Gossip encryption key is configured |
| `ServicesReady` | All Kubernetes Services are ready |
| `AdvertiseResolved` | LoadBalancer IP has been resolved |
| `StatefulSetReady` | StatefulSet has desired ready replicas |
| `ACLBootstrapped` | ACL bootstrap has completed |
| `RouteReady` | OpenShift Route is created |
| `MonitoringReady` | ServiceMonitor/PrometheusRule are created |
| `LicenseValid` | Nomad Enterprise license is valid |
| `AutopilotHealthy` | Raft autopilot reports healthy |

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
10. **Route** — creates OpenShift Route and resolves the admitted hostname (when enabled, gated on Route CRD availability)
11. **Monitoring** — creates ServiceMonitor and PrometheusRule (when enabled, gated on Prometheus Operator CRD availability)
12. **ACLBootstrap** — bootstraps ACLs and creates the operator status token (when ACLs enabled)
13. **ClusterStatus** — queries the Nomad API for leader, autopilot health, and license status

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
