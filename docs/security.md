# Security

## Multi-tenancy

One operator instance watches the whole Kubernetes cluster and
reconciles NomadClusters in any namespace (all OLM install modes are
supported, `AllNamespaces` is the default). The supported tenant
layout is namespace-scoped: each NomadCluster lives in a namespace
together with its own dependency Secrets - the license Secret
(`spec.license.secretName`), any user CA, and any Vault token Secrets
are resolved in the CR's namespace only, never from a shared central
namespace. Multiple NomadClusters per namespace work (names must
differ); the same cluster name in different namespaces also works.
This topology is exercised by the multi-namespace e2e fleet test.
Running more than one operator instance against the same Kubernetes
cluster (sharding) is unsupported.

## Security posture

All workloads - the operator, Nomad server pods, snapshot agents, and
autoscaler agents - run under the Kubernetes Pod Security Standards
**restricted** profile:
non-root (explicit UID/fsGroup on vanilla Kubernetes; SCC-assigned on
OpenShift), `RuntimeDefault` seccomp, no privilege escalation, all
capabilities dropped, and read-only root filesystems with explicit
writable mounts. The e2e suite runs in a namespace with
`pod-security.kubernetes.io/enforce=restricted` to keep this true.

Snapshot artifacts from `aead`-keyring clusters (the Nomad default)
contain cleartext key material - see
[Keyrings](guides/keyrings.md) for why external KMS wrapping
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
explicitly - last, after the (best-effort) Nomad-side cleanup.

The consequence: if the finalizer never completes - operator
uninstalled before the cluster was deleted, namespace force-deleted
with the finalizer stripped, etc. - the bootstrap Secret is orphaned
with **no garbage collection**. It contains a Nomad management token,
so orphans are worth sweeping for. List all bootstrap Secrets and
cross-reference against live clusters:

```sh
kubectl get secrets -A -l nomad.hashicorp.com/cluster
kubectl get nomadclusters -A
```

Any Secret whose `nomad.hashicorp.com/cluster` label names a cluster
that no longer exists can be deleted (the token it holds died with the
cluster). The operator does not scan for orphans itself - that would
require a periodic cluster-wide sweep, which is out of scope.

## Operator RBAC

The threat model's primary mitigation is that no bindings exist beyond
the bundled ClusterRole, which presumes the bundled role is minimal.
Every permission in the generated role
([config/rbac/role.yaml](https://github.com/benemon/nomad-enterprise-operator/blob/main/config/rbac/role.yaml))
is justified below by the controller and call site that uses it.

Two structural rules explain verbs that no single call site names:
`get;list;watch` travel together because every read goes through the
controller-runtime cache, and any cached `get` starts an informer that
lists and watches; owned resources are removed by Kubernetes garbage
collection through ownerReferences, so `delete` appears only where the
operator deletes an object explicitly.

| Resource | Verbs | Used by |
|----------|-------|---------|
| `configmaps` | create, update, delete + reads | Cluster controller: OpenShift trust bundle and CA bundle ConfigMaps, keyring state ConfigMap. Autoscaler controller: agent configuration. `delete`: the cluster controller reaps the legacy rendered-config ConfigMap once the StatefulSet is fully rolled onto the Secret-backed config. |
| `secrets` | create, update, delete + reads | Cluster controller: TLS certificates, gossip key, rendered server config, ACL token Secrets. Snapshot and autoscaler controllers: agent config and token Secrets. `delete`: the deletion finalizer removes the bootstrap-token Secret explicitly (it has no ownerReference - see above). `watch` also drives rolling restarts when referenced user Secrets change. |
| `services` | create, update + reads | Cluster controller: internal, external, and headless Services. Autoscaler controller: agent metrics Service. |
| `serviceaccounts` | create + reads | Cluster controller: the per-cluster ServiceAccount the Nomad pods run as. Owned, so never updated or deleted by the operator. |
| `serviceaccounts/token` | create | Cluster controller: TokenRequest minting the ephemeral audience-bound JWT for Vault keyring authentication. |
| `pods` | reads | Cluster controller: pod readiness before ACL bootstrap, roll-completion tracking. |
| `persistentvolumeclaims` | create, update, delete + reads | Snapshot controller: snapshot storage PVC. `delete`: the cluster deletion finalizer removes the server data PVCs. |
| `events` | create, patch | The Event recorder on all three controllers; `patch` is how the recorder folds repeats into an event series. |
| `apps/statefulsets` | create, update, patch, delete + reads | Cluster controller: the server StatefulSet; `patch` for scale-down replica steps; `delete` by the deletion finalizer ahead of PVC cleanup. |
| `apps/deployments` | create, update, delete + reads | Autoscaler controller: agent Deployment. Snapshot controller: periodic snapshot runner Deployment; `delete` removes the stale runner when the schedule moves between one-shot and periodic. |
| `batch/jobs` | create, delete + reads | Snapshot controller: one-shot snapshot Jobs. Jobs are immutable, so there is no `update` - re-runs delete and recreate. |
| `monitoring.coreos.com/servicemonitors` | create, update + reads | Cluster and autoscaler controllers. Removed only by garbage collection, so no `delete`. |
| `monitoring.coreos.com/prometheusrules` | create, update, delete + reads | Cluster and autoscaler controllers. `delete` because the rule follows `prometheusRulesEnabled` both ways - toggling off deletes it. |
| `policy/poddisruptionbudgets` | create, update, delete + reads | Cluster and autoscaler controllers; `delete` when replicas drop below the point where a PDB is meaningful. |
| `rbac/roles` | create, update + reads | Cluster controller: per-cluster Role granting the Nomad pods read access to their ConfigMaps, Secrets, and pods; `update` reverts manual edits. |
| `rbac/rolebindings` | create + reads | Cluster controller: binds the per-cluster ServiceAccount to that Role. RoleRef is immutable, so there is no `update`. |
| `route.openshift.io/routes` | create, update + reads | Cluster controller: the UI Route. |
| `route.openshift.io/routes/custom-host` | create, update | Required to set `spec.host` when the CR configures an explicit Route host. |
| `nomad.hashicorp.com` CRs | update + reads | The controllers' own resources; `update` adds and removes finalizers. The snapshot controller also reads the target NomadCluster. |
| `nomad.hashicorp.com` CRs `/status` | patch | Status writes ride MergeFrom patches. |
| `nomad.hashicorp.com` CRs `/finalizers` | update | Required by the OwnerReferencesPermissionEnforcement admission plugin (on by default on OpenShift) for setting `blockOwnerDeletion` on owned objects. |


