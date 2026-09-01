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


