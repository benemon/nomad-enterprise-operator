# Nomad Enterprise Operator

Deploy, snapshot and scale Nomad Enterprise control planes - on the
Kubernetes cluster you already run.
{ .neo-tagline }

Running a Nomad Enterprise control plane means answering questions that
have nothing to do with scheduling workloads: who issues and rotates the
mTLS certificates, where the gossip key lives, how the ACL system gets
bootstrapped without a human holding a root token, what wraps the root
encryption keys, and whether last night's Raft snapshot actually reached
the bucket. On Kubernetes, every one of those answers is usually a
script someone wrote and hopes still works.

This operator makes them declarative. An operator is a reconciliation
loop: it holds a model of what ought to be true, watches what is true,
and continuously converges the second towards the first. Where a Helm
chart ends at API submission, this operator manages Nomad itself,
through Kubernetes objects - the Raft membership, the encryption keys,
the certificates, and the ACL system that accumulate state long after
install. A `NomadCluster` resource deploys
a production-shaped Nomad Enterprise server cluster - mTLS everywhere,
ACLs bootstrapped, audit logging on, Pod Security `restricted` - and
two companion resources cover the operational tail: `NomadSnapshot` for
scheduled and one-shot Raft snapshots to local, S3, GCS, or Azure Blob
storage, and `NomadAutoscaler` for managed Nomad Autoscaler agents,
including Dynamic Application Sizing.

!!! note "Community project"
    This operator is not maintained or supported by HashiCorp. It is an
    independent community project. The `nomad.hashicorp.com` API group
    used by its CRDs is a structural identifier inherited from the Nomad
    ecosystem, not an endorsement or affiliation. A Nomad Enterprise
    license is required for the clusters it deploys. If you deploy it,
    your support contract is the GitHub issue tracker.

## Architectural boundaries

Two deliberate scope decisions define what this operator is:

**Server clusters only - bring your own clients.** The operator deploys
and manages Nomad **server** (control-plane) clusters. HashiCorp does
not support running Nomad clients as containers, so client nodes are
explicitly out of scope: provision your client fleet on VMs or bare
metal and point it at the cluster's advertised address
(`status.services`). Nothing in the CRD models clients, and nothing
will.

**Single region per cluster - no federation management (v1).** Each
NomadCluster CR is one Raft cluster in one region
(`spec.topology.region`). Multi-region federation - WAN gossip joins,
cross-region ACL replication - is not managed by the operator in v1.
Nomad itself supports federating operator-deployed clusters if you
expose the serf WAN port and configure the joins out-of-band; the
operator neither helps nor hinders. If federation management becomes a
real need, it will arrive as its own design cycle, not as a side
effect.

## Where to go

- [Getting started](getting-started.md) - install the operator and
  deploy a first cluster.
- Guides - [TLS and trust](guides/tls.md),
  [keyrings](guides/keyrings.md),
  [Vault workload identity](guides/workload-identity.md),
  [ACLs](guides/acls.md), [monitoring](guides/monitoring.md), and
  [sizing and scaling](guides/scaling.md).
- Operations - [versions and upgrades](operations/versions.md) and the
  runbooks for [upgrade](runbooks/upgrade.md),
  [restore](runbooks/restore.md), and
  [disaster recovery](runbooks/disaster-recovery.md).
- [Security](security.md) - posture, tenancy, and the
  [threat model](threat-model/README.md).
- Reference - [NomadCluster](reference/nomadcluster.md),
  [NomadSnapshot](reference/nomadsnapshot.md),
  [NomadAutoscaler](reference/nomadautoscaler.md), and the
  [reconciliation pipeline](reference/reconciliation.md).
