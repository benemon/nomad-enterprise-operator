# Nomad Enterprise Operator

A Kubernetes operator that deploys, snapshots, and scales Nomad
Enterprise server clusters.
{ .neo-tagline }

Running a Nomad Enterprise control plane involves work beyond
scheduling: issuing and rotating mTLS certificates, storing the gossip
key, bootstrapping the ACL system, wrapping the root encryption keys,
and verifying that Raft snapshots reach their storage target. This
operator manages those concerns declaratively through Kubernetes
objects, past the point where a Helm chart ends at API submission.

A `NomadCluster` resource deploys a Nomad Enterprise server cluster
with mTLS, bootstrapped ACLs, audit logging, and Pod Security
`restricted` from the first reconcile. Two companion resources cover
day-2 operations: `NomadSnapshot` for scheduled and one-shot Raft
snapshots to local, S3, GCS, or Azure Blob storage, and
`NomadAutoscaler` for managed Nomad Autoscaler agents, including
Dynamic Application Sizing.

!!! note "Community project"
    This operator is not maintained or supported by HashiCorp. It is an
    independent community project. The `nomad.hashicorp.com` API group
    used by its CRDs is a structural identifier inherited from the Nomad
    ecosystem, not an endorsement or affiliation. A Nomad Enterprise
    license is required for the clusters it deploys. Support is
    community-based through the GitHub issue tracker; there is no SLA.

## Architectural boundaries

Two scope decisions define what this operator is:

**Server clusters only.** The operator deploys and manages Nomad
**server** (control-plane) clusters. HashiCorp does not support running
Nomad clients as containers, so client nodes are out of scope:
provision your client fleet on VMs or bare metal and point it at the
cluster's advertised address (`status.services`). The CRD does not
model clients.

**Single region per cluster.** Each NomadCluster CR is one Raft
cluster in one region (`spec.topology.region`). Multi-region
federation (WAN gossip joins, cross-region ACL replication) is not
managed by the operator in v1. Nomad itself supports federating
operator-deployed clusters if you expose the serf WAN port and
configure the joins out-of-band.

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
