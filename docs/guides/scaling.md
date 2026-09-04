# Sizing, placement, and scaling

## Production sizing

The operator's defaults (requests `250m`/`512Mi`, limits `2`/`2Gi`)
are **dev-grade** - sized so a first cluster schedules on a laptop or
kind. For production, size the servers to these tiers:

> Small (dev-test and initial production): 2–4 CPU cores, 8–16 GB
> memory, 100+ GB disk, 3000+ IOPS, 75+ MB/s throughput.
> Large: 8–16 CPU cores, 32–64 GB memory, 200+ GB disk, 10000+ IOPS,
> 250+ MB/s throughput. Avoid burstable instance types.

*- HashiCorp Validated Design: Nomad Enterprise Solution Design Guide*

Set requests equal to limits - Guaranteed QoS is the Kubernetes
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

The operator sets `GOMEMLIMIT` on the server containers to 90% of the
effective memory limit, so the Go runtime reclaims memory as usage
approaches the container ceiling instead of running into the OOM
killer with a healthy heap. The value tracks `resources.limits.memory`
(including the default when resources are unset); there is no knob.
The remaining 10% is headroom for memory outside the runtime's
control, so a server whose genuinely live state exceeds the limit
still fails - the soft limit buys degradation instead of a cliff, not
unbounded capacity.

Storage IOPS and throughput are properties of the storageClass and
invisible to the operator - validating them is a user responsibility.
The operator alerts on the *symptom* instead: `NomadRaftCommitSlow`
fires when commit latency indicates the floor is not being met.

## Pod placement

Pod anti-affinity is operator-owned: preferred scheduling, weight 100,
`kubernetes.io/hostname` topology, applied at every replica count
(preferred scheduling is inert with nothing to avoid). The pod template
never varies with `spec.replicas`, so scale operations do not restart
surviving servers - a restart would change the survivor's IP behind its
Raft ID, and a lone voter cannot repair its own stale address entry.
For multi-zone distribution use the standard
`spec.topologySpreadConstraints` field.


## Pod Disruption Budget

For HA clusters (`spec.replicas ≥ 3`) the operator owns a `policy/v1` PodDisruptionBudget named after the cluster, with `maxUnavailable = replicas/2` (integer division: 1 for `N=3`, 2 for `N=5`). This bounds voluntary disruptions - node drains, upgrades, and rolling rollouts - so a Raft quorum is always preserved.

For single-instance clusters (`spec.replicas = 1`) no PDB is created. Single-instance clusters are not HA, and a PDB with `maxUnavailable: 0` would block all voluntary disruption (preventing routine node maintenance) without providing any quorum benefit.

The PDB is operator-owned with no spec field; scaling from `N=3` to `N=5` updates `maxUnavailable` in place, and scaling down to `N=1` deletes the PDB. Out-of-band PDB deletions are recreated on the next reconcile.

## Scaling down

To scale a cluster down, patch `spec.replicas` to the desired count. The operator removes one Raft peer per reconcile (highest ordinal first), verifies the removal against the new peer list, records the removed server ID in `status.scaleDown.removedPeers`, and only patches `sts.spec.replicas` once every required peer has been removed. The recorded list persists across operator restarts so a crashed operator never re-removes a peer.

Scaling from 3 or more replicas down to fewer than 3 sacrifices Raft
fault tolerance, so the operator refuses to start until you opt in by
annotating the cluster with
`nomad.hashicorp.com/accept-degraded-quorum: "true"`. Until then the
`Ready` condition reports reason `DegradedQuorumNotAccepted`.

The data and audit PVCs for removed ordinals are **reclaimed** on
scale-down. A Nomad server's `data_dir` holds only its Raft state and
node identity - the durable cluster state lives on the surviving
leader - so a removed server that later rejoins on its old volume boots
with a stale identity the leader rejects as a duplicate, and never
returns to the voter set. Reclaiming the volumes means a subsequent
scale-up provisions fresh ones and the rejoining servers reform quorum
cleanly. `spec.persistence.reclaimPolicy` governs cluster-*delete*
behaviour separately. Back up audit logs off-cluster if you need a
removed server's audit trail past a scale-down.

## Scaling up

Scale-up from a live cluster is serialized: the operator adds one
replica per reconcile and waits for the new server to join the voter
set before adding the next. Simultaneous joins race Nomad's member
reconciliation - leadership churn mid-join can strand a server in an
add/remove loop - while a lone join meets a settled leader. Initial
cluster creation still starts all replicas at once, as
`bootstrap_expect` requires. A scale-up stalled at fewer voters than
replicas is visible in `status.autopilot`; restarting the affected pod
forces a fresh gossip join and unsticks it.

## Single-server address healing

A lone server rescheduled onto a new pod IP keeps its Raft ID but not
its address, and Nomad cannot amend the sole voter's own Raft entry -
there is no quorum to vote the change through, so a later scale-up
would strand at one voter. The server start wrapper closes this at
boot: when the rendered config says one replica, Raft state exists,
and no sibling pod resolves in the headless service, it rewrites the
self-entry to the current pod IP via Nomad's native `peers.json`
recovery. The guards matter more than the write - a multi-server
cluster must never be reset to a self-only configuration, so the heal
never fires while any sibling exists. Multi-voter clusters need no
help: the leader repairs peer addresses natively.

Two operational rules:

- **Do not `kubectl delete pod <cluster>-N` directly.** The operator's scale-down contract is "user adjusts `spec.replicas`." Out-of-band pod deletion does not trigger Raft peer removal; the dead Raft entry sits there until Nomad autopilot's `cleanupDeadServers` eventually removes it (if enabled).
- **Serf gossip cleanup is delegated to autopilot.** The operator does not call `nomad server force-leave`. With the default `autopilot.cleanupDeadServers: true`, stale Serf members are removed within `autopilot.lastContactThreshold × N` intervals after the pod terminates. If you disable `cleanupDeadServers`, run `nomad server force-leave <name>` manually after a scale-down.


