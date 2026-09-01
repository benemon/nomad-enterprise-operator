# Versions and upgrades

## Image version pinning

The default value of `spec.image.tag` is a **concrete patch version** (e.g. `2.0.5-ent`), not a floating tag like `1.11-ent` or `2-ent`. This is a deliberate safety measure for Raft cluster integrity.

Upgrading a cluster to a new Nomad version is a user-driven
`spec.image.tag` change. **Snapshot before you upgrade** - the operator
deliberately does not do it for you. The full procedure, including the
pre-upgrade one-shot snapshot and rollback guidance, is in the
[disaster-recovery runbook](../runbooks/disaster-recovery.md). The short form: take a
one-shot `NomadSnapshot`, wait for `status.phase: Succeeded`, then patch
`spec.image.tag`; the operator rolls the StatefulSet one pod at a time
behind the PodDisruptionBudget.

**Why a pinned default matters.** Nomad is a Raft consensus cluster. A floating tag (one that resolves to "whatever the latest patch happens to be at this instant") combined with the operator's default `imagePullPolicy: Always` means a registry-side retag during a rolling restart can produce version-mismatched peers. Two servers running 2.0.3 and one server running 2.0.4 may interact in ways that produce silent quorum loss or replication anomalies. By pinning the default to a single concrete version per operator release, every server in every Raft cluster runs the same Nomad binary unless the user explicitly opts out.

**How to override.** Set `spec.image.tag` to your desired version (concrete or floating) at the CR level:

```yaml
spec:
  image:
    tag: "2.0.5-ent"   # or any other tag your environment requires
```

**Digest pinning (air-gapped/CISO environments).** For environments
that require content-addressed immutability - the fork-and-sign
workflows described under [Security posture](../security.md) usually
end in a digest, not a tag - set `spec.image.digest`:

```yaml
spec:
  image:
    repository: registry.internal/nomad
    digest: "sha256:4f5c…"   # full 64-hex-char digest
```

When a digest is set, the image reference is `repository@digest` and
`spec.image.tag` is ignored (digest takes precedence). Digests are
immutable, so `pullPolicy: Always` becomes redundant - harmless, but
`IfNotPresent` avoids pointless registry round-trips. The snapshot
agent uses the same image reference as the cluster.

**Operator release cadence.** Each operator release ships with the default tag updated to the most recent known-good Nomad Enterprise patch release. Upgrade behaviour: existing NomadClusters that do not override `spec.image.tag` receive the new default on next reconcile, which triggers a rolling restart of the StatefulSet.

## Nomad version compatibility

The operator manages **Nomad Enterprise** servers (a license is the
one required field). Compatibility is stated in three tiers, and the
"tested" tier reports exactly what CI proves - nothing more:

| Tier | Versions | Evidence |
|------|----------|----------|
| Tested | `2.0.x-ent` (current default `2.0.5-ent`) | full e2e suite, nightly |
| Tested upgrade paths | `1.10-ent → 1.11-ent`, `1.11-ent → 2.0-ent` | nightly upgrade matrix: rolling upgrade with the Raft quorum floor asserted at every poll |
| Expected to work | `1.10.x-ent` and `1.11.x-ent` as running versions | upgrade-matrix clusters boot and serve on these lines, but the full suite does not run against them |
| Unsupported | anything below `1.10-ent`; Nomad CE | untested; CE lacks the licensed features the operator manages (audit, snapshot agent) |

Upgrade one minor version at a time (the matrix pairs are consecutive
for this reason). The matrix uses major.minor tags deliberately - each
run exercises the latest patch of each line, so the proof
self-maintains as patches ship; when a new Nomad minor GAs, a new pair
is appended to the nightly matrix and this table.


