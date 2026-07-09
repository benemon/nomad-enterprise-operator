# Runbook: Upgrading a Nomad Cluster

Audience: a human operator bumping the Nomad version of an
operator-managed NomadCluster. Version changes are user-driven: edit
`spec.image.tag` and the operator performs a rolling restart of the
StatefulSet. The PodDisruptionBudget bounds voluntary disruption so
quorum survives the roll, but Raft *state* compatibility across
versions is Nomad's contract, not the operator's — which is why you
snapshot first.

**The operator deliberately does not snapshot for you.** An automatic
pre-upgrade snapshot was considered and retracted (design review §4.1,
platform-engineer review §3.5): it would need its own storage target
configuration on every NomadCluster, silently couple upgrades to
storage-backend availability, and hide the one step a human should
consciously perform before mutating a consensus cluster. The one-shot
NomadSnapshot mode makes the manual step three commands.

## Snapshot before upgrade

**1. The risk.** An upgrade rolls every server pod onto a new Nomad
binary. If the new version mis-handles existing Raft state (rare, but
release notes exist for a reason), or the roll goes wrong halfway and
quorum is lost with mixed-version peers, recovery without a snapshot
means rebuilding cluster state by hand. A snapshot taken seconds before
the upgrade turns that scenario into a documented restore.

**2. Take a one-shot snapshot.** Apply a NomadSnapshot with no
`schedule` (uses your normal storage target — S3/GCS/Azure/local all
work; local shown for brevity):

```sh
kubectl apply -f - <<'EOF'   # one-shot NomadSnapshot: no spec.schedule
apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadSnapshot
metadata:
  name: pre-upgrade
  namespace: <ns>
spec:
  clusterRef:
    name: <cluster>
  target:
    local:
      size: 1Gi
EOF
```

**3. Wait for it to succeed.** Do not start the upgrade until the
snapshot phase is `Succeeded`:

```sh
kubectl wait nomadsnapshot/pre-upgrade -n <ns> \
  --for=jsonpath='{.status.phase}'=Succeeded --timeout=5m
```

If it reports `Failed` instead, inspect the Job pod logs
(`kubectl logs -n <ns> job/pre-upgrade-snapshot`) and fix the cause —
upgrading on top of a failed snapshot defeats the point.

**4. Perform the upgrade.** Bump the image tag; the operator rolls the
StatefulSet:

```sh
kubectl patch nomadcluster <cluster> -n <ns> --type=merge \
  -p '{"spec":{"image":{"tag":"<new-version>"}}}'
```

Watch the roll complete and the cluster return to Ready:

```sh
kubectl get nomadcluster <cluster> -n <ns> -w
kubectl wait nomadcluster/<cluster> -n <ns> \
  --for=condition=Ready --timeout=15m
```

Confirm every server reports the new version
(`status.nomadVersion` is probed from the running agents):

```sh
kubectl get nomadcluster <cluster> -n <ns> -o jsonpath='{.status.nomadVersion}'
```

**5. If it goes wrong.** Restore the pre-upgrade snapshot by following
[restore.md](restore.md) — including its warning about operator tokens
minted after the snapshot. If the upgrade failed at the binary level
(pods crash-looping on the new version), first revert `spec.image.tag`
to the previous version and let the roll settle before considering a
state restore.

Once the upgrade is verified, delete the one-shot NomadSnapshot
(`kubectl delete nomadsnapshot pre-upgrade -n <ns>`); its storage
artifact is retained per your target's semantics.
