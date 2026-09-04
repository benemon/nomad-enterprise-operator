# NomadAutoscaler reference

A `NomadAutoscaler` deploys a [Nomad Autoscaler](https://developer.hashicorp.com/nomad/tools/autoscaling)
agent (enterprise image by default) wired to a `NomadCluster`: the
operator derives the Nomad address, CA, and a dedicated ACL token from
`clusterRef`. Scaling policies are **not** authored in this CR - they
live in job specifications and reach the agent through its Nomad policy
source. The CR covers two metric paths:

- **Horizontal application scaling**: task-group `scaling` blocks
  evaluated against the built-in `nomad-apm` plugin. Works with any
  Nomad cluster the operator manages.
- **Dynamic Application Sizing** (Nomad Enterprise): vertical
  `scaling "cpu" | "mem"` blocks producing sizing recommendations.
  Requires `spec.dynamicApplicationSizing` and a Prometheus (below).

## Spec

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `clusterRef.name` | `string` | | Name of the target NomadCluster. **Immutable** - retargeting would orphan the minted ACL credentials, so delete and recreate instead (the finalizer cleans up) |
| `clusterRef.namespace` | `string` | | Not supported (admission-rejected): the NomadCluster must be in the NomadAutoscaler's own namespace, because the agent pod mounts the cluster's TLS Secret and pods cannot mount Secrets across namespaces |
| `replicas` | `int` | `1` | Agent pods, 1-3. Above 1 enables the agent's [high-availability mode](#autoscaler-high-availability) |
| `image.repository` | `string` | `hashicorp/nomad-autoscaler-enterprise` | Agent image. Dynamic Application Sizing needs the enterprise image |
| `image.tag` | `string` | `0.5.0-ent` | Pinned concrete version, same rationale as [image version pinning](../operations/versions.md) |
| `image.digest` | `string` | | Optional content-digest pin; takes precedence over `tag` |
| `image.pullPolicy` | `string` | `Always` | Defence against registry-side retags of the pinned tag; applies even when the `image` block is omitted |
| `namespaces` | `[]string` | `["default"]` | Nomad namespaces the agent may observe and scale; drives both agent config and the minted ACL policy scope. `"*"` grants all and must be the only entry |
| `dynamicApplicationSizing.enabled` | `bool` | `false` | Enable DAS support |
| `dynamicApplicationSizing.prometheusURL` | `string` | | Prometheus endpoint for usage history. Required when DAS is enabled (admission-enforced) |
| `monitoring.enabled` | `bool` | `true` | Create the metrics Service (and ServiceMonitor where the CRD exists) for the agent's `/v1/metrics` endpoint |
| `monitoring.prometheusRulesEnabled` | `bool` | `false` | Create a PrometheusRule with the operator's [autoscaler alerts](#autoscaler-alerts). Same opt-in shape as the NomadCluster field; deleted when toggled off |
| `logLevel` | `string` | `INFO` | `DEBUG`, `INFO`, or `WARN` |
| `enableDebug` | `bool` | `false` | Expose the agent's pprof endpoints |
| `resources` / `nodeSelector` / `tolerations` | | | Standard pod scheduling knobs for the agent |

Spec changes roll the agent automatically: the pod template carries
`checksum/config` and `checksum/secrets` annotations (rendered config
and minted token respectively), and the Deployment uses a surge rollout
(`maxSurge: 1`, `maxUnavailable: 0`) so a warm agent is always up.
Direct edits to the agent Deployment - including
`kubectl rollout restart` - are reverted by the reconciler; roll the
agent by changing the CR spec instead.

## Client telemetry prerequisites

Nomad **client** agents are [outside the operator's scope](../index.md#architectural-boundaries),
and by default Nomad 2.x collects **no task statistics** - the
autoscaler's `nomad-apm` queries read 0 and DAS has no usage history.
Every client must set:

```hcl
telemetry {
  publish_allocation_metrics = true
  publish_node_metrics       = true
  prometheus_metrics         = true
}
```

`prometheus_metrics` is what makes `/v1/metrics?format=prometheus`
answer (without it the endpoint returns 415), which the DAS Prometheus
scrapes.

!!! warning
    None of these failure modes surface in agent errors. The symptom
    is scaling policies that evaluate to zero.

## Dynamic Application Sizing

Sizing is computed from usage **history**, which Nomad itself does not
retain - that is why `prometheusURL` is required: point it at a
Prometheus instance that scrapes the client agents' `/v1/metrics`
endpoints. Recommendations surface in the Nomad UI and the
`/v1/recommendations` API. Note the recommendations API is compiled
out of CE binaries: query an enterprise server (a CE binary answers
501, including the CLI talking through a CE client agent). Running the
enterprise binary on client nodes removes the caveat; clients need no
license of their own.

## Autoscaler high availability

At `replicas > 1` the agents form a leader-election group over a Nomad
Variables lock (namespace `default`, path
`nomad-autoscaler/<k8s-namespace>/<name>/lock` - operator-owned and
unique per CR, so two instances never share an election). Only the
leader evaluates policies; standbys are warm. The operator adds a
PodDisruptionBudget (`minAvailable: 1`) and preferred pod
anti-affinity, both removed when `replicas` returns to 1.

Failover timing with the agent's defaults (`lock_ttl 60s`,
`lock_delay 30s`, acquire retry ~66s), measured on a live cluster:

- **Graceful shutdown** (rollout, drain, pod delete): the agent
  releases the lock on SIGTERM, and `lock_delay` does not apply to a
  released lock. Takeover completes in ~2s when another pod is starting
  (rollouts), worst case one standby retry period (~66s).
- **Leader crash** (SIGKILL, OOM, node loss): the lock must expire -
  TTL from the last renewal plus `lock_delay`, plus the standby's next
  acquire attempt, ~3 minutes. Expect **no scaling actions
  for up to ~3 minutes** after a leader crash; size scaling policy
  cooldowns accordingly.

## Autoscaler ACL Token

The autoscaler **requires ACLs** on the referenced NomadCluster
(`spec.server.acl.enabled: true`, the default): the agent authenticates
with a dedicated token the operator mints. A cluster with ACLs disabled
is reported as a terminal misconfiguration - `Ready=False` with reason
`ACLsDisabled` and a Warning Event. It is not reported as a transient wait.

The operator creates policy `autoscaler-agent-<namespace>-<name>`
scoped to exactly what the spec needs: `scale` on each entry in
`spec.namespaces`, `node:read`, `operator:read` (the enterprise agent's
startup license check), variables access on the HA lock path when
`replicas > 1`, and `submit-recommendation` when DAS is enabled. The
policy is re-upserted on spec changes so it tracks the CR. The token
lives in the `<name>-autoscaler-token` Secret; if the operator re-mints
it (for example after an out-of-band deletion in Nomad), a
`checksum/secrets` annotation rolls the agent pods onto the new token.
Token and policy are deleted from Nomad when the NomadAutoscaler is
deleted.

## Autoscaler alerts

With `monitoring.prometheusRulesEnabled: true` (and the Prometheus
Operator CRDs present), the operator maintains a PrometheusRule scoped
to this instance's metrics Service:

| Alert | Severity | Fires when |
|-------|----------|------------|
| `NomadAutoscalerScalingErrors` | warning | Scaling invocations are returning errors (`scale_invoke_error_count` increasing) for 5m |
| `NomadAutoscalerPolicyEvaluationsStalled` | warning | Scaling policies exist but no policy evaluations ran in 30 minutes - in HA mode only the leader evaluates, so check leader election first |
| `NomadAutoscalerAgentDown` | critical | An agent's metrics scrape target has been down for 5 minutes |

## Conditions

`Ready=True` (reason `Deployed`) requires at least one ready agent
replica. `Ready=False` reasons: `ClusterNotFound`, `ACLsDisabled`
(terminal, also emitted as a Warning Event),
`WaitingForACLBootstrap`, `WaitingForManagementToken`,
`TokenCreationFailed` (also emitted as a Warning Event), and
`DeploymentNotReady`. A separate `Degraded` condition tracks agent
health past the Ready snapshot: `AgentUnavailable` when ready replicas
sit below desired for over two minutes, and `RolloutStuck` when the
Deployment exceeds its progress deadline (the surge strategy keeps
`Ready=True` on the old pods in that case - watch `Degraded`, which
also emits an `AutoscalerDegraded` Warning Event once per transition).

## Example

```yaml
apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadAutoscaler
metadata:
  name: autoscaler
spec:
  clusterRef:
    name: nomad
  replicas: 2
  dynamicApplicationSizing:
    enabled: true
    prometheusURL: http://das-prometheus:9090
```

The full annotated sample is in
[`config/samples/nomad_v1alpha1_nomadautoscaler.yaml`](https://github.com/benemon/nomad-enterprise-operator/blob/main/config/samples/nomad_v1alpha1_nomadautoscaler.yaml).


