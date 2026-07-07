# Operator load testing with kube-burner

This directory is the load-test rig for the **operator** (neo-31u's
successor to the original bash driver). It uses
[kube-burner](https://kube-burner.github.io/kube-burner/latest/), a
CNCF tool for churning Kubernetes objects at scale and measuring what
happens — the same tool the OpenShift performance and scale team uses.
The NomadClusters are the load; the operator is the thing being
measured.

Run it via the **Load Test** GitHub Actions workflow (manual dispatch,
`tier` input = fleet size). Standard 4 vCPU runners hold ~12
one-replica clusters — the ceiling was established empirically, with
the operator's queue depth at zero while the host starved.

To run this same rig against a real OpenShift cluster for larger tiers
and to exercise SCCs + User Workload Monitoring, see
[README-ocp.md](README-ocp.md). This file documents the kind lane; the
config is env-driven and shared between both.

## How a run works

`kube-burner init -c config.yml` executes the *jobs* in `config.yml`
in order, taking *measurements* while they run, collecting *metrics*
at job boundaries, and evaluating *alerts* at the end. Every file in
this directory maps to one of those concepts.

## config.yml — jobs and waiting

Doc: [configuration reference](https://kube-burner.github.io/kube-burner/latest/reference/configuration/)

Two jobs run in order:

1. **create-wave** (`jobType: create`) renders
   `templates/nomadcluster.yml` once per iteration (`jobIterations`
   comes from the `ITERATIONS` env var — the config file itself is a
   Go template fed by environment variables). All objects land in one
   namespace (`namespacedIterations: false`), matching how a real
   fleet shares namespaces.

   The load-bearing part is the wait:

   ```yaml
   waitOptions:
     customStatusPaths:
       - key: '(.phase)'
         value: Running
   ```

   `customStatusPaths` ([docs](https://kube-burner.github.io/kube-burner/latest/reference/configuration/#waitoptions))
   takes jq expressions evaluated against each object's `.status`;
   kube-burner blocks until every NomadCluster reports
   `status.phase: Running` or `maxWaitTimeout` (20m) expires — and a
   timeout **fails the run**. That *is* convergence gate 1: a fleet
   that doesn't fully converge is a failed tier, never a silent pass
   (the bash rig's first GHA run reported success with three
   never-converged clusters; this design makes that impossible).

2. **delete-wave** (`jobType: delete`) removes everything the create
   job made, selected by the `kube-burner-job` label kube-burner
   stamps on its objects. This exercises the operator's deletion path
   (finalizers: ACL cleanup, StatefulSet-before-PVC ordering) as a
   fan-out.

## templates/nomadcluster.yml — the load unit

Doc: [object templates](https://kube-burner.github.io/kube-burner/latest/reference/configuration/#objects)

A minimal 1-replica cluster named `load-{{ .Iteration }}` —
`{{ .Iteration }}` is kube-burner's per-iteration counter. `emptyDir`
data (`persistence.size: ""`) keeps the tier's cost in operator work
rather than PVC churn; `NodePort` avoids the LoadBalancer-IP wait that
never resolves on kind. The license Secret is pre-created by the
workflow (the operator retries cleanly until it exists).

### Operand pod-sizing knob

`SERVER_CPU` and `SERVER_MEMORY` set the Nomad **server** pods'
`spec.resources` — request and limit together, so each squeezed
resource is Guaranteed QoS and its OOM/throttle boundary *is* the value
under test. Unset (the default, and the whole GHA lane) omits the field
and the operator supplies its own default (requests 250m/512Mi, limits
2/2Gi); either knob may be set alone, since the operator fills the
unset fields per-field.

This is the operand floor sweep: step the values **down** across runs
and the convergence gate (every server must reach `phase=Running`
inside `maxWaitTimeout`) catches the **won't-boot floor** for free — no
extra instrumentation. The narrower OOM-vs-throttle floor uses the
operand-side series in `metrics.yml` and the OOMKilled / CFS-throttle
gates in `alerts.yml` — those need cadvisor/kube-state sources the kind
lane's bundled Prometheus does not scrape, so they only bite on the OCP
lane ([README-ocp.md](README-ocp.md)); on kind they return empty and
never fire.

`HOLD` keeps the converged fleet alive for a duration before the
delete-wave (`jobPause`, inside the create-wave measurement window), so
steady-state operand samples exist — without it the pods live seconds
and a size can pass at boot yet fail minutes later.

`SIM_NODES` / `LOAD_RATE` add per-cluster load drivers (simulated
client fleets + job-dispatch pressure) so the sweep sizes a *working*
server rather than an idle one. They need purpose-built images, so they
are documented with the OCP lane
([README-ocp.md](README-ocp.md#real-nomad-side-load-nodesim--nomad-load));
unset, they render nothing and this lane is untouched.

```sh
SERVER_MEMORY=256Mi SERVER_CPU=250m HOLD=10m ITERATIONS=10 kube-burner init -c config.yml
```

## Measurements

Doc: [measurements](https://kube-burner.github.io/kube-burner/latest/measurements/)

None enabled. `podLatency` (the usual choice) tracks pods created by
the kube-burner job itself — this rig's pods are operator-created
secondaries, which it cannot see. Convergence timing comes from the
job duration (the create-wave cannot finish before every NomadCluster
reports Running) and the operator's reconcile-duration series in the
metrics profile.

## metrics.yml — the operator-side series

Doc: [metrics collection](https://kube-burner.github.io/kube-burner/latest/observability/metrics/)

A *metrics profile*: PromQL queries kube-burner runs against
Prometheus at job boundaries, tagged with the job window and written
by the local indexer
([docs](https://kube-burner.github.io/kube-burner/latest/observability/indexing/))
to `collected-metrics/` — uploaded as the workflow artifact.

The queries are the operator's saturation and cost story: workqueue
depth and average queue latency, reconcile outcomes, RSS, CPU rate,
and Nomad API request counts. Two reading rules: counters are
cumulative across the operator's lifetime (read deltas between
windows), and happy-path reconciles finish as `requeue_after` — the
steady-state heartbeat — not `success` (which moves mainly on
deletions).

## alerts.yml — operator-side gates

Doc: [alerting](https://kube-burner.github.io/kube-burner/latest/observability/alerting/)

An *alert profile*: expressions evaluated over the run window;
`severity: error` fails the run. Gate 2 lives here — sustained
nomadcluster workqueue depth means operator saturation. The threshold
is pinned from calibration: depth stayed at zero through every wave
at these tiers, so any sustained depth is signal. Add gates here as
tiers grow (reconcile-error rate, queue-latency ceilings).

## prometheus.yaml — the metrics source

kube-burner queries a Prometheus API rather than scraping `/metrics`
directly, so the workflow installs a pinned
[prometheus-operator](https://github.com/prometheus-operator/prometheus-operator)
and this minimal `Prometheus` instance. It selects **every
ServiceMonitor in the operator namespace** — which includes the one
the operator creates for itself — so the rig exercises the shipped
monitoring surface end-to-end: the scraper authenticates through the
operator's kube-rbac-proxy using the shipped `metrics-reader`
ClusterRole, exactly as a user's Prometheus would.

## Reading a run

Download the workflow artifact. `collected-metrics/` contains one
JSON document per metrics-profile query per job window, plus the
`podLatency` measurement documents (quantile summaries and raw
per-pod records). Compare operator series across the `create-wave`
and `delete-wave` windows; the podLatency quantiles are the
per-cluster convergence distribution.

## GHA baseline (N=10, ubuntu-latest, 2026-07-05)

First green parity run: create-wave 76s wall-clock (10 clusters,
Prometheus stack sharing the 4 vCPU), delete-wave 2s, workqueue depth
0 throughout. Matches the local bash-rig calibration (N=10: 79-80s) —
the flip changed the harness, not the numbers.

## Gates (pinned from calibration, 2026-07-05)

| Gate | Mechanism | Rationale |
|------|-----------|-----------|
| Fleet fully converges | `customStatusPaths` wait + `maxWaitTimeout` | partial convergence is a failed tier, not a pass |
| No sustained workqueue depth | `alerts.yml` | depth was zero at every calibrated tier; sustained depth = operator saturation, distinct from host ceilings |
