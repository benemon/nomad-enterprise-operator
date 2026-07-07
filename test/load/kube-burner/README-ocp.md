# Operator load testing on OpenShift (local OCP lane)

The [kind lane](README.md) is the cheap, reproducible baseline run by
the **Load Test** GitHub Actions workflow. This lane runs the *same*
rig (`config.yml`, `metrics.yml`, `alerts.yml`, `templates/`) against a
real OpenShift cluster to reach tiers the 4-vCPU GHA runners can't
(the roadmap's Category 2: fleet 50-200, multi-replica lifecycle,
churn-at-scale) and to exercise the platform surface kind never sees —
SCCs, and User Workload Monitoring (UWM) scraping the operator's own
ServiceMonitor end-to-end.

It is a **complement, not a re-baseline**: OCP is a different
substrate, so its numbers are their own calibration lane with their own
pinned gates. Keep the kind numbers as the reproducible reference.

## What differs from the kind lane

Only the substrate diverges; the rig is env-driven and shared.

| Concern | kind lane | OCP lane |
|---|---|---|
| Image delivery | `kind load docker-image` | push to a registry OCP can pull |
| Metrics source | bundled `prometheus.yaml` + port-forward | **UWM** scrapes the operator's ServiceMonitor; query `thanos-querier` |
| Pod security | fixed UID 65532 | `OPENSHIFT=true` → SCC assigns the namespace range |
| `prometheus.yaml` | applied | **not applied** (UWM replaces it) |

The two OCP knobs (`config.yml` reads both from the environment):

- `PROMETHEUS_TOKEN` — a bearer token for `thanos-querier`; its presence
  switches the metrics endpoint to token + `skipTLSVerify`.
- `OPENSHIFT=true` — sets `spec.openshift.enabled` on every load
  cluster so the Nomad pods pass `restricted-v2` (the operator drops the
  hardcoded 65532 UID; `route.enabled` stays false, so NodePort remains
  the external service — no Route infrastructure needed).

## ⚠️ Do not run this alongside a live soak on the same cluster

Two independent hazards, the second fatal to co-location:

1. `make deploy` targets namespace `nomad-enterprise-operator-system`
   with namePrefix `nomad-enterprise-operator-` (cluster-scoped RBAC
   included). Redeploying over a running soak operator **replaces it and
   resets its RSS / keyring counters**, destroying the measurement.

2. The operator **watches all namespaces** (`cmd/main.go` builds the
   manager with no namespace-scoped cache; the OLM install carries
   `olm.targetNamespaces=""`). So a running operator reconciles *every*
   NomadCluster on the cluster — including a load fleet in any other
   namespace. That perturbs its workqueue, RSS, and reconcile counters,
   which is exactly what a soak measures. An isolating overlay (distinct
   namespace + namePrefix) fixes hazard 1 but **not** this one: the soak
   operator still reconciles the load clusters. There is no safe
   co-location until the operator gains namespace-scoped watching.

So while a soak is live on the target cluster, pick one:

1. Run this lane on a **different cluster** with no operator watching.
2. Run **after** the soak completes and its operator is torn down.

Do not attempt to co-locate on the soak's cluster.

## Prerequisites

- `oc` logged in as cluster-admin (SCC, UWM config, and the internal
  registry route all need it).
- `kube-burner` `v2.7.3` (match the workflow's pin) on your `PATH`.
- The Nomad Enterprise license at `test/e2e/testdata/nomad.hclic`.
- A container builder. **Arch note:** OCP nodes are amd64; an Apple
  Silicon dev host must cross-build (`make docker-buildx
  PLATFORMS=linux/amd64`), not `make docker-build`.

## 1. Enable User Workload Monitoring

UWM's Prometheus discovers ServiceMonitors in user namespaces. The
operator auto-creates its own (gated on the monitoring CRDs, which OCP
always has), so once UWM is on and the operator is deployed, its
metrics flow with no extra wiring.

```sh
oc -n openshift-monitoring patch configmap cluster-monitoring-config \
  --type merge -p '{"data":{"config.yaml":"enableUserWorkload: true\n"}}' \
  || oc -n openshift-monitoring create configmap cluster-monitoring-config \
       --from-literal=config.yaml=$'enableUserWorkload: true\n'
oc -n openshift-user-workload-monitoring rollout status statefulset/prometheus-user-workload --timeout=180s
```

If the cluster already has a `cluster-monitoring-config` with other
keys, edit it instead of the merge above and add `enableUserWorkload:
true` to the existing `config.yaml`.

## 2. Build and push the operator image

The operator image must be pullable by the cluster — `kind load` has no
OCP equivalent. Simplest is any external registry you can push to:

```sh
IMG=quay.io/<you>/nomad-enterprise-operator:load
make docker-buildx IMG=$IMG PLATFORMS=linux/amd64   # cross-build for amd64 nodes
```

Or the cluster's internal registry (pods then pull via the internal
service name). The target namespace must exist *before* the push — the
registry rejects pushes to a nonexistent project (`make deploy` only
creates it in step 3):

```sh
oc create namespace nomad-enterprise-operator-system
oc patch configs.imageregistry.operator.openshift.io/cluster --type merge \
  -p '{"spec":{"defaultRoute":true}}'
REG=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}')
oc registry login --registry="$REG"
IMG=$REG/nomad-enterprise-operator-system/nomad-enterprise-operator:load
make docker-buildx IMG=$IMG PLATFORMS=linux/amd64
# Deploy referencing the in-cluster service, not the external route:
IMG=image-registry.openshift-image-registry.svc:5000/nomad-enterprise-operator-system/nomad-enterprise-operator:load
```

## 3. Deploy the operator (heed the soak warning above)

```sh
make install
make deploy IMG=$IMG
oc -n nomad-enterprise-operator-system create secret generic nomad-license \
  --from-file=license=test/e2e/testdata/nomad.hclic
oc -n nomad-enterprise-operator-system rollout status \
  deploy/nomad-enterprise-operator-controller-manager --timeout=180s
```

## 4. Prepare the load namespace

```sh
oc create namespace nomad-load
oc -n nomad-load create secret generic nomad-license \
  --from-file=license=test/e2e/testdata/nomad.hclic
```

The load clusters run here under `restricted-v2`; `OPENSHIFT=true`
(step 6) is what lets their pods schedule.

## 5. Mint a thanos-querier token and URL

kube-burner runs on your host and queries `thanos-querier`'s
Prometheus API. Grant a ServiceAccount `cluster-monitoring-view` and
mint a short-lived token:

```sh
oc create serviceaccount loadtest-querier -n nomad-enterprise-operator-system
oc adm policy add-cluster-role-to-user cluster-monitoring-view \
  -z loadtest-querier -n nomad-enterprise-operator-system
export PROMETHEUS_TOKEN=$(oc create token loadtest-querier \
  -n nomad-enterprise-operator-system --duration=6h)
export PROMETHEUS_URL=https://$(oc -n openshift-monitoring get route thanos-querier -o jsonpath='{.spec.host}')
```

(No route? Port-forward instead: `oc -n openshift-monitoring
port-forward svc/thanos-querier 9091:9091` and set
`PROMETHEUS_URL=https://127.0.0.1:9091`.) `skipTLSVerify` is set
automatically whenever `PROMETHEUS_TOKEN` is present, so the router /
self-signed cert is not a blocker.

## 6. Run

```sh
cd test/load/kube-burner
OPENSHIFT=true ITERATIONS=25 kube-burner init -c config.yml --log-level=info
```

Convergence gate 1 (every NomadCluster reaches `phase=Running` inside
`maxWaitTimeout`, else the run fails) and the workqueue-depth alert
apply here exactly as on the kind lane.

### Operand pod-sizing sweep

The `SERVER_CPU` / `SERVER_MEMORY` knobs
([kind README](README.md#operand-pod-sizing-knob)) work here too, and
this is the lane where the sweep is self-scoring: `thanos-querier`
exposes the operand containers' cadvisor/kube-state series that the
kind lane cannot see, `metrics.yml` collects them (working-set bytes,
CFS-throttle ratio, OOMKilled last-state, restarts), and `alerts.yml`
fails the run on any operand OOMKill or a sustained throttle ratio
above 25%. Step the values down across runs; the convergence gate
still catches outright won't-boot.

Set `HOLD` to keep the converged fleet alive before the delete-wave —
the steady-state samples come from that window (a size can pass boot
yet OOM minutes later under GC/raft-snapshot pressure):

```sh
OPENSHIFT=true SERVER_MEMORY=256Mi SERVER_CPU=250m HOLD=15m ITERATIONS=25 \
  kube-burner init -c config.yml --log-level=info
```

First calibration (2026-07-07, N=10, idle single-replica servers):
boot working set ~33Mi (drifts to ~46Mi over an 8m hold); 40Mi
converges clean, 32Mi OOMKills 6/10. CPU throttle is boot-burst
dominated — 55% at 50m / 42% at 75m over the wave window, but
steady-state only 1.2% at 100m and 2.6% at 50m — so the sustained
gate passes idle servers at every tested size; it exists for the
load-backed sweep. Use `HOLD=10m` or more: the gate's coverage guard
needs ~7 minutes of pod life before it can evaluate.

First calibration caveat: those numbers were taken with **no Nomad
jobs** — an idle-server floor. The load-backed floor comes from the
next section.

### Real Nomad-side load: nodesim + nomad-load

The `SIM_NODES` / `LOAD_RATE` knobs put genuine scheduling pressure on
each load cluster using HashiCorp's own bench tooling —
[nomad-nodesim](https://github.com/hashicorp-forge/nomad-nodesim)
(simulated client fleets, the instrument behind nomad-bench) and
[nomad-bench](https://github.com/hashicorp-forge/nomad-bench)'s
`tools/nomad-load` (job register/dispatch pressure). Each knob adds a
per-cluster Deployment to the create-wave; the delete-wave reaps them
by the same `kube-burner.io/job` label. Unset knobs render nothing —
the run is byte-identical to a no-load one.

- `SIM_NODES=<n>` — one nodesim pod per cluster registers *n* simulated
  clients over RPC mTLS. It mounts the operator-issued `<cluster>-tls`
  Secret and presents its cert (the EKU covers `clientAuth`), so no new
  cert machinery. The simulated clients ship the `mock` driver, so
  dispatched jobs actually place and "run".
- `LOAD_RATE=<r>` — one nomad-load pod per cluster registers a
  parameterized mock batch job and dispatches it at *r*/s over HTTPS,
  authenticating with the CA plus the `<cluster>-acl-bootstrap` token.
  Each dispatch is an eval + alloc on a simulated node (`run_for: 10s`),
  so steady state carries ~10·*r* live allocations of state per cluster.
- `NODESIM_IMAGE` / `NOMAD_LOAD_IMAGE` — required once the matching
  knob is set (the config render fails loud if missing).
- `LOAD_LADDER=true` — the scale sweep. Cluster *i* carries `(i+1) ×`
  the base `SIM_NODES`/`LOAD_RATE`, so one run yields a full
  scale-response row for the resource profile under test: the per-pod
  operand series (`load-<i>-0` = rung *i+1*) read out as "this profile
  sustains rung *k*, fails at rung *k+1*". Stepping
  `SERVER_MEMORY`/`SERVER_CPU` down across ladder runs fills the
  profile-vs-scale matrix — workload scale is the third sizing vector
  alongside memory and CPU. In ladder runs the operand gates firing at
  the upper rungs is the *expected readout*, not a rig failure; uniform
  runs (no ladder) are the regression-gate mode for a chosen
  profile-and-scale pair once the knee is known.

The forge repos publish **no official images**; build and push to the
internal registry (upstream Dockerfiles as-is, pin the tag to the
upstream commit):

```sh
git clone https://github.com/hashicorp-forge/nomad-nodesim
git clone https://github.com/hashicorp-forge/nomad-bench
REG=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}')
oc registry login --registry="$REG"
oc get namespace nomad-load || oc create namespace nomad-load  # registry rejects pushes to a nonexistent project
# Pre-create the imagestreams: without them the registry answers the
# push's manifest existence-check with 500 (not 404) and docker aborts.
oc create imagestream nomad-nodesim -n nomad-load
oc create imagestream nomad-load -n nomad-load
docker buildx build --platform linux/amd64 --push \
  -t "$REG/nomad-load/nomad-nodesim:$(git -C nomad-nodesim rev-parse --short HEAD)" nomad-nodesim/
docker buildx build --platform linux/amd64 --push \
  -t "$REG/nomad-load/nomad-load:$(git -C nomad-bench rev-parse --short HEAD)" nomad-bench/tools/nomad-load/
```

Run with the pods pulling via the in-cluster registry service — a
ladder run sweeping rungs 10→100 sim nodes / 0.5→5 dispatches/s
against one profile:

```sh
OPENSHIFT=true ITERATIONS=10 LOAD_LADDER=true \
  SIM_NODES=10 NODESIM_IMAGE=image-registry.openshift-image-registry.svc:5000/nomad-load/nomad-nodesim:<tag> \
  LOAD_RATE=0.5 NOMAD_LOAD_IMAGE=image-registry.openshift-image-registry.svc:5000/nomad-load/nomad-load:<tag> \
  SERVER_MEMORY=128Mi SERVER_CPU=250m HOLD=8m MAX_WAIT=10m \
  kube-burner init -c config.yml --log-level=info
```

`MAX_WAIT` trims the convergence timeout on runs where upper rungs are
expected to fail — the OOM/throttle verdicts land in the metrics
either way, so there is no point waiting out the full 20m gate window.
Rung registration pace is ~2s per simulated client (a 100-node rung
takes ~3½ minutes to fully populate), so keep `HOLD` ≥ 8m for a
steady-state window at the top rungs.

Reading ladder runs: capture live pod state (restart counts,
`lastState: OOMKilled`) **before the delete-wave** — it is the
authoritative verdict. The indexed metrics corroborate, but filter by
the run's UUID (`collected-metrics/*.json` docs are appended across
runs and tagged), and know that back-to-back runs reuse pod names, so
a run's early Prometheus window can carry the previous run's dying
samples (observed live: a ladder run's OOM alert fired at window start
on ghosts from the prior run). Leave a gap between runs when alert
exit codes must be clean.

First load-backed calibration (2026-07-07, ladder runs at 250m CPU,
HOLD=8m, rung = 10·i nodes / 0.5·i disp/s): **128Mi sustains rung 3**
(30 nodes / 1.5 disp/s; rungs 4+ OOM), **256Mi sustains rung 6**
(60 nodes / 3 disp/s, marginal; rungs 7+ OOM); working set grows
roughly linearly with rung (90→255Mi across the 256Mi ladder) and
grows through the hold — dead dispatch jobs accumulate until Nomad's
job GC (default threshold 4h), so verdicts are hold-relative and
conservative. CPU: momentary boot/restart throttle bursts up to 90%
at top rungs, but the sustained gate never fired — memory fails first
at 250m. Uniform control (50 nodes / 2 disp/s at 128Mi): all 10
replicas OOMKilled ~6m into the hold. Consequence: the operator's
shipped defaults (512Mi request / 2Gi limit) are sane under real load;
do not publish the idle floor as sizing guidance.

Spot-check that the simulation is real: `nomad node status` inside any
server pod must count exactly `SIM_NODES` ready clients, and `nomad job
status` shows the dispatched batch children churning.

Sequencing is free: the kubelet blocks the nodesim pod until the
operator creates `<cluster>-tls`, and the nomad-load container until
`<cluster>-acl-bootstrap` exists — both appear during cluster boot, so
the drivers start as their cluster converges.

## Ramp-to-failure: one long-lived cluster (`config-ramp.yml`)

A second, independent profile (neo-1je; the fleet rig above is untouched).
Instead of many ephemeral clusters, ONE long-lived 3-server HA cluster at
the operand's **shipped defaults** (req 250m/512Mi, lim 2/2Gi — `resources`
omitted) takes a stepped client+dispatch ramp until it fails
**functionally**. The question it answers: where does a default-sized HA
cluster actually break, and how does it degrade?

Deploy the target once (prereqs as above: operator deployed, `nomad-load`
namespace + license secret, driver images pushed):

```sh
oc apply -f ramp-cluster.yml
oc -n nomad-load wait nomadcluster/ramp --for=jsonpath='{.status.phase}'=Running --timeout=15m
LB=$(oc -n nomad-load get nomadcluster ramp -o jsonpath='{.status.advertiseAddress}')
```

The external Service is the CRD-default **LoadBalancer** (the lab's
MetalLB assigns a VIP), and Nomad serves its UI on the same HTTP port —
watch the run live at `https://$LB:4646/ui` (self-signed cert; log in with
the `ramp-acl-bootstrap` token: `oc -n nomad-load get secret
ramp-acl-bootstrap -o jsonpath='{.data.secret-id}' | base64 -d`).

Each ramp-wave iteration adds one nodesim step (`STEP_NODES` clients) and
one nomad-load step (`STEP_RATE` disp/s) against the fixed cluster, then
plateaus for `STEP_DELAY` (default 5m). Load AGGREGATES: step *i* brings
the cluster to `(i+1)·STEP_NODES` clients and `(i+1)·STEP_RATE` disp/s.
The nomad-load instances share one deterministic parameterized job
(`test_job_0_1`), so rates sum cleanly. The neo-0g1 profile ratio is 10
clients : 0.5 disp/s — keep `STEP_RATE = STEP_NODES/20` for
cross-comparison. There is no alerts profile: en-route operand OOMKills
are expected data points, not the verdict — a 3-server cluster should
ride out single-server kills.

```sh
STEPS=20 STEP_NODES=50 STEP_RATE=2.5 \
  NODESIM_IMAGE=image-registry.openshift-image-registry.svc:5000/nomad-load/nomad-nodesim:<tag> \
  NOMAD_LOAD_IMAGE=image-registry.openshift-image-registry.svc:5000/nomad-load/nomad-load:<tag> \
  kube-burner init -c config-ramp.yml --log-level=info
```

**The failure verdict is functional, watched from outside via the LB**
(the watcher, run alongside; timestamps + step boundaries locate the
failure point):

```sh
TOKEN=$(oc -n nomad-load get secret ramp-acl-bootstrap -o jsonpath='{.data.secret-id}' | base64 -d)
while true; do
  ts=$(date -u +%FT%TZ)
  leader=$(curl -sk --max-time 5 "https://$LB:4646/v1/status/leader" || echo UNRESPONSIVE)
  nodes=$(curl -sk --max-time 5 -H "X-Nomad-Token: $TOKEN" "https://$LB:4646/v1/nodes" | jq 'map(select(.Status=="ready")) | length' 2>/dev/null || echo '?')
  echo "$ts leader=$leader ready_nodes=$nodes"
  sleep 15
done | tee ramp-watch.log
```

Failure = leader empty/`UNRESPONSIVE` sustained across a plateau, or the
API refusing service. Registration stalls (`ready_nodes` stops tracking
the cumulative target) are degradation data, not the verdict. Capture
server pod state (`oc -n nomad-load get pods -l app.kubernetes.io/instance=ramp
-o wide`, restart counts, `lastState`) at each event — pod-level events
are en-route data.

On functional failure, abort the run (Ctrl-C kube-burner) and reap the
step drivers by hand — the in-config delete-wave only runs on a
survived-to-ceiling run. The cluster itself is never kube-burner's (no
`kube-burner.io/job` label) and stays up for post-mortem either way:

```sh
oc -n nomad-load delete deploy -l kube-burner.io/job=ramp-wave
```

## Reading a run

`collected-metrics/` holds one JSON document per metrics-profile query
per job window (workqueue depth/latency, reconcile outcomes, RSS, CPU
rate, Nomad API requests). The reading rules from the
[kind README](README.md#metricsyml--the-operator-side-series) hold:
counters are cumulative (read deltas between the create-wave and
delete-wave windows), and happy-path reconciles land in
`requeue_after`, not `success`.

## Gates need OCP calibration

`alerts.yml`'s `workqueue_depth > 5` threshold is calibrated on 4-vCPU
kind and pinned for that lane. OCP holds larger tiers with different
headroom, so its gates must be **calibrated on a first run and then
pinned separately** — do not assume the kind thresholds transfer.
Record the OCP tier numbers and pinned gates back in neo-31u, as the
kind tiers were.
