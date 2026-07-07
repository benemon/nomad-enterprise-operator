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
service name):

```sh
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
