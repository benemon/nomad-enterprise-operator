# Operator load testing (neo-31u)

Fleet-scale load test for the **operator** — real kind cluster, real
Nomad Enterprise servers, operator-side measurements only.

```sh
make test-load LOAD_N=10          # tier size; results in test/load/results-*.txt
```

Scenarios: create wave (per-cluster seconds to Running), steady-state
soak, delete wave (finalizer fan-out). Between scenarios the rig
scrapes the operator's own metrics endpoint using a dedicated
`loadtest-metrics` ServiceAccount bound to the shipped
`metrics-reader` ClusterRole.

Reading the numbers:

- Counters are **cumulative across operator lifetime** — read deltas
  between scrapes, not absolutes.
- Happy-path reconciles end in `requeue_after` (the steady-state
  heartbeat), not `success`; `success` moves mainly on deletions.
- Never run in the PR lane; tiers are host-calibrated.

## Calibration baseline (N=10, kind, 2026-07-05)

- Create wave: all Running in 79–80s wall-clock (per-cluster 39–80s);
  workqueue depth 0 at every sample; avg queue latency ~17ms.
- Operator cost for the whole wave: +4.7MB RSS, +1.0 CPU-seconds.
- Delete wave: sub-second for the tier (single-cluster deletion
  measured at ~150ms end-to-end on a local apiserver).
- Finding: ~3 transient reconcile errors per cluster during boot
  (not-ready conditions surfacing as errors rather than requeues) —
  pollutes error-rate alerting; tracked for cleanup.
