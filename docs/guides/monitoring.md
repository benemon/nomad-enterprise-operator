# Monitoring

ServiceMonitor and PrometheusRule are created when monitoring is enabled
AND the Prometheus Operator CRDs (`monitoring.coreos.com/v1`) are installed
- on any Kubernetes distribution, independent of `openshift.enabled`.
Clusters without the CRDs skip monitoring resources cleanly.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `monitoring.enabled` | `bool` | `true` | Create ServiceMonitor |
| `monitoring.prometheusRulesEnabled` | `bool` | `false` | Create PrometheusRule |

Scrape cadence is operator-owned (30s interval, 10s timeout). The
ServiceMonitor scrapes `/v1/metrics` over HTTPS and targets the
headless service only (marked `nomad.hashicorp.com/metrics: "true"`)
- `publishNotReadyAddresses` keeps telemetry flowing while pods are
unready during a leaderless window, which is exactly when you need it.

**Dispatched-job series are dropped by default.** The ServiceMonitor
ships a `metricRelabelings` rule discarding series with
`exported_job=~".*dispatch-.*"` (per-child `job_summary_*` and
`blocked_evals_job_*`). Dispatch children are ephemeral and each one
mints new series; under a dispatch workload this floods shared
Prometheus with thousands of short-lived series. Nomad acknowledges
the same trade server-side with
[`disable_dispatched_job_summary_metrics`](https://developer.hashicorp.com/nomad/docs/configuration/telemetry).
Consequences to plan for:

- **`NomadJobFailed` cannot fire for dispatched jobs** - the series is
  dropped at scrape, so no downstream rule can recover it. Track
  dispatch outcomes in the system that calls `job dispatch` (dispatch
  response + [event stream](https://developer.hashicorp.com/nomad/api-docs/events)),
  not via Prometheus.
- Blocked-eval *attribution* for dispatch children is unavailable in
  Prometheus; the aggregate `NomadEvalsBlocked` alert still fires, and
  `nomad eval list` identifies the job at debug time.
- If your Prometheus is sized for the churn, create an additional
  ServiceMonitor without the drop rule targeting the marked headless
  service - the operator does not prevent supplementary monitors.

The shipped PrometheusRule covers three concern groups: health
(leader loss, server down, job failures, memory, Raft backlog and
commit latency), lifecycle expiry (CA and server certificates,
license), and control-plane saturation. `NomadEvalsBlocked` and
`NomadPlanQueueBacklog` fire on the scale-trigger signals;
`NomadRaftCommitSlow` fires on the symptom of under-provisioned
storage or CPU. All expressions target metric names verified against
live Nomad 2.0.x telemetry. When the saturation alerts fire:

> Scale the servers vertically first; scale horizontally (3 → 5
> servers) when sustained scheduler saturation persists at the larger
> instance size.

*- HashiCorp Validated Design: Nomad Enterprise Operating Guide*


## Operator metrics

The operator exports its own Prometheus metrics on the existing
`:8443/metrics` endpoint (HTTPS, kube-rbac-proxy-style auth via
ServiceAccount bearer token). When the Prometheus Operator CRDs are
installed, the operator creates a ServiceMonitor for itself
automatically; the declarative equivalent ships at
`config/prometheus/operator-monitor.yaml`.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nomad_operator_phase_duration_seconds` | Histogram | `cluster`, `namespace`, `phase` | Wall-clock duration of each reconciliation phase. Expected range: milliseconds (no-op phases) to low seconds (certificate issuance) |
| `nomad_operator_nomad_api_requests_total` | Counter | `method`, `outcome` | Nomad API requests issued by the operator. `outcome` is `success` or `error` |
| `nomad_operator_cert_expiry_timestamp_seconds` | Gauge | `cluster`, `namespace`, `cert` | NotAfter of each operator-managed certificate as a Unix timestamp. Alert when `< time() + 30d` |
| `nomad_operator_license_expiry_timestamp_seconds` | Gauge | `cluster`, `namespace` | Nomad Enterprise license expiration as a Unix timestamp |
| `nomad_operator_acl_bootstrap_failures_total` | Counter | `cluster`, `namespace` | Failed ACL bootstrap attempts. Any non-zero rate warrants investigation |
| `nomad_operator_scale_down_in_progress` | Gauge | `cluster`, `namespace` | 1 while a Raft scale-down operation is running, else 0 |
| `nomad_operator_nomad_version_info` | Gauge | `cluster`, `namespace`, `version` | Constant 1; the observed Nomad server version is carried as a label. The previous series is deleted on version change so each cluster exposes a single version label |

**Cardinality budget:** the operator is designed for ≤200 NomadClusters
per operator instance. Beyond that, the per-cluster label on
`nomad_operator_phase_duration_seconds` produces histogram cardinality
you should size your Prometheus storage for. Multi-instance operator
deployments (sharded by namespace) are not currently supported.


