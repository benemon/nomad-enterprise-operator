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

The shipped PrometheusRule carries one rule group (`nomad.rules`)
whose 13 alerts cover three concerns: health
(leader loss, server down, job failures, memory, Raft backlog and
commit latency), lifecycle expiry (CA and server certificates,
license), and control-plane saturation. `NomadEvalsBlocked` and
`NomadPlanQueueBacklog` fire on the scale-trigger signals;
`NomadRaftCommitSlow` fires on the symptom of under-provisioned
storage or CPU. When the saturation alerts fire:

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
| `nomad_operator_keyring_token_renewals_total` | Counter | `cluster`, `namespace`, `entry` | Successful Vault keyring-token renewals per transit entry; read as a rate against mints |
| `nomad_operator_keyring_token_mints_total` | Counter | `cluster`, `namespace`, `entry` | Vault keyring-token mints (fresh logins) per transit entry; a rising rate with flat renewals signals a re-mint storm |

A Grafana dashboard covering these metrics plus the controller-runtime
reconcile, workqueue, and process series ships in the repository at
`config/grafana/operator-dashboard.json`. Import it and point the
datasource variable at the Prometheus that scrapes the operator.


## Capacity

**Cardinality budget:** the operator supports ≤200 NomadClusters per
operator instance. Multi-instance operator deployments (sharded by
namespace or otherwise) are not supported: run exactly one operator
per Kubernetes cluster and treat 200 NomadClusters as the ceiling for
that instance.

Measured monitoring cost per operand cluster (1-replica cluster, Nomad
2.0.5-ent, the operator ServiceMonitor at its 30s cadence):

| Quantity | Idle cluster | Under dispatch churn (175 clients, ~9 dispatch/s) |
|----------|-------------|--------------------------------------------------|
| Stored series per cluster | 234 | 618 |
| `/v1/metrics` scrape payload | ~240 KiB | ~2.6 MiB |

Under dispatch churn ~96% of the samples the endpoint exposes are
per-dispatch-child series; the shipped `metricRelabelings` rule drops
them at scrape, which is why stored series stay in the hundreds while
the payload grows tenfold. The payload is still transferred and parsed
on every scrape, so the binding cost at fleet scale is scrape
bandwidth and ingest parsing, not TSDB cardinality: 200 clusters under
sustained dispatch churn present ~17 MiB/s of scrape payload to
Prometheus, while stored series stay in the 47k (idle) to 124k
(churning) range - comfortable for a single mid-size Prometheus.

The operator's own metrics add ~176 series per cluster, dominated by
the `nomad_operator_phase_duration_seconds` histogram (phases x
buckets); at 200 clusters that is ~35k series.

**Retention sizing:** at the 30s cadence each cluster writes 2,880
samples per series per day; at ~1.5 bytes per compressed sample the
TSDB cost is roughly

```
bytes ≈ clusters × series_per_cluster × 2880 × 1.5 × retention_days
```

or ~1 MiB per idle cluster per day (234 series) and ~2.7 MiB per
churning cluster per day (618 series). A 200-cluster fleet with 30-day
retention sizes to ~6-16 GiB of TSDB, before Prometheus overheads.

**Operator control-plane cost** (measured on a 10-cluster fleet,
kind on an 8-core/8 GiB Docker VM): converging 10 simultaneously
created clusters takes ~76s end to end; reconcile p50 is ~35ms with
p99 spiking to ~40s during ACL bootstrap (the reconcile blocks on
first Nomad API availability); workqueue depth peaks at 3 with p99
queue wait ~9s during the burst and returns to zero at steady state.
Steady-state cost at 10 clusters is ~0.5% of one core and ~68 MiB RSS.
The scaling constraint during create bursts is long ACL-bootstrap
reconciles serialized over the controller's 4 concurrent workers -
queue wait grows with the number of clusters bootstrapping at the same
moment, not with fleet size at rest.


