/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package metrics declares the operator's Prometheus metric handles,
// registered on controller-runtime's default registry (:8443/metrics).
//
// TEST ISOLATION: the registry is process-global across the whole test
// binary — tests must use label values unique to the test, or delta
// assertions, to avoid cross-contaminating counters.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// PhaseDuration observes wall-clock seconds per reconciliation phase
	// per cluster (AC-8.1.1, populated by D4a).
	PhaseDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "nomad_operator_phase_duration_seconds",
		Help:    "Duration of each reconciliation phase in seconds, per NomadCluster.",
		Buckets: prometheus.DefBuckets,
	}, []string{"cluster", "namespace", "phase"})

	// NomadAPIRequests counts Nomad API calls by method and outcome
	// (AC-8.1.2, populated by D4b's NomadAPI decorator).
	NomadAPIRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nomad_operator_nomad_api_requests_total",
		Help: "Total Nomad API requests issued by the operator, by method and outcome.",
	}, []string{"method", "outcome"})

	// CertExpiry exports the NotAfter timestamp (Unix seconds) of each
	// managed certificate (AC-8.1.3, populated by D4c).
	CertExpiry = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nomad_operator_cert_expiry_timestamp_seconds",
		Help: "Expiry (NotAfter) of operator-managed certificates as a Unix timestamp, per cluster and certificate.",
	}, []string{"cluster", "namespace", "cert"})

	// LicenseExpiry exports the Nomad Enterprise license expiration as a
	// Unix timestamp (AC-8.1.4, populated by D4d).
	LicenseExpiry = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nomad_operator_license_expiry_timestamp_seconds",
		Help: "Nomad Enterprise license expiration as a Unix timestamp, per cluster.",
	}, []string{"cluster", "namespace"})

	// ACLBootstrapFailures counts failed ACL bootstrap attempts
	// (AC-8.1.5, populated by D4e).
	ACLBootstrapFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nomad_operator_acl_bootstrap_failures_total",
		Help: "Total failed ACL bootstrap attempts, per cluster.",
	}, []string{"cluster", "namespace"})

	// ScaleDownInProgress is 1 while a Raft scale-down operation is
	// running for a cluster, else 0 (AC-8.1.6, populated by D2e).
	ScaleDownInProgress = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nomad_operator_scale_down_in_progress",
		Help: "1 while a Raft scale-down operation is in progress for the cluster, else 0.",
	}, []string{"cluster", "namespace"})

	// NomadVersionInfo is an info-style gauge (constant 1) carrying the
	// version as a label; the previous series is deleted on version
	// change to bound cardinality.
	NomadVersionInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nomad_operator_nomad_version_info",
		Help: "Observed Nomad server version per cluster; value is always 1, version carried as a label.",
	}, []string{"cluster", "namespace", "version"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		PhaseDuration,
		NomadAPIRequests,
		CertExpiry,
		LicenseExpiry,
		ACLBootstrapFailures,
		ScaleDownInProgress,
		NomadVersionInfo,
	)

	// Seed each vec with an empty-label child so every family appears
	// on /metrics from startup (a child-less vec exports nothing).
	// PromQL treats empty label values as absent, so no collisions.
	PhaseDuration.WithLabelValues("", "", "").Observe(0)
	NomadAPIRequests.WithLabelValues("", "").Add(0)
	CertExpiry.WithLabelValues("", "", "").Set(0)
	LicenseExpiry.WithLabelValues("", "").Set(0)
	ACLBootstrapFailures.WithLabelValues("", "").Add(0)
	ScaleDownInProgress.WithLabelValues("", "").Set(0)
	NomadVersionInfo.WithLabelValues("", "", "").Set(0)
}
