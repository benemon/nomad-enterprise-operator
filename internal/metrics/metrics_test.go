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

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// TestMetricsRegistered (AC-F4.2) asserts all seven §8.1 handles are
// registered on controller-runtime's default registry under their
// canonical names. Each handle gets one labelled child first so the vecs
// materialise in Gather output.
func TestMetricsRegistered(t *testing.T) {
	PhaseDuration.WithLabelValues("c", "ns", "Certificate").Observe(0)
	NomadAPIRequests.WithLabelValues("GetLeader", "success").Add(0)
	CertExpiry.WithLabelValues("c", "ns", "ca").Set(0)
	LicenseExpiry.WithLabelValues("c", "ns").Set(0)
	ACLBootstrapFailures.WithLabelValues("c", "ns").Add(0)
	ScaleDownInProgress.WithLabelValues("c", "ns").Set(0)
	NomadVersionInfo.WithLabelValues("c", "ns", "2.0.0").Set(1)

	families, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	found := map[string]bool{}
	for _, mf := range families {
		found[mf.GetName()] = true
	}

	expected := []string{
		"nomad_operator_phase_duration_seconds",
		"nomad_operator_nomad_api_requests_total",
		"nomad_operator_cert_expiry_timestamp_seconds",
		"nomad_operator_license_expiry_timestamp_seconds",
		"nomad_operator_acl_bootstrap_failures_total",
		"nomad_operator_scale_down_in_progress",
		"nomad_operator_nomad_version_info",
	}
	for _, name := range expected {
		if !found[name] {
			t.Errorf("metric %q not registered on the controller-runtime registry", name)
		}
	}

	// Double-registration must panic per MustRegister semantics — proves
	// init() already registered the handles (not just lazily gatherable).
	defer func() {
		if recover() == nil {
			t.Error("re-registering PhaseDuration should panic (AlreadyRegisteredError)")
		}
	}()
	ctrlmetrics.Registry.MustRegister(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "nomad_operator_phase_duration_seconds",
		Help: "Duration of each reconciliation phase in seconds, per NomadCluster.",
	}, []string{"cluster", "namespace", "phase"}))
}
