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

package phases

import (
	"context"
	"strings"
	"testing"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// TestPrometheusRuleContent covers neo-ru9: the shipped PrometheusRule
// carries the operator-gauge-backed certificate alerts alongside the
// Nomad-metric alerts, scoped to the owning cluster's labels — a
// regression here silently strips users of expiry alerting.
func TestPrometheusRuleContent(t *testing.T) {
	_ = monitoringv1.AddToScheme(scheme.Scheme)

	cluster := newTestCluster("mon-ns", "mon")
	cluster.Spec.Monitoring.PrometheusRulesEnabled = true

	phase := &MonitoringPhase{PhaseContext: &PhaseContext{
		Client: fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(),
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}}
	if result := phase.ensurePrometheusRule(context.Background(), cluster); result.Error != nil {
		t.Fatalf("ensurePrometheusRule() error = %v", result.Error)
	}

	rule := &monitoringv1.PrometheusRule{}
	if err := phase.Client.Get(context.Background(),
		types.NamespacedName{Name: "mon", Namespace: "mon-ns"}, rule); err != nil {
		t.Fatalf("PrometheusRule not created: %v", err)
	}

	byName := map[string]monitoringv1.Rule{}
	for _, g := range rule.Spec.Groups {
		for _, r := range g.Rules {
			byName[r.Alert] = r
		}
	}

	want := map[string]string{ // alert -> severity
		"NomadEvalsBlocked":           "warning",
		"NomadPlanQueueBacklog":       "warning",
		"NomadRaftCommitSlow":         "warning",
		"NomadCACertExpiringSoon":     "warning",
		"NomadCACertExpired":          "critical",
		"NomadServerCertExpiringSoon": "critical",
		"NomadLicenseExpiringSoon":    "warning",
		"NomadLicenseExpired":         "critical",
	}
	for alert, severity := range want {
		r, ok := byName[alert]
		if !ok {
			t.Errorf("alert %s missing from PrometheusRule", alert)
			continue
		}
		if r.Labels["severity"] != severity {
			t.Errorf("%s severity = %q, want %q", alert, r.Labels["severity"], severity)
		}
	}

	// The cert alerts must be scoped to THIS cluster's gauge series.
	for _, alert := range []string{"NomadCACertExpiringSoon", "NomadCACertExpired", "NomadServerCertExpiringSoon"} {
		expr := byName[alert].Expr.StrVal
		if !strings.Contains(expr, `cluster="mon"`) || !strings.Contains(expr, `namespace="mon-ns"`) {
			t.Errorf("%s expr not scoped to the owning cluster: %s", alert, expr)
		}
		if !strings.Contains(expr, "nomad_operator_cert_expiry_timestamp_seconds") {
			t.Errorf("%s expr does not use the operator gauge: %s", alert, expr)
		}
	}
}
