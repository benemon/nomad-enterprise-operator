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
	"reflect"
	"strings"
	"testing"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// TestServiceMonitorContent covers neo-q1d: Nomad serves 4646 as TLS,
// so a scheme-less ServiceMonitor scrapes plain HTTP and silently
// loses every nomad_* series; dispatched jobs emit per-job series
// that must be dropped before they flood shared Prometheus.
func TestServiceMonitorContent(t *testing.T) {
	_ = monitoringv1.AddToScheme(scheme.Scheme)

	cluster := newTestCluster("mon-ns", "mon")
	phase := &MonitoringPhase{PhaseContext: &PhaseContext{
		Client: fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(),
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}}
	if result := phase.ensureServiceMonitor(context.Background(), cluster); result.Error != nil {
		t.Fatalf("ensureServiceMonitor() error = %v", result.Error)
	}

	sm := &monitoringv1.ServiceMonitor{}
	if err := phase.Client.Get(context.Background(),
		types.NamespacedName{Name: "mon", Namespace: "mon-ns"}, sm); err != nil {
		t.Fatalf("ServiceMonitor not created: %v", err)
	}

	// Must select the marked headless service — GetSelectorLabels is
	// the pod selector and matches no Service at all; matching all
	// services scrapes each pod once per service.
	wantSel := map[string]string{
		"app.kubernetes.io/instance":  "mon",
		"nomad.hashicorp.com/metrics": "true",
	}
	if !reflect.DeepEqual(sm.Spec.Selector.MatchLabels, wantSel) {
		t.Errorf("selector = %v, want %v", sm.Spec.Selector.MatchLabels, wantSel)
	}

	ep := sm.Spec.Endpoints[0]
	if ep.Scheme == nil || *ep.Scheme != "https" {
		t.Errorf("endpoint scheme = %v, want https", ep.Scheme)
	}
	if ep.TLSConfig == nil || ep.TLSConfig.InsecureSkipVerify == nil || !*ep.TLSConfig.InsecureSkipVerify {
		t.Error("endpoint must carry a tlsConfig with insecureSkipVerify")
	}
	if ep.Port != "http" || ep.Path != "/v1/metrics" {
		t.Errorf("endpoint target = %s %s, want http /v1/metrics", ep.Port, ep.Path)
	}

	var dropsDispatch bool
	for _, rc := range ep.MetricRelabelConfigs {
		if rc.Action == "drop" && len(rc.SourceLabels) == 1 && rc.SourceLabels[0] == "exported_job" &&
			strings.Contains(rc.Regex, "dispatch") {
			dropsDispatch = true
		}
	}
	if !dropsDispatch {
		t.Error("metricRelabelings must drop per-dispatched-job series on exported_job")
	}
}

// Pre-fix installs carry a scheme-less ServiceMonitor; ensure must
// converge it in place (neo-q1d) and must not rewrite an already
// converged object (no churn).
func TestServiceMonitorConverges(t *testing.T) {
	_ = monitoringv1.AddToScheme(scheme.Scheme)

	cluster := newTestCluster("mon-ns", "mon")
	stale := &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{Name: "mon", Namespace: "mon-ns"},
		Spec: monitoringv1.ServiceMonitorSpec{
			// Pre-fix shape: pod-selector labels that match no Service.
			Selector: metav1.LabelSelector{
				MatchLabels: GetSelectorLabels(newTestCluster("mon-ns", "mon")),
			},
			Endpoints: []monitoringv1.Endpoint{{
				Port:          "http",
				Path:          "/v1/metrics",
				Interval:      monitoringv1.Duration("30s"),
				ScrapeTimeout: monitoringv1.Duration("10s"),
				Params:        map[string][]string{"format": {"prometheus"}},
			}},
		},
	}
	phase := &MonitoringPhase{PhaseContext: &PhaseContext{
		Client: fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(stale).Build(),
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}}

	if result := phase.ensureServiceMonitor(context.Background(), cluster); result.Error != nil {
		t.Fatalf("ensureServiceMonitor() error = %v", result.Error)
	}
	sm := &monitoringv1.ServiceMonitor{}
	if err := phase.Client.Get(context.Background(),
		types.NamespacedName{Name: "mon", Namespace: "mon-ns"}, sm); err != nil {
		t.Fatalf("ServiceMonitor missing: %v", err)
	}
	ep := sm.Spec.Endpoints[0]
	if ep.Scheme == nil || *ep.Scheme != "https" || ep.TLSConfig == nil {
		t.Fatal("existing scheme-less ServiceMonitor was not converged to https+tlsConfig")
	}
	if sm.Spec.Selector.MatchLabels["nomad.hashicorp.com/metrics"] != "true" {
		t.Fatal("existing pod-selector-shaped ServiceMonitor was not converged to the service marker selector")
	}

	rv := sm.ResourceVersion
	if result := phase.ensureServiceMonitor(context.Background(), cluster); result.Error != nil {
		t.Fatalf("ensureServiceMonitor() second pass error = %v", result.Error)
	}
	if err := phase.Client.Get(context.Background(),
		types.NamespacedName{Name: "mon", Namespace: "mon-ns"}, sm); err != nil {
		t.Fatalf("ServiceMonitor missing after second pass: %v", err)
	}
	if sm.ResourceVersion != rv {
		t.Error("converged ServiceMonitor was rewritten on a no-op reconcile")
	}
}

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
