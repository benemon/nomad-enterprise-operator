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

package controller

import (
	"context"
	"strings"
	"testing"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
)

func init() {
	_ = nomadv1alpha1.AddToScheme(scheme.Scheme)
	_ = monitoringv1.AddToScheme(scheme.Scheme)
}

// monitoringMapper returns a RESTMapper that knows the Prometheus
// Operator GVKs — simulating a cluster with the CRDs installed. The
// empty variant simulates one without (same convention as the phases
// monitoring discovery tests).
func monitoringMapper(withCRDs bool) meta.RESTMapper {
	mapper := meta.NewDefaultRESTMapper(nil)
	if withCRDs {
		mapper.Add(schema.GroupVersionKind{Group: "monitoring.coreos.com", Version: "v1", Kind: "ServiceMonitor"}, meta.RESTScopeNamespace)
		mapper.Add(schema.GroupVersionKind{Group: "monitoring.coreos.com", Version: "v1", Kind: "PrometheusRule"}, meta.RESTScopeNamespace)
	}
	return mapper
}

func newMonitoringReconciler(withCRDs bool, objs ...*nomadv1alpha1.NomadAutoscaler) *NomadAutoscalerReconciler {
	builder := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithRESTMapper(monitoringMapper(withCRDs))
	for _, o := range objs {
		builder = builder.WithObjects(o)
	}
	return &NomadAutoscalerReconciler{Client: builder.Build(), Scheme: scheme.Scheme}
}

// TestAutoscalerPrometheusRuleLifecycle covers neo-2um.9: the rule is
// opt-in behind monitoring.prometheusRulesEnabled, created only when
// the Prometheus Operator CRDs exist, and deleted on toggle-off.
func TestAutoscalerPrometheusRuleLifecycle(t *testing.T) {
	ctx := context.Background()
	ruleKey := types.NamespacedName{Name: "as-autoscaler-rules", Namespace: "ns1"}

	newAS := func(rulesEnabled bool) *nomadv1alpha1.NomadAutoscaler {
		a := testAutoscaler(nil)
		a.Spec.Monitoring.PrometheusRulesEnabled = rulesEnabled
		return a
	}

	t.Run("enabled creates the rule with owner reference", func(t *testing.T) {
		a := newAS(true)
		r := newMonitoringReconciler(true, a)
		if err := r.reconcileMonitoring(ctx, a); err != nil {
			t.Fatalf("reconcileMonitoring() error = %v", err)
		}
		rule := &monitoringv1.PrometheusRule{}
		if err := r.Get(ctx, ruleKey, rule); err != nil {
			t.Fatalf("PrometheusRule not created: %v", err)
		}
		if len(rule.OwnerReferences) != 1 || rule.OwnerReferences[0].Kind != "NomadAutoscaler" {
			t.Errorf("owner reference = %+v, want the NomadAutoscaler", rule.OwnerReferences)
		}
	})

	t.Run("default (disabled) creates no rule and deletes a leftover", func(t *testing.T) {
		a := newAS(true)
		r := newMonitoringReconciler(true, a)
		if err := r.reconcileMonitoring(ctx, a); err != nil {
			t.Fatal(err)
		}
		// Toggle off: the rule must go.
		a.Spec.Monitoring.PrometheusRulesEnabled = false
		if err := r.reconcileMonitoring(ctx, a); err != nil {
			t.Fatalf("reconcileMonitoring() after toggle-off error = %v", err)
		}
		rule := &monitoringv1.PrometheusRule{}
		if err := r.Get(ctx, ruleKey, rule); !errors.IsNotFound(err) {
			t.Errorf("rule still present after toggle-off (err=%v)", err)
		}
		// ServiceMonitor is unaffected by the toggle.
		sm := &monitoringv1.ServiceMonitor{}
		if err := r.Get(ctx, types.NamespacedName{Name: "as-autoscaler-metrics", Namespace: "ns1"}, sm); err != nil {
			t.Errorf("ServiceMonitor must survive the rules toggle: %v", err)
		}
	})

	t.Run("no Prometheus Operator CRDs: no rule, no error", func(t *testing.T) {
		a := newAS(true)
		r := newMonitoringReconciler(false, a)
		if err := r.reconcileMonitoring(ctx, a); err != nil {
			t.Fatalf("reconcileMonitoring() must skip cleanly without the CRDs: %v", err)
		}
		if err := r.Get(ctx, ruleKey, &monitoringv1.PrometheusRule{}); !errors.IsNotFound(err) {
			t.Errorf("rule must not be created without the CRDs (err=%v)", err)
		}
	})
}

// TestAutoscalerPrometheusRuleContent pins the alert set and the
// per-CR scoping: every expression is bounded to this instance's
// metrics Service job label.
func TestAutoscalerPrometheusRuleContent(t *testing.T) {
	a := testAutoscaler(nil)
	spec := autoscalerPrometheusRuleSpec(a)

	if len(spec.Groups) != 1 || spec.Groups[0].Name != "nomad-autoscaler.rules" {
		t.Fatalf("groups = %+v, want one nomad-autoscaler.rules group", spec.Groups)
	}
	rules := spec.Groups[0].Rules

	want := map[string]string{
		"NomadAutoscalerScalingErrors":            "warning",
		"NomadAutoscalerPolicyEvaluationsStalled": "warning",
		"NomadAutoscalerAgentDown":                "critical",
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d", len(rules), len(want))
	}
	for _, rule := range rules {
		severity, ok := want[rule.Alert]
		if !ok {
			t.Errorf("unexpected alert %q", rule.Alert)
			continue
		}
		if rule.Labels["severity"] != severity {
			t.Errorf("%s severity = %q, want %q", rule.Alert, rule.Labels["severity"], severity)
		}
		if !strings.Contains(rule.Expr.String(), `job="as-autoscaler-metrics"`) {
			t.Errorf("%s expr not scoped to the instance's job label: %s", rule.Alert, rule.Expr.String())
		}
		if rule.Annotations["summary"] == "" || rule.Annotations["description"] == "" {
			t.Errorf("%s missing summary/description annotations", rule.Alert)
		}
	}

	// The stall alert must use `unless` so it also fires when the
	// evaluation counter is entirely absent (a fresh, wedged agent).
	for _, rule := range rules {
		if rule.Alert == "NomadAutoscalerPolicyEvaluationsStalled" {
			if !strings.Contains(rule.Expr.String(), "unless") {
				t.Errorf("stall expr must use `unless` for the absent-counter case: %s", rule.Expr.String())
			}
			if !strings.Contains(rule.Expr.String(), "policy_total_num") {
				t.Errorf("stall expr must reference the policy-count gauge: %s", rule.Expr.String())
			}
		}
	}
}
