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
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
)

func testAutoscaler(name string, mutate func(*nomadv1alpha1.NomadAutoscaler)) *nomadv1alpha1.NomadAutoscaler {
	a := &nomadv1alpha1.NomadAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns1"},
		// Mirrors an apiserver-defaulted object: the controller no longer
		// re-defaults replicas, namespaces, or logLevel in Go.
		Spec: nomadv1alpha1.NomadAutoscalerSpec{
			ClusterRef: nomadv1alpha1.ClusterReference{Name: "nomad"},
			Replicas:   1,
			Namespaces: []string{"default"},
			LogLevel:   "INFO",
		},
	}
	if mutate != nil {
		mutate(a)
	}
	return a
}

func TestBuildAutoscalerPolicyRules(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*nomadv1alpha1.NomadAutoscaler)
		want       []string
		wantAbsent []string
		wantOneOf  string // substring that must appear exactly once
	}{
		{
			// operator read is unconditional: the enterprise agent's
			// startup license check needs it even with DAS disabled.
			name:       "single namespace, no HA, no DAS",
			want:       []string{`namespace "default"`, `policy = "scale"`, `node {`, "operator {"},
			wantAbsent: []string{"variables", "submit-recommendation"},
		},
		{
			name: "DAS adds the recommendations capability",
			mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
				a.Spec.DynamicApplicationSizing.Enabled = true
			},
			want: []string{`capabilities = ["submit-recommendation"]`, "operator {"},
		},
		{
			name: "HA with default namespace granted merges the lock into that block",
			mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
				a.Spec.Replicas = 2
			},
			want:      []string{"nomad-autoscaler/ns1/as/lock", `capabilities = ["write", "read", "list"]`},
			wantOneOf: `namespace "default"`,
		},
		{
			// The exact default block must NOT carry scale here: only
			// payments was granted, and nothing else covers default.
			name: "HA with a non-default namespace emits a separate bare lock block",
			mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
				a.Spec.Replicas = 3
				a.Spec.Namespaces = []string{"payments"}
			},
			want:      []string{`namespace "payments"`, `namespace "default"`, "nomad-autoscaler/ns1/as/lock"},
			wantOneOf: `policy = "scale"`,
		},
		{
			// Nomad resolves exact blocks over globs without merging, so
			// the exact lock block must repeat the wildcard's scale grant
			// — a bare variables block would 403 scaling in "default".
			name: "wildcard namespace: the exact lock block carries the full scale grant",
			mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
				a.Spec.Replicas = 2
				a.Spec.Namespaces = []string{"*"}
			},
			want: []string{`namespace "*"`, "nomad-autoscaler/ns1/as/lock",
				"namespace \"default\" {\n  policy = \"scale\"\n  variables {"},
		},
		{
			name: "wildcard + DAS: the exact lock block carries the recommendations capability too",
			mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
				a.Spec.Replicas = 2
				a.Spec.Namespaces = []string{"*"}
				a.Spec.DynamicApplicationSizing.Enabled = true
			},
			want: []string{"namespace \"default\" {\n  policy = \"scale\"\n  capabilities = [\"submit-recommendation\"]\n  variables {"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := buildAutoscalerPolicyRules(testAutoscaler("as", tc.mutate))
			for _, want := range tc.want {
				if !strings.Contains(rules, want) {
					t.Errorf("rules missing %q:\n%s", want, rules)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(rules, absent) {
					t.Errorf("rules must not contain %q:\n%s", absent, rules)
				}
			}
			if tc.wantOneOf != "" {
				if got := strings.Count(rules, tc.wantOneOf); got != 1 {
					t.Errorf("rules must contain %q exactly once, got %d:\n%s", tc.wantOneOf, got, rules)
				}
			}
		})
	}
}

func TestGenerateAutoscalerConfig(t *testing.T) {
	const addr = "https://nomad-internal.ns1.svc:4646"

	cases := []struct {
		name       string
		mutate     func(*nomadv1alpha1.NomadAutoscaler)
		want       []string
		wantAbsent []string
	}{
		{
			name:       "single namespace watches that namespace",
			want:       []string{addr, `namespace = "default"`, `log_level    = "INFO"`, "enable_debug = false", "prometheus_metrics = true"},
			wantAbsent: []string{"high_availability"},
		},
		{
			name: "multiple namespaces watch the wildcard; ACL enforces the boundary",
			mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
				a.Spec.Namespaces = []string{"a", "b"}
			},
			want: []string{`namespace = "*"`},
		},
		{
			name: "HA renders the per-instance lock path",
			mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
				a.Spec.Replicas = 2
			},
			want: []string{"high_availability", `lock_namespace = "default"`, `lock_path      = "nomad-autoscaler/ns1/as/lock"`},
		},
		{
			name: "debug and log level pass through",
			mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
				a.Spec.EnableDebug = true
				a.Spec.LogLevel = "DEBUG"
			},
			want: []string{"enable_debug = true", `log_level    = "DEBUG"`},
		},
		{
			name: "DAS renders the prometheus APM block",
			mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
				a.Spec.DynamicApplicationSizing.Enabled = true
				a.Spec.DynamicApplicationSizing.PrometheusURL = "http://das-prometheus:9090"
			},
			want: []string{`apm "prometheus"`, `address = "http://das-prometheus:9090"`},
		},
		{
			name:       "no prometheus APM block without DAS",
			wantAbsent: []string{`apm "prometheus"`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := generateAutoscalerConfig(testAutoscaler("as", tc.mutate), addr)
			for _, want := range tc.want {
				if !strings.Contains(config, want) {
					t.Errorf("config missing %q:\n%s", want, config)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(config, absent) {
					t.Errorf("config must not contain %q:\n%s", absent, config)
				}
			}
		})
	}
}
