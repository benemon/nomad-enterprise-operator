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
	"context"
	"testing"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func init() {
	_ = monitoringv1.AddToScheme(scheme.Scheme)
}

func fakeClientWithMapper(mapper meta.RESTMapper) client.Client {
	return fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithRESTMapper(mapper).
		Build()
}

func TestEnsureOperatorServiceMonitor(t *testing.T) {
	const ns = "nomad-enterprise-operator-system"
	ctx := context.Background()

	t.Run("creates ServiceMonitor when CRDs present", func(t *testing.T) {
		mapper := meta.NewDefaultRESTMapper(nil)
		mapper.Add(serviceMonitorGVK, meta.RESTScopeNamespace)
		c := fakeClientWithMapper(mapper)

		if err := EnsureOperatorServiceMonitor(ctx, c, ns); err != nil {
			t.Fatalf("EnsureOperatorServiceMonitor() error = %v", err)
		}

		sm := &monitoringv1.ServiceMonitor{}
		if err := c.Get(ctx, types.NamespacedName{
			Name: "nomad-enterprise-operator-metrics-monitor", Namespace: ns,
		}, sm); err != nil {
			t.Fatalf("expected ServiceMonitor created: %v", err)
		}
		if sm.Spec.Endpoints[0].Path != "/metrics" || sm.Spec.Endpoints[0].Port != "https" {
			t.Errorf("unexpected endpoint: %+v", sm.Spec.Endpoints[0])
		}
	})

	t.Run("no-op when CRDs absent", func(t *testing.T) {
		c := fakeClientWithMapper(meta.NewDefaultRESTMapper(nil))

		if err := EnsureOperatorServiceMonitor(ctx, c, ns); err != nil {
			t.Fatalf("should be a clean no-op without CRDs, got %v", err)
		}

		smList := &monitoringv1.ServiceMonitorList{}
		if err := c.List(ctx, smList); err == nil && len(smList.Items) > 0 {
			t.Errorf("no ServiceMonitor should exist, found %d", len(smList.Items))
		}
	})

	t.Run("idempotent when ServiceMonitor already exists", func(t *testing.T) {
		mapper := meta.NewDefaultRESTMapper(nil)
		mapper.Add(serviceMonitorGVK, meta.RESTScopeNamespace)
		c := fakeClientWithMapper(mapper)

		if err := EnsureOperatorServiceMonitor(ctx, c, ns); err != nil {
			t.Fatalf("first ensure: %v", err)
		}
		if err := EnsureOperatorServiceMonitor(ctx, c, ns); err != nil {
			t.Fatalf("second ensure should be idempotent: %v", err)
		}
	})
}
