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

	"k8s.io/utils/ptr"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func init() {
	_ = monitoringv1.AddToScheme(scheme.Scheme)
}

// newMapperPhaseContext builds a PhaseContext whose client's RESTMapper
// knows exactly the given GVKs — simulating clusters with and without
// optional CRDs installed (B4 / AC-2.2.4 / AC-B4.2).
func newMapperPhaseContext(mapper meta.RESTMapper) *PhaseContext {
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithRESTMapper(mapper).
		Build()
	return &PhaseContext{
		Client: fakeClient,
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}
}

func TestMonitoringDiscoveryGated(t *testing.T) {
	cluster := newTestCluster("test-ns", "test-cluster")
	cluster.Spec.Monitoring.Enabled = ptr.To(true)
	// openshift.enabled deliberately false: monitoring must work without it.

	t.Run("Prometheus CRDs present creates ServiceMonitor", func(t *testing.T) {
		mapper := meta.NewDefaultRESTMapper(nil)
		mapper.Add(serviceMonitorGVK, meta.RESTScopeNamespace)

		p := NewMonitoringPhase(newMapperPhaseContext(mapper))
		result := p.Execute(context.Background(), cluster)
		if result.Error != nil {
			t.Fatalf("Execute() error = %v", result.Error)
		}

		sm := &monitoringv1.ServiceMonitor{}
		if err := p.Client.Get(context.Background(), types.NamespacedName{
			Name: "test-cluster", Namespace: "test-ns",
		}, sm); err != nil {
			t.Errorf("expected ServiceMonitor to be created: %v", err)
		}
	})

	t.Run("Prometheus CRDs absent skips cleanly", func(t *testing.T) {
		mapper := meta.NewDefaultRESTMapper(nil) // knows nothing

		p := NewMonitoringPhase(newMapperPhaseContext(mapper))
		result := p.Execute(context.Background(), cluster)
		if result.Error != nil {
			t.Fatalf("Execute() should skip without error when CRDs absent, got %v", result.Error)
		}

		smList := &monitoringv1.ServiceMonitorList{}
		if err := p.Client.List(context.Background(), smList); err == nil && len(smList.Items) > 0 {
			t.Errorf("no ServiceMonitor should be created when CRDs absent, found %d", len(smList.Items))
		}
	})

	t.Run("monitoring disabled skips regardless of CRDs", func(t *testing.T) {
		mapper := meta.NewDefaultRESTMapper(nil)
		mapper.Add(serviceMonitorGVK, meta.RESTScopeNamespace)

		disabled := newTestCluster("test-ns", "test-cluster")
		disabled.Spec.Monitoring.Enabled = ptr.To(false)

		p := NewMonitoringPhase(newMapperPhaseContext(mapper))
		if result := p.Execute(context.Background(), disabled); result.Error != nil {
			t.Fatalf("Execute() error = %v", result.Error)
		}

		smList := &monitoringv1.ServiceMonitorList{}
		if err := p.Client.List(context.Background(), smList); err == nil && len(smList.Items) > 0 {
			t.Errorf("no ServiceMonitor should be created when monitoring disabled, found %d", len(smList.Items))
		}
	})
}

func TestRouteDiscoveryGated(t *testing.T) {
	cluster := newTestCluster("test-ns", "test-cluster")
	cluster.Spec.OpenShift.Enabled = true
	cluster.Spec.OpenShift.Route.Enabled = true

	t.Run("Route CRDs absent emits RouteCRDMissing warning and skips", func(t *testing.T) {
		mapper := meta.NewDefaultRESTMapper(nil) // no Route GVK

		ctx := newMapperPhaseContext(mapper)
		recorder := record.NewFakeRecorder(5)
		ctx.Recorder = recorder

		p := NewRoutePhase(ctx)
		result := p.Execute(context.Background(), cluster)
		if result.Error != nil {
			t.Fatalf("Execute() should skip without error when Route CRDs absent, got %v", result.Error)
		}

		select {
		case ev := <-recorder.Events:
			if !strings.Contains(ev, "RouteCRDMissing") {
				t.Errorf("expected RouteCRDMissing event, got %q", ev)
			}
		default:
			t.Error("expected a Warning Event to be emitted")
		}
	})
}
