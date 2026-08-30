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
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// The metrics marker must sit on the headless service ONLY: it is what
// the ServiceMonitor selects, and all three services otherwise carry
// identical labels — marking more than one scrapes each pod once per
// matching service (neo-q1d).
func TestMetricsMarkerOnHeadlessServiceOnly(t *testing.T) {
	cluster := newTestCluster("svc-ns", "svc")
	phase := &ServicesPhase{PhaseContext: &PhaseContext{
		Client: fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(),
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}}
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}

	for name, wantMarker := range map[string]bool{
		"svc-headless": true,
		"svc-internal": false,
		"svc-external": false,
	} {
		svc := &corev1.Service{}
		if err := phase.Client.Get(context.Background(),
			types.NamespacedName{Name: name, Namespace: "svc-ns"}, svc); err != nil {
			t.Fatalf("service %s missing: %v", name, err)
		}
		if got := svc.Labels["nomad.hashicorp.com/metrics"] == "true"; got != wantMarker {
			t.Errorf("%s metrics marker = %v, want %v", name, got, wantMarker)
		}
	}
}

// A removed CR field must clear the corresponding Service field: a
// stale spec.loadBalancerIP makes MetalLB reject the allocation when an
// address annotation is also present (neo-8t2). CR annotations prune
// via applied-key bookkeeping; annotations other controllers own
// survive.
func TestExternalServiceReconcilesRemovedFields(t *testing.T) {
	ctx := context.Background()
	cluster := newTestCluster("svc-ns", "svc")
	cluster.Spec.Services.External.Type = corev1.ServiceTypeLoadBalancer
	cluster.Spec.Services.External.LoadBalancerIP = "172.16.101.99"
	cluster.Spec.Services.External.Annotations = map[string]string{
		"metallb.io/loadBalancerIPs": "172.16.101.99",
	}
	phase := &ServicesPhase{PhaseContext: &PhaseContext{
		Client: fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(),
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}}
	if result := phase.Execute(ctx, cluster); result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}

	key := types.NamespacedName{Name: "svc-external", Namespace: "svc-ns"}
	svc := &corev1.Service{}
	if err := phase.Client.Get(ctx, key, svc); err != nil {
		t.Fatalf("external service missing: %v", err)
	}
	if svc.Spec.LoadBalancerIP != "172.16.101.99" {
		t.Fatalf("loadBalancerIP = %q, want set", svc.Spec.LoadBalancerIP)
	}
	if svc.Annotations["nomad.hashicorp.com/applied-annotations"] != "metallb.io/loadBalancerIPs" {
		t.Fatalf("applied-annotations record = %q", svc.Annotations["nomad.hashicorp.com/applied-annotations"])
	}

	// A controller-owned annotation appears out of band.
	svc.Annotations["metallb.io/ip-allocated-from-pool"] = "lab-pool"
	if err := phase.Client.Update(ctx, svc); err != nil {
		t.Fatalf("simulating foreign annotation: %v", err)
	}

	cluster.Spec.Services.External.LoadBalancerIP = ""
	cluster.Spec.Services.External.Annotations = nil
	if result := phase.Execute(ctx, cluster); result.Error != nil {
		t.Fatalf("Execute() after removal error = %v", result.Error)
	}
	if err := phase.Client.Get(ctx, key, svc); err != nil {
		t.Fatalf("external service missing after removal: %v", err)
	}
	if svc.Spec.LoadBalancerIP != "" {
		t.Errorf("loadBalancerIP = %q, want cleared", svc.Spec.LoadBalancerIP)
	}
	if _, present := svc.Annotations["metallb.io/loadBalancerIPs"]; present {
		t.Error("removed CR annotation was not pruned")
	}
	if svc.Annotations["metallb.io/ip-allocated-from-pool"] != "lab-pool" {
		t.Error("foreign annotation did not survive reconcile")
	}
	if _, present := svc.Annotations["nomad.hashicorp.com/applied-annotations"]; present {
		t.Error("applied-annotations record not removed when CR annotations cleared")
	}

	// Steady state must not churn writes.
	before := svc.ResourceVersion
	if result := phase.Execute(ctx, cluster); result.Error != nil {
		t.Fatalf("steady-state Execute() error = %v", result.Error)
	}
	if err := phase.Client.Get(ctx, key, svc); err != nil {
		t.Fatalf("external service missing after steady state: %v", err)
	}
	if svc.ResourceVersion != before {
		t.Errorf("steady-state reconcile wrote the Service (rv %s -> %s)", before, svc.ResourceVersion)
	}

	cluster.Spec.Services.External.Type = corev1.ServiceTypeNodePort
	if result := phase.Execute(ctx, cluster); result.Error != nil {
		t.Fatalf("Execute() after type change error = %v", result.Error)
	}
	if err := phase.Client.Get(ctx, key, svc); err != nil {
		t.Fatalf("external service missing after type change: %v", err)
	}
	if svc.Spec.Type != corev1.ServiceTypeNodePort {
		t.Errorf("type = %q, want NodePort", svc.Spec.Type)
	}
}
