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
