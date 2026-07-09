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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

		if err := EnsureOperatorServiceMonitor(ctx, c, ns, "controller-manager-sa"); err != nil {
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

		if err := EnsureOperatorServiceMonitor(ctx, c, ns, "controller-manager-sa"); err != nil {
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

		if err := EnsureOperatorServiceMonitor(ctx, c, ns, "controller-manager-sa"); err != nil {
			t.Fatalf("first ensure: %v", err)
		}
		if err := EnsureOperatorServiceMonitor(ctx, c, ns, "controller-manager-sa"); err != nil {
			t.Fatalf("second ensure should be idempotent: %v", err)
		}
	})

	t.Run("unchanged ServiceMonitor is not rewritten", func(t *testing.T) {
		mapper := meta.NewDefaultRESTMapper(nil)
		mapper.Add(serviceMonitorGVK, meta.RESTScopeNamespace)
		c := fakeClientWithMapper(mapper)

		if err := EnsureOperatorServiceMonitor(ctx, c, ns, "controller-manager-sa"); err != nil {
			t.Fatalf("first ensure: %v", err)
		}
		sm := &monitoringv1.ServiceMonitor{}
		key := types.NamespacedName{Name: "nomad-enterprise-operator-metrics-monitor", Namespace: ns}
		if err := c.Get(ctx, key, sm); err != nil {
			t.Fatal(err)
		}
		rv := sm.ResourceVersion

		if err := EnsureOperatorServiceMonitor(ctx, c, ns, "controller-manager-sa"); err != nil {
			t.Fatalf("second ensure: %v", err)
		}
		if err := c.Get(ctx, key, sm); err != nil {
			t.Fatal(err)
		}
		if sm.ResourceVersion != rv {
			t.Errorf("ServiceMonitor was rewritten without drift: resourceVersion %s -> %s", rv, sm.ResourceVersion)
		}
	})

	// Guards the neo-wkn upgrade bug: a create-only ensure left the
	// rc.3-era bearerTokenFile shape in place across operator upgrades.
	t.Run("converges existing ServiceMonitor with old bearerTokenFile shape", func(t *testing.T) {
		mapper := meta.NewDefaultRESTMapper(nil)
		mapper.Add(serviceMonitorGVK, meta.RESTScopeNamespace)
		c := fakeClientWithMapper(mapper)

		old := &monitoringv1.ServiceMonitor{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nomad-enterprise-operator-metrics-monitor",
				Namespace: ns,
				Labels:    map[string]string{"foreign-label": "keep-me"},
			},
			Spec: monitoringv1.ServiceMonitorSpec{
				Endpoints: []monitoringv1.Endpoint{{
					Path:            "/metrics",
					Port:            "https",
					BearerTokenFile: "/var/run/secrets/kubernetes.io/serviceaccount/token", //nolint:staticcheck // recreating the pre-fix shape is the point
				}},
			},
		}
		if err := c.Create(ctx, old); err != nil {
			t.Fatal(err)
		}

		if err := EnsureOperatorServiceMonitor(ctx, c, ns, "controller-manager-sa"); err != nil {
			t.Fatalf("ensure over old shape: %v", err)
		}

		sm := &monitoringv1.ServiceMonitor{}
		if err := c.Get(ctx, types.NamespacedName{
			Name: "nomad-enterprise-operator-metrics-monitor", Namespace: ns,
		}, sm); err != nil {
			t.Fatal(err)
		}
		ep := sm.Spec.Endpoints[0]
		if ep.BearerTokenFile != "" { //nolint:staticcheck // asserting the deprecated field was cleared
			t.Error("bearerTokenFile survived convergence")
		}
		if ep.Authorization == nil || ep.Authorization.Credentials == nil ||
			ep.Authorization.Credentials.Name != scrapeTokenSecret {
			t.Error("converged endpoint must carry Secret-backed authorization")
		}
		if sm.Labels["foreign-label"] != "keep-me" {
			t.Error("foreign label stripped: label merge must be additive")
		}
		if sm.Labels["app.kubernetes.io/name"] != "nomad-enterprise-operator" {
			t.Error("selector-relevant label not converged")
		}
	})

	t.Run("converges scrape token Secret SA annotation on drift", func(t *testing.T) {
		mapper := meta.NewDefaultRESTMapper(nil)
		mapper.Add(serviceMonitorGVK, meta.RESTScopeNamespace)
		c := fakeClientWithMapper(mapper)

		stale := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      scrapeTokenSecret,
				Namespace: ns,
				Annotations: map[string]string{
					corev1.ServiceAccountNameKey: "old-sa",
				},
			},
			Type: corev1.SecretTypeServiceAccountToken,
		}
		if err := c.Create(ctx, stale); err != nil {
			t.Fatal(err)
		}

		if err := EnsureOperatorServiceMonitor(ctx, c, ns, "controller-manager-sa"); err != nil {
			t.Fatalf("ensure over stale Secret: %v", err)
		}

		secret := &corev1.Secret{}
		if err := c.Get(ctx, types.NamespacedName{Name: scrapeTokenSecret, Namespace: ns}, secret); err != nil {
			t.Fatal(err)
		}
		if got := secret.Annotations[corev1.ServiceAccountNameKey]; got != "controller-manager-sa" {
			t.Errorf("SA annotation not converged: got %q", got)
		}
	})
}

// The emitted ServiceMonitor must never use file-path auth or TLS
// fields: OpenShift user-workload monitoring rejects the whole object
// ("it accesses file system via bearer token file"), silently killing
// operator self-metrics. Secret-backed shapes work everywhere.
func TestServiceMonitorHasNoFilePathAuth(t *testing.T) {
	ctx := context.Background()
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(serviceMonitorGVK, meta.RESTScopeNamespace)
	c := fakeClientWithMapper(mapper)
	if err := EnsureOperatorServiceMonitor(ctx, c, "sm-ns", "controller-manager-sa"); err != nil {
		t.Fatal(err)
	}
	sm := &monitoringv1.ServiceMonitor{}
	if err := c.Get(ctx, types.NamespacedName{
		Name: "nomad-enterprise-operator-metrics-monitor", Namespace: "sm-ns"}, sm); err != nil {
		t.Fatal(err)
	}
	for _, ep := range sm.Spec.Endpoints {
		if ep.BearerTokenFile != "" { //nolint:staticcheck // asserting the deprecated field stays empty is the point
			t.Fatal("bearerTokenFile is prohibited by OpenShift UWM")
		}
		if ep.Authorization == nil || ep.Authorization.Credentials == nil ||
			ep.Authorization.Credentials.Name == "" {
			t.Fatal("endpoint must carry Secret-backed authorization")
		}
		if ep.TLSConfig != nil && (ep.TLSConfig.CAFile != "" || ep.TLSConfig.CertFile != "" || ep.TLSConfig.KeyFile != "") {
			t.Fatal("file-path TLS fields are prohibited by OpenShift UWM")
		}
	}
	// The referenced token Secret must exist alongside.
	secret := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: scrapeTokenSecret, Namespace: "sm-ns"}, secret); err != nil {
		t.Fatalf("scrape token Secret must be ensured: %v", err)
	}
	if secret.Type != corev1.SecretTypeServiceAccountToken ||
		secret.Annotations[corev1.ServiceAccountNameKey] != "controller-manager-sa" {
		t.Fatalf("scrape token Secret must be a service-account-token for the operator SA, got %+v", secret)
	}
}
