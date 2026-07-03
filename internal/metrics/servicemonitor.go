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
	"fmt"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/nomad-enterprise-operator/internal/discovery"
)

var serviceMonitorGVK = schema.GroupVersionKind{
	Group:   "monitoring.coreos.com",
	Version: "v1",
	Kind:    "ServiceMonitor",
}

// EnsureOperatorServiceMonitor creates (or leaves in place) a
// ServiceMonitor scraping the operator's own :8443/metrics endpoint
// (AC-F4.4). Gated on Prometheus Operator CRD availability via the shared
// discovery helper — on clusters without the CRDs it is a clean no-op.
// The static equivalent ships at config/prometheus/operator-monitor.yaml,
// serving GitOps flows that prefer declarative installation.
func EnsureOperatorServiceMonitor(ctx context.Context, c client.Client, namespace string) error {
	if !discovery.HasGVK(c.RESTMapper(), serviceMonitorGVK) {
		return nil
	}

	name := "nomad-enterprise-operator-metrics-monitor"
	existing := &monitoringv1.ServiceMonitor{}
	err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, existing)
	if err == nil {
		return nil
	}
	if !errors.IsNotFound(err) {
		return fmt.Errorf("failed to check for operator ServiceMonitor: %w", err)
	}

	httpsScheme := monitoringv1.Scheme("https")
	// One label set serves as both the ServiceMonitor's own labels and
	// its service selector — the two must agree.
	labels := map[string]string{
		"control-plane":          "controller-manager",
		"app.kubernetes.io/name": "nomad-enterprise-operator",
	}
	sm := &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Endpoints: []monitoringv1.Endpoint{{
				Path:            "/metrics",
				Port:            "https",
				Scheme:          &httpsScheme,
				BearerTokenFile: "/var/run/secrets/kubernetes.io/serviceaccount/token",
				// prometheus-operator/apis v0.88+ moved Endpoint.TLSConfig
				// inside the embedded HTTPConfigWithProxyAndTLSFiles ->
				// HTTPConfigWithTLSFiles struct. Reach it via the embed
				// path in struct-literal form.
				HTTPConfigWithProxyAndTLSFiles: monitoringv1.HTTPConfigWithProxyAndTLSFiles{
					HTTPConfigWithTLSFiles: monitoringv1.HTTPConfigWithTLSFiles{
						TLSConfig: &monitoringv1.TLSConfig{
							SafeTLSConfig: monitoringv1.SafeTLSConfig{
								// The metrics endpoint serves a
								// controller-runtime self-signed cert;
								// scrape verification is skipped, matching
								// config/prometheus/monitor.yaml.
								InsecureSkipVerify: ptr.To(true),
							},
						},
					},
				},
			}},
			Selector: metav1.LabelSelector{
				MatchLabels: labels,
			},
		},
	}

	if err := c.Create(ctx, sm); err != nil && !errors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create operator ServiceMonitor: %w", err)
	}
	return nil
}
