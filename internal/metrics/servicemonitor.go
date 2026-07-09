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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
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

// scrapeTokenSecret is a service-account-token Secret the token
// controller keeps populated for the operator's own ServiceAccount.
// The ServiceMonitor references it via authorization.credentials —
// file-path auth (bearerTokenFile) is prohibited by OpenShift
// user-workload monitoring, which rejected the previous shape outright.
const scrapeTokenSecret = "nomad-enterprise-operator-metrics-scrape-token"

func ensureScrapeTokenSecret(ctx context.Context, c client.Client, namespace, serviceAccount string) error {
	existing := &corev1.Secret{}
	err := c.Get(ctx, types.NamespacedName{Name: scrapeTokenSecret, Namespace: namespace}, existing)
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to check for scrape token Secret: %w", err)
		}
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      scrapeTokenSecret,
				Namespace: namespace,
				Annotations: map[string]string{
					corev1.ServiceAccountNameKey: serviceAccount,
				},
			},
			Type: corev1.SecretTypeServiceAccountToken,
		}
		if err := c.Create(ctx, secret); err != nil && !errors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create scrape token Secret: %w", err)
		}
		return nil
	}
	// Converge the SA annotation on drift; Secret type is immutable, so
	// that is the only field worth reconciling in place (neo-wkn).
	if existing.Annotations[corev1.ServiceAccountNameKey] == serviceAccount {
		return nil
	}
	if existing.Annotations == nil {
		existing.Annotations = map[string]string{}
	}
	existing.Annotations[corev1.ServiceAccountNameKey] = serviceAccount
	if err := c.Update(ctx, existing); err != nil {
		return fmt.Errorf("failed to update scrape token Secret: %w", err)
	}
	return nil
}

// EnsureOperatorServiceMonitor creates (or converges) a
// ServiceMonitor scraping the operator's own :8443/metrics endpoint
// (AC-F4.4), plus the token Secret its authorization references.
// Gated on Prometheus Operator CRD availability via the shared
// discovery helper — on clusters without the CRDs it is a clean no-op.
// The static equivalent ships at config/prometheus/operator-monitor.yaml,
// serving GitOps flows that prefer declarative installation.
func EnsureOperatorServiceMonitor(ctx context.Context, c client.Client, namespace, serviceAccount string) error {
	if !discovery.HasGVK(c.RESTMapper(), serviceMonitorGVK) {
		return nil
	}
	if err := ensureScrapeTokenSecret(ctx, c, namespace, serviceAccount); err != nil {
		return err
	}

	name := "nomad-enterprise-operator-metrics-monitor"

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
				Path:   "/metrics",
				Port:   "https",
				Scheme: &httpsScheme,

				// prometheus-operator/apis v0.88+ moved Endpoint.TLSConfig
				// inside the embedded HTTPConfigWithProxyAndTLSFiles ->
				// HTTPConfigWithTLSFiles struct. Reach it via the embed
				// path in struct-literal form.
				HTTPConfigWithProxyAndTLSFiles: monitoringv1.HTTPConfigWithProxyAndTLSFiles{
					HTTPConfigWithTLSFiles: monitoringv1.HTTPConfigWithTLSFiles{
						// Secret-backed authorization, never a file
						// path: OpenShift user-workload monitoring
						// rejects bearerTokenFile. The scraping
						// identity is the operator's own SA, which the
						// bundled metrics-reader binding authorizes
						// through kube-rbac-proxy.
						HTTPConfigWithoutTLS: monitoringv1.HTTPConfigWithoutTLS{
							Authorization: &monitoringv1.SafeAuthorization{
								Credentials: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: scrapeTokenSecret},
									Key:                  "token",
								},
							},
						},
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

	existing := &monitoringv1.ServiceMonitor{}
	err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, existing)
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to check for operator ServiceMonitor: %w", err)
		}
		if err := c.Create(ctx, sm); err != nil && !errors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create operator ServiceMonitor: %w", err)
		}
		return nil
	}

	// Converge on drift — a create-only ensure left the rc.3-era
	// bearerTokenFile shape in place across operator upgrades, keeping
	// the UWM rejection alert firing until deleted by hand (neo-wkn).
	// Labels merge additively; selector-relevant keys must win, foreign
	// labels survive.
	labelDrift := false
	for k, v := range labels {
		if existing.Labels[k] != v {
			labelDrift = true
			break
		}
	}
	if !labelDrift && equality.Semantic.DeepEqual(existing.Spec, sm.Spec) {
		return nil
	}
	if existing.Labels == nil {
		existing.Labels = map[string]string{}
	}
	for k, v := range labels {
		existing.Labels[k] = v
	}
	existing.Spec = sm.Spec
	if err := c.Update(ctx, existing); err != nil {
		return fmt.Errorf("failed to update operator ServiceMonitor: %w", err)
	}
	return nil
}
