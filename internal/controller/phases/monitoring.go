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

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// MonitoringPhase creates ServiceMonitor and PrometheusRule for Prometheus monitoring.
type MonitoringPhase struct {
	*PhaseContext
}

// NewMonitoringPhase creates a new MonitoringPhase.
func NewMonitoringPhase(ctx *PhaseContext) *MonitoringPhase {
	return &MonitoringPhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *MonitoringPhase) Name() string {
	return "Monitoring"
}

// Execute creates or updates Prometheus monitoring resources.
func (p *MonitoringPhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	// Skip if OpenShift or monitoring is disabled
	if !cluster.Spec.OpenShift.Enabled || !cluster.Spec.OpenShift.Monitoring.Enabled {
		p.Log.V(1).Info("OpenShift monitoring disabled, skipping")
		return OK()
	}

	// Create ServiceMonitor
	if result := p.ensureServiceMonitor(ctx, cluster); result.Error != nil || result.Requeue {
		return result
	}

	// Create PrometheusRule if enabled (check new field first, then deprecated)
	prometheusRulesEnabled := cluster.Spec.OpenShift.Monitoring.PrometheusRulesEnabled ||
		cluster.Spec.OpenShift.Monitoring.PrometheusRule.Enabled
	if prometheusRulesEnabled {
		if result := p.ensurePrometheusRule(ctx, cluster); result.Error != nil || result.Requeue {
			return result
		}
	}

	return OK()
}

func (p *MonitoringPhase) ensureServiceMonitor(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	monitoring := cluster.Spec.OpenShift.Monitoring

	// Use flattened fields first, fall back to deprecated nested fields
	interval := monitoring.ScrapeInterval
	if interval == "" {
		interval = monitoring.ServiceMonitor.Interval
	}
	if interval == "" {
		interval = "30s"
	}

	scrapeTimeout := monitoring.ScrapeTimeout
	if scrapeTimeout == "" {
		scrapeTimeout = monitoring.ServiceMonitor.ScrapeTimeout
	}
	if scrapeTimeout == "" {
		scrapeTimeout = "10s"
	}

	// Build labels - prefer flattened field, fall back to deprecated
	labels := GetLabels(cluster)
	additionalLabels := monitoring.AdditionalLabels
	if len(additionalLabels) == 0 {
		additionalLabels = monitoring.ServiceMonitor.AdditionalLabels
	}
	for k, v := range additionalLabels {
		labels[k] = v
	}

	sm := &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
			Labels:    labels,
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector: metav1.LabelSelector{
				MatchLabels: GetSelectorLabels(cluster),
			},
			NamespaceSelector: monitoringv1.NamespaceSelector{
				MatchNames: []string{cluster.Namespace},
			},
			Endpoints: []monitoringv1.Endpoint{
				{
					Port:          "http",
					Path:          "/v1/metrics",
					Interval:      monitoringv1.Duration(interval),
					ScrapeTimeout: monitoringv1.Duration(scrapeTimeout),
					Params: map[string][]string{
						"format": {"prometheus"},
					},
				},
			},
		},
	}

	if err := controllerutil.SetControllerReference(cluster, sm, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on ServiceMonitor")
	}

	existing := &monitoringv1.ServiceMonitor{}
	err := p.Client.Get(ctx, types.NamespacedName{Name: sm.Name, Namespace: sm.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			p.Log.Info("Creating ServiceMonitor", "name", sm.Name)
			if err := p.Client.Create(ctx, sm); err != nil {
				return Error(err, "Failed to create ServiceMonitor")
			}
			return OK()
		}
		return Error(err, "Failed to get ServiceMonitor")
	}

	// Update if changed
	if p.serviceMonitorNeedsUpdate(existing, sm) {
		existing.Spec = sm.Spec
		existing.Labels = sm.Labels
		p.Log.Info("Updating ServiceMonitor", "name", sm.Name)
		if err := p.Client.Update(ctx, existing); err != nil {
			return Error(err, "Failed to update ServiceMonitor")
		}
	}

	return OK()
}

func (p *MonitoringPhase) ensurePrometheusRule(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	rule := &monitoringv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Spec: monitoringv1.PrometheusRuleSpec{
			Groups: []monitoringv1.RuleGroup{
				{
					Name: "nomad.rules",
					Rules: []monitoringv1.Rule{
						{
							Alert: "NomadJobFailed",
							Expr:  intstr.FromString(`nomad_nomad_job_summary_failed{exported_job!~".*periodic.*"} > 0`),
							For:   ptr(monitoringv1.Duration("5m")),
							Labels: map[string]string{
								"severity": "warning",
							},
							Annotations: map[string]string{
								"summary":     "Nomad job has failed allocations",
								"description": "Job {{ $labels.exported_job }} in namespace {{ $labels.namespace }} has {{ $value }} failed allocations.",
							},
						},
						{
							Alert: "NomadClusterLeaderLost",
							Expr:  intstr.FromString(`changes(nomad_raft_leader_lastContact_count[5m]) > 5`),
							For:   ptr(monitoringv1.Duration("2m")),
							Labels: map[string]string{
								"severity": "critical",
							},
							Annotations: map[string]string{
								"summary":     "Nomad cluster experiencing leader instability",
								"description": "Nomad cluster {{ $labels.namespace }} has had multiple leader changes in the past 5 minutes.",
							},
						},
						{
							Alert: "NomadServerDown",
							Expr:  intstr.FromString(`up{job=~".*nomad.*"} == 0`),
							For:   ptr(monitoringv1.Duration("1m")),
							Labels: map[string]string{
								"severity": "critical",
							},
							Annotations: map[string]string{
								"summary":     "Nomad server is down",
								"description": "Nomad server {{ $labels.instance }} in namespace {{ $labels.namespace }} is down.",
							},
						},
						{
							Alert: "NomadHighMemoryUsage",
							Expr:  intstr.FromString(`nomad_runtime_alloc_bytes / nomad_runtime_sys_bytes * 100 > 90`),
							For:   ptr(monitoringv1.Duration("10m")),
							Labels: map[string]string{
								"severity": "warning",
							},
							Annotations: map[string]string{
								"summary":     "Nomad server high memory usage",
								"description": "Nomad server {{ $labels.instance }} is using more than 90% of allocated memory.",
							},
						},
						{
							Alert: "NomadRaftBehind",
							Expr:  intstr.FromString(`nomad_raft_commitNumLogs - nomad_raft_appliedIndex > 1000`),
							For:   ptr(monitoringv1.Duration("5m")),
							Labels: map[string]string{
								"severity": "warning",
							},
							Annotations: map[string]string{
								"summary":     "Nomad server falling behind on Raft commits",
								"description": "Nomad server {{ $labels.instance }} has more than 1000 uncommitted Raft logs.",
							},
						},
						{
							Alert: "NomadLicenseExpiringSoon",
							Expr:  intstr.FromString(`(nomad_license_expiration_time_epoch - time()) / 86400 < 30 and (nomad_license_expiration_time_epoch - time()) > 0`),
							For:   ptr(monitoringv1.Duration("1h")),
							Labels: map[string]string{
								"severity": "warning",
							},
							Annotations: map[string]string{
								"summary":     "Nomad Enterprise license expiring soon",
								"description": "Nomad Enterprise license expires in {{ $value | printf \"%.0f\" }} days. Renew before expiration to avoid service disruption.",
							},
						},
						{
							Alert: "NomadLicenseExpired",
							Expr:  intstr.FromString(`nomad_license_expiration_time_epoch - time() < 0`),
							For:   ptr(monitoringv1.Duration("5m")),
							Labels: map[string]string{
								"severity": "critical",
							},
							Annotations: map[string]string{
								"summary":     "Nomad Enterprise license has expired",
								"description": "Nomad Enterprise license has expired. The cluster may enter a degraded state. Apply a valid license immediately.",
							},
						},
					},
				},
			},
		},
	}

	if err := controllerutil.SetControllerReference(cluster, rule, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on PrometheusRule")
	}

	existing := &monitoringv1.PrometheusRule{}
	err := p.Client.Get(ctx, types.NamespacedName{Name: rule.Name, Namespace: rule.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			p.Log.Info("Creating PrometheusRule", "name", rule.Name)
			if err := p.Client.Create(ctx, rule); err != nil {
				return Error(err, "Failed to create PrometheusRule")
			}
			return OK()
		}
		return Error(err, "Failed to get PrometheusRule")
	}

	return OK()
}

func (p *MonitoringPhase) serviceMonitorNeedsUpdate(existing, desired *monitoringv1.ServiceMonitor) bool {
	if len(existing.Spec.Endpoints) != len(desired.Spec.Endpoints) {
		return true
	}
	if len(existing.Spec.Endpoints) > 0 && len(desired.Spec.Endpoints) > 0 {
		if existing.Spec.Endpoints[0].Interval != desired.Spec.Endpoints[0].Interval {
			return true
		}
		if existing.Spec.Endpoints[0].ScrapeTimeout != desired.Spec.Endpoints[0].ScrapeTimeout {
			return true
		}
	}
	return false
}
