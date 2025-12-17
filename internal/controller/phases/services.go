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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// ServicesPhase creates all Kubernetes Services for Nomad.
type ServicesPhase struct {
	*PhaseContext
}

// NewServicesPhase creates a new ServicesPhase.
func NewServicesPhase(ctx *PhaseContext) *ServicesPhase {
	return &ServicesPhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *ServicesPhase) Name() string {
	return "Services"
}

// Execute creates or updates all Kubernetes Services for Nomad.
func (p *ServicesPhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	// Create headless service for StatefulSet DNS
	if result := p.ensureHeadlessService(ctx, cluster); result.Error != nil || result.Requeue {
		return result
	}

	// Create internal ClusterIP service
	if result := p.ensureInternalService(ctx, cluster); result.Error != nil || result.Requeue {
		return result
	}

	// Create external LoadBalancer/NodePort service
	if result := p.ensureExternalService(ctx, cluster); result.Error != nil || result.Requeue {
		return result
	}

	return OK()
}

func (p *ServicesPhase) ensureHeadlessService(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name + "-headless",
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Spec: corev1.ServiceSpec{
			Type:                     corev1.ServiceTypeClusterIP,
			ClusterIP:                corev1.ClusterIPNone,
			PublishNotReadyAddresses: true,
			Selector:                 GetSelectorLabels(cluster),
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       4646,
					TargetPort: intstr.FromInt(4646),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "rpc",
					Port:       4647,
					TargetPort: intstr.FromInt(4647),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "serf",
					Port:       4648,
					TargetPort: intstr.FromInt(4648),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	return p.ensureService(ctx, cluster, svc)
}

func (p *ServicesPhase) ensureInternalService(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name + "-internal",
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: GetSelectorLabels(cluster),
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       4646,
					TargetPort: intstr.FromInt(4646),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	return p.ensureService(ctx, cluster, svc)
}

func (p *ServicesPhase) ensureExternalService(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	serviceType := cluster.Spec.Services.External.Type
	if serviceType == "" {
		serviceType = corev1.ServiceTypeLoadBalancer
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        cluster.Name + "-external",
			Namespace:   cluster.Namespace,
			Labels:      GetLabels(cluster),
			Annotations: cluster.Spec.Services.External.Annotations,
		},
		Spec: corev1.ServiceSpec{
			Type:     serviceType,
			Selector: GetSelectorLabels(cluster),
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       4646,
					TargetPort: intstr.FromInt(4646),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "rpc",
					Port:       4647,
					TargetPort: intstr.FromInt(4647),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	// Set LoadBalancerIP if specified
	if cluster.Spec.Services.External.LoadBalancerIP != "" && serviceType == corev1.ServiceTypeLoadBalancer {
		svc.Spec.LoadBalancerIP = cluster.Spec.Services.External.LoadBalancerIP
	}

	return p.ensureService(ctx, cluster, svc)
}

func (p *ServicesPhase) ensureService(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, svc *corev1.Service) PhaseResult {
	if err := controllerutil.SetControllerReference(cluster, svc, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on Service "+svc.Name)
	}

	existing := &corev1.Service{}
	err := p.Client.Get(ctx, types.NamespacedName{Name: svc.Name, Namespace: svc.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			p.Log.Info("Creating Service", "name", svc.Name, "type", svc.Spec.Type)
			if err := p.Client.Create(ctx, svc); err != nil {
				return Error(err, "Failed to create Service "+svc.Name)
			}
			return OK()
		}
		return Error(err, "Failed to get Service "+svc.Name)
	}

	// Update annotations if changed (for external service)
	if svc.Annotations != nil && !mapsEqual(existing.Annotations, svc.Annotations) {
		existing.Annotations = svc.Annotations
		p.Log.Info("Updating Service annotations", "name", svc.Name)
		if err := p.Client.Update(ctx, existing); err != nil {
			return Error(err, "Failed to update Service "+svc.Name)
		}
	}

	return OK()
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
