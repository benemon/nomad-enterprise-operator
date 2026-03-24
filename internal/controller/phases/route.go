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
	routev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// RoutePhase creates the OpenShift Route for Nomad UI access.
type RoutePhase struct {
	*PhaseContext
}

// NewRoutePhase creates a new RoutePhase.
func NewRoutePhase(ctx *PhaseContext) *RoutePhase {
	return &RoutePhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *RoutePhase) Name() string {
	return "Route"
}

// Execute creates or updates the OpenShift Route for Nomad UI access.
// The Route always uses reencrypt termination since mTLS is always enabled.
func (p *RoutePhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	// Skip if OpenShift or Route is disabled
	if !cluster.Spec.OpenShift.Enabled || !cluster.Spec.OpenShift.Route.Enabled {
		p.Log.V(1).Info("OpenShift Route disabled, skipping")
		return OK()
	}

	route, err := p.buildRoute(ctx, cluster)
	if err != nil {
		return Error(err, "Failed to build Route")
	}

	if err := controllerutil.SetControllerReference(cluster, route, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on Route")
	}

	existing := &routev1.Route{}
	if err := p.Client.Get(ctx, types.NamespacedName{Name: route.Name, Namespace: route.Namespace}, existing); err != nil {
		if errors.IsNotFound(err) {
			p.Log.Info("Creating Route", "name", route.Name)
			if err := p.Client.Create(ctx, route); err != nil {
				return Error(err, "Failed to create Route")
			}
			return OK()
		}
		return Error(err, "Failed to get Route")
	}

	// Always overwrite spec on every reconcile so that certificate renewals,
	// CA rotations, and CertificateSecretName changes are picked up.
	if p.routeNeedsUpdate(existing, route) {
		existing.Spec = route.Spec
		p.Log.Info("Updating Route", "name", route.Name)
		if err := p.Client.Update(ctx, existing); err != nil {
			return Error(err, "Failed to update Route")
		}
	}

	return OK()
}

func (p *RoutePhase) buildRoute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (*routev1.Route, error) {
	routeSpec := cluster.Spec.OpenShift.Route

	// mTLS is always enabled — Route is always reencrypt with HTTP→HTTPS redirect
	tlsConfig := &routev1.TLSConfig{
		Termination:                   routev1.TLSTerminationReencrypt,
		InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
	}

	// Set DestinationCACertificate from the Nomad CA so the router can verify the backend
	if len(p.CACert) > 0 {
		tlsConfig.DestinationCACertificate = string(p.CACert)
	}

	// Load custom external-facing certificate if specified
	if routeSpec.TLS.CertificateSecretName != "" {
		certSecret := &corev1.Secret{}
		if err := p.Client.Get(ctx, types.NamespacedName{
			Name:      routeSpec.TLS.CertificateSecretName,
			Namespace: cluster.Namespace,
		}, certSecret); err != nil {
			return nil, err
		}
		certKey := routeSpec.TLS.SecretKeys.Certificate
		if certKey == "" {
			certKey = "tls.crt"
		}
		keyKey := routeSpec.TLS.SecretKeys.PrivateKey
		if keyKey == "" {
			keyKey = "tls.key"
		}
		tlsConfig.Certificate = string(certSecret.Data[certKey])
		tlsConfig.Key = string(certSecret.Data[keyKey])
	}

	route := &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "console",
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Spec: routev1.RouteSpec{
			To: routev1.RouteTargetReference{
				Kind:   "Service",
				Name:   cluster.Name + "-internal",
				Weight: ptr.To(int32(100)),
			},
			Port: &routev1.RoutePort{
				TargetPort: intstr.FromString("http"),
			},
			TLS: tlsConfig,
		},
	}

	// Set custom host if specified
	if routeSpec.Host != "" {
		route.Spec.Host = routeSpec.Host
	}

	return route, nil
}

func (p *RoutePhase) routeNeedsUpdate(existing, desired *routev1.Route) bool {
	if existing.Spec.TLS == nil && desired.Spec.TLS != nil {
		return true
	}
	if existing.Spec.TLS != nil && desired.Spec.TLS != nil {
		if existing.Spec.TLS.Termination != desired.Spec.TLS.Termination {
			return true
		}
		if existing.Spec.TLS.DestinationCACertificate != desired.Spec.TLS.DestinationCACertificate {
			return true
		}
		if existing.Spec.TLS.Certificate != desired.Spec.TLS.Certificate {
			return true
		}
		if existing.Spec.TLS.Key != desired.Spec.TLS.Key {
			return true
		}
	}
	if desired.Spec.Host != "" && existing.Spec.Host != desired.Spec.Host {
		return true
	}
	return false
}
