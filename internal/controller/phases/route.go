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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
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
func (p *RoutePhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	// Skip if OpenShift or Route is disabled
	if !cluster.Spec.OpenShift.Enabled || !cluster.Spec.OpenShift.Route.Enabled {
		p.Log.V(1).Info("OpenShift Route disabled, skipping")
		return OK()
	}

	route := p.buildRoute(cluster)

	if err := controllerutil.SetControllerReference(cluster, route, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on Route")
	}

	existing := &routev1.Route{}
	err := p.Client.Get(ctx, types.NamespacedName{Name: route.Name, Namespace: route.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			p.Log.Info("Creating Route", "name", route.Name)
			if err := p.Client.Create(ctx, route); err != nil {
				return Error(err, "Failed to create Route")
			}
			return OK()
		}
		return Error(err, "Failed to get Route")
	}

	// Update if TLS config changed
	if p.routeNeedsUpdate(existing, route) {
		existing.Spec = route.Spec
		p.Log.Info("Updating Route", "name", route.Name)
		if err := p.Client.Update(ctx, existing); err != nil {
			return Error(err, "Failed to update Route")
		}
	}

	return OK()
}

func (p *RoutePhase) buildRoute(cluster *nomadv1alpha1.NomadCluster) *routev1.Route {
	routeSpec := cluster.Spec.OpenShift.Route

	// Determine TLS termination type
	termination := routev1.TLSTerminationEdge
	switch routeSpec.TLS.Termination {
	case "passthrough":
		termination = routev1.TLSTerminationPassthrough
	case "reencrypt":
		termination = routev1.TLSTerminationReencrypt
	}

	// Determine insecure edge termination policy
	insecurePolicy := routev1.InsecureEdgeTerminationPolicyRedirect
	switch routeSpec.TLS.InsecureEdgeTerminationPolicy {
	case "Allow":
		insecurePolicy = routev1.InsecureEdgeTerminationPolicyAllow
	case "None":
		insecurePolicy = routev1.InsecureEdgeTerminationPolicyNone
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
				Weight: ptr(int32(100)),
			},
			Port: &routev1.RoutePort{
				TargetPort: intstr.FromString("http"),
			},
			TLS: &routev1.TLSConfig{
				Termination:                   termination,
				InsecureEdgeTerminationPolicy: insecurePolicy,
			},
		},
	}

	// Set custom host if specified
	if routeSpec.Host != "" {
		route.Spec.Host = routeSpec.Host
	}

	return route
}

func (p *RoutePhase) routeNeedsUpdate(existing, desired *routev1.Route) bool {
	if existing.Spec.TLS == nil && desired.Spec.TLS != nil {
		return true
	}
	if existing.Spec.TLS != nil && desired.Spec.TLS != nil {
		if existing.Spec.TLS.Termination != desired.Spec.TLS.Termination {
			return true
		}
		if existing.Spec.TLS.InsecureEdgeTerminationPolicy != desired.Spec.TLS.InsecureEdgeTerminationPolicy {
			return true
		}
	}
	if desired.Spec.Host != "" && existing.Spec.Host != desired.Spec.Host {
		return true
	}
	return false
}

func ptr[T any](v T) *T {
	return &v
}
