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

package v1alpha1

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// nomadclusterlog is the logger used by NomadCluster webhook handlers.
var nomadclusterlog = logf.Log.WithName("nomadcluster-webhook")

// SetupWebhookWithManager registers the NomadCluster validating webhook with
// the controller-runtime manager.
func (r *NomadCluster) SetupWebhookWithManager(mgr ctrl.Manager) error {
	// controller-runtime v0.24 replaced the NewWebhookManagedBy(mgr).For(r)
	// pair with a single generic builder.WebhookManagedBy[T](mgr, r)
	// constructor.
	return builder.WebhookManagedBy(mgr, r).
		WithDefaulter(&NomadClusterCustomDefaulter{}).
		WithValidator(&NomadClusterCustomValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-nomad-hashicorp-com-v1alpha1-nomadcluster,mutating=true,failurePolicy=fail,sideEffects=None,groups=nomad.hashicorp.com,resources=nomadclusters,verbs=create;update,versions=v1alpha1,name=mnomadcluster.kb.io,admissionReviewVersions=v1

// NomadClusterCustomDefaulter applies defaults to a NomadCluster.
// The Default method is intentionally a no-op skeleton: the CRD's
// kubebuilder:default markers cover all current defaulting needs. The
// scaffolding is in place for future C6 work.
//
// controller-runtime v0.24 made the Defaulter/Validator interfaces
// generic over the concrete type — the framework now handles the
// runtime.Object → *NomadCluster type assertion before invoking us.
type NomadClusterCustomDefaulter struct{}

var _ admission.Defaulter[*NomadCluster] = &NomadClusterCustomDefaulter{}

// Default implements admission.Defaulter[*NomadCluster].
func (d *NomadClusterCustomDefaulter) Default(_ context.Context, cluster *NomadCluster) error {
	nomadclusterlog.V(1).Info("defaulting NomadCluster", "name", cluster.GetName())
	return nil
}

// +kubebuilder:webhook:path=/validate-nomad-hashicorp-com-v1alpha1-nomadcluster,mutating=false,failurePolicy=fail,sideEffects=None,groups=nomad.hashicorp.com,resources=nomadclusters,verbs=create;update,versions=v1alpha1,name=vnomadcluster.kb.io,admissionReviewVersions=v1

// NomadClusterCustomValidator validates a NomadCluster.
//
// AC-F3.3 implements ONLY the replicas-in-{1,3,5} rule. The full invariant
// matrix (C6) lands later — when adding rules, extend validateReplicas-style
// helpers and call them from ValidateCreate/ValidateUpdate.
type NomadClusterCustomValidator struct{}

var _ admission.Validator[*NomadCluster] = &NomadClusterCustomValidator{}

// ValidateCreate implements admission.Validator[*NomadCluster].
func (v *NomadClusterCustomValidator) ValidateCreate(_ context.Context, cluster *NomadCluster) (admission.Warnings, error) {
	nomadclusterlog.V(1).Info("validating NomadCluster create", "name", cluster.GetName())
	return nil, validateReplicas(cluster)
}

// ValidateUpdate implements admission.Validator[*NomadCluster].
func (v *NomadClusterCustomValidator) ValidateUpdate(_ context.Context, _, cluster *NomadCluster) (admission.Warnings, error) {
	nomadclusterlog.V(1).Info("validating NomadCluster update", "name", cluster.GetName())
	return nil, validateReplicas(cluster)
}

// ValidateDelete implements admission.Validator[*NomadCluster].
func (v *NomadClusterCustomValidator) ValidateDelete(_ context.Context, _ *NomadCluster) (admission.Warnings, error) {
	return nil, nil
}

// validateReplicas enforces that spec.replicas is 1, 3, or 5. A value of 0
// is treated as the kubebuilder default (3) by the API server before this
// webhook runs, so an explicit zero here would mean the user set it to zero —
// which is rejected.
func validateReplicas(cluster *NomadCluster) error {
	r := cluster.Spec.Replicas
	switch r {
	case 1, 3, 5:
		return nil
	default:
		return fmt.Errorf("spec.replicas must be 1, 3, or 5 (got %d): Nomad servers run a Raft quorum and require an odd member count to avoid split-brain", r)
	}
}
