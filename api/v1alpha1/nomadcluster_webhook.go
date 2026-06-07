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

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// nomadclusterlog is the logger used by NomadCluster webhook handlers.
var nomadclusterlog = logf.Log.WithName("nomadcluster-webhook")

// SetupWebhookWithManager registers the NomadCluster validating webhook with
// the controller-runtime manager.
func (r *NomadCluster) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		WithDefaulter(&NomadClusterCustomDefaulter{}).
		WithValidator(&NomadClusterCustomValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-nomad-hashicorp-com-v1alpha1-nomadcluster,mutating=true,failurePolicy=fail,sideEffects=None,groups=nomad.hashicorp.com,resources=nomadclusters,verbs=create;update,versions=v1alpha1,name=mnomadcluster.kb.io,admissionReviewVersions=v1

// NomadClusterCustomDefaulter applies defaults to a NomadCluster.
// The Default method is intentionally a no-op skeleton: the CRD's
// kubebuilder:default markers cover all current defaulting needs. The
// scaffolding is in place for future C6 work.
type NomadClusterCustomDefaulter struct{}

var _ webhook.CustomDefaulter = &NomadClusterCustomDefaulter{}

// Default implements webhook.CustomDefaulter.
func (d *NomadClusterCustomDefaulter) Default(_ context.Context, obj runtime.Object) error {
	cluster, ok := obj.(*NomadCluster)
	if !ok {
		return fmt.Errorf("expected a NomadCluster object but got %T", obj)
	}
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

var _ webhook.CustomValidator = &NomadClusterCustomValidator{}

// ValidateCreate implements webhook.CustomValidator.
func (v *NomadClusterCustomValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	cluster, ok := obj.(*NomadCluster)
	if !ok {
		return nil, fmt.Errorf("expected a NomadCluster object but got %T", obj)
	}
	nomadclusterlog.V(1).Info("validating NomadCluster create", "name", cluster.GetName())
	return nil, validateReplicas(cluster)
}

// ValidateUpdate implements webhook.CustomValidator.
func (v *NomadClusterCustomValidator) ValidateUpdate(_ context.Context, _, newObj runtime.Object) (admission.Warnings, error) {
	cluster, ok := newObj.(*NomadCluster)
	if !ok {
		return nil, fmt.Errorf("expected a NomadCluster object but got %T", newObj)
	}
	nomadclusterlog.V(1).Info("validating NomadCluster update", "name", cluster.GetName())
	return nil, validateReplicas(cluster)
}

// ValidateDelete implements webhook.CustomValidator.
func (v *NomadClusterCustomValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
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
