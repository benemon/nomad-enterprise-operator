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
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// RBACPhase creates Role and RoleBinding for Nomad pods.
type RBACPhase struct {
	*PhaseContext
}

// NewRBACPhase creates a new RBACPhase.
func NewRBACPhase(ctx *PhaseContext) *RBACPhase {
	return &RBACPhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *RBACPhase) Name() string {
	return "RBAC"
}

// Execute creates or updates RBAC resources for Nomad pods.
func (p *RBACPhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	// Create Role
	if result := p.ensureRole(ctx, cluster); result.Error != nil || result.Requeue {
		return result
	}

	// Create RoleBinding
	if result := p.ensureRoleBinding(ctx, cluster); result.Error != nil || result.Requeue {
		return result
	}

	return OK()
}

func (p *RBACPhase) ensureRole(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{string(corev1.ResourcePods)},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}

	if err := controllerutil.SetControllerReference(cluster, role, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on Role")
	}

	existing := &rbacv1.Role{}
	err := p.Client.Get(ctx, types.NamespacedName{Name: role.Name, Namespace: role.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			p.Log.Info("Creating Role", "name", role.Name)
			if err := p.Client.Create(ctx, role); err != nil {
				return Error(err, "Failed to create Role")
			}
			return OK()
		}
		return Error(err, "Failed to get Role")
	}

	// Update if rules changed
	if !rulesEqual(existing.Rules, role.Rules) {
		existing.Rules = role.Rules
		p.Log.Info("Updating Role", "name", role.Name)
		if err := p.Client.Update(ctx, existing); err != nil {
			return Error(err, "Failed to update Role")
		}
	}

	return OK()
}

func (p *RBACPhase) ensureRoleBinding(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     cluster.Name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      cluster.Name,
				Namespace: cluster.Namespace,
			},
		},
	}

	if err := controllerutil.SetControllerReference(cluster, rb, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on RoleBinding")
	}

	existing := &rbacv1.RoleBinding{}
	err := p.Client.Get(ctx, types.NamespacedName{Name: rb.Name, Namespace: rb.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			p.Log.Info("Creating RoleBinding", "name", rb.Name)
			if err := p.Client.Create(ctx, rb); err != nil {
				return Error(err, "Failed to create RoleBinding")
			}
			return OK()
		}
		return Error(err, "Failed to get RoleBinding")
	}

	return OK()
}

func rulesEqual(a, b []rbacv1.PolicyRule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !policyRuleEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

func policyRuleEqual(a, b rbacv1.PolicyRule) bool {
	return stringSliceEqual(a.APIGroups, b.APIGroups) &&
		stringSliceEqual(a.Resources, b.Resources) &&
		stringSliceEqual(a.Verbs, b.Verbs)
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
