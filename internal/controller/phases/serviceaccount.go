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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// ServiceAccountPhase creates the ServiceAccount for Nomad pods.
type ServiceAccountPhase struct {
	*PhaseContext
}

// NewServiceAccountPhase creates a new ServiceAccountPhase.
func NewServiceAccountPhase(ctx *PhaseContext) *ServiceAccountPhase {
	return &ServiceAccountPhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *ServiceAccountPhase) Name() string {
	return "ServiceAccount"
}

// Execute creates or updates the ServiceAccount for Nomad pods.
func (p *ServiceAccountPhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
	}

	// Set owner reference
	if err := controllerutil.SetControllerReference(cluster, sa, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on ServiceAccount")
	}

	// Check if exists
	existing := &corev1.ServiceAccount{}
	err := p.Client.Get(ctx, types.NamespacedName{Name: sa.Name, Namespace: sa.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			// Create
			p.Log.Info("Creating ServiceAccount", "name", sa.Name)
			if err := p.Client.Create(ctx, sa); err != nil {
				return Error(err, "Failed to create ServiceAccount")
			}
			return OK()
		}
		return Error(err, "Failed to get ServiceAccount")
	}

	// Already exists, nothing to update for ServiceAccount
	return OK()
}
