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
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// PDBPhase reconciles the PodDisruptionBudget for the Nomad server
// StatefulSet. The operator owns the PDB (no spec field on
// NomadCluster) — D1 design intent is that the disruption policy is a
// platform-level concern, not user-tunable.
//
// Shape per AC-2.3.1:
//   - N >= 3: a policy/v1 PodDisruptionBudget exists, named after the
//     cluster, with maxUnavailable = N/2 (integer division: 1 for 3,
//     2 for 5) and selector matching the operator's pod labels.
//   - N == 1: no PDB. Single-instance clusters are not HA — the
//     operator does not block node drains for them. If a PDB exists
//     from a prior larger replica count, this phase deletes it.
type PDBPhase struct {
	*PhaseContext
}

// NewPDBPhase creates a new PDBPhase.
func NewPDBPhase(ctx *PhaseContext) *PDBPhase {
	return &PDBPhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *PDBPhase) Name() string {
	return "PDB"
}

// Execute creates, updates, or deletes the PDB to match spec.replicas.
func (p *PDBPhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	name := types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}

	if cluster.Spec.Replicas < 3 {
		// N=1 (the only sub-3 value allowed by the spec enum) — no PDB
		// needed. Delete any existing PDB to handle scale-down from a
		// previously larger replica count; ignore NotFound so the
		// phase is a no-op when the PDB was never created.
		existing := &policyv1.PodDisruptionBudget{}
		if err := p.Client.Get(ctx, name, existing); err != nil {
			if errors.IsNotFound(err) {
				return OK()
			}
			return Error(err, "Failed to get PodDisruptionBudget")
		}
		p.Log.Info("Deleting PodDisruptionBudget for single-instance cluster", "name", name.Name)
		if err := p.Client.Delete(ctx, existing); err != nil && !errors.IsNotFound(err) {
			return Error(err, "Failed to delete PodDisruptionBudget")
		}
		return OK()
	}

	desired := p.buildPDB(cluster)
	if err := controllerutil.SetControllerReference(cluster, desired, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on PodDisruptionBudget")
	}

	existing := &policyv1.PodDisruptionBudget{}
	if err := p.Client.Get(ctx, name, existing); err != nil {
		if errors.IsNotFound(err) {
			p.Log.Info("Creating PodDisruptionBudget", "name", name.Name, "maxUnavailable", desired.Spec.MaxUnavailable)
			if err := p.Client.Create(ctx, desired); err != nil {
				return Error(err, "Failed to create PodDisruptionBudget")
			}
			return OK()
		}
		return Error(err, "Failed to get PodDisruptionBudget")
	}

	// Selector and other fields are immutable post-create. The only
	// thing that can drift here is MaxUnavailable on a scale-out: 3→5
	// changes it from 1 to 2 (AC-2.3.3). Compare by IntOrString value
	// to avoid spurious updates from differing-but-equal encodings.
	if !intOrStringEqual(existing.Spec.MaxUnavailable, desired.Spec.MaxUnavailable) {
		p.Log.Info("Updating PodDisruptionBudget maxUnavailable",
			"name", name.Name,
			"from", existing.Spec.MaxUnavailable,
			"to", desired.Spec.MaxUnavailable)
		existing.Spec.MaxUnavailable = desired.Spec.MaxUnavailable
		if err := p.Client.Update(ctx, existing); err != nil {
			return Error(err, "Failed to update PodDisruptionBudget")
		}
	}

	return OK()
}

func (p *PDBPhase) buildPDB(cluster *nomadv1alpha1.NomadCluster) *policyv1.PodDisruptionBudget {
	maxUnavailable := intstr.FromInt32(cluster.Spec.Replicas / 2)
	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: &maxUnavailable,
			Selector: &metav1.LabelSelector{
				MatchLabels: GetSelectorLabels(cluster),
			},
		},
	}
}

func intOrStringEqual(a, b *intstr.IntOrString) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Type == b.Type && a.IntVal == b.IntVal && a.StrVal == b.StrVal
}
