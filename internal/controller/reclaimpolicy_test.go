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

package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/internal/controller/phases"
)

// C1 (neo-bjd): spec.persistence.reclaimPolicy gates finalizer PVC deletion.
//
//	AC-2.3.12 — enum Retain|Delete, default Retain (admission defaulting).
//	AC-2.3.13 — under Retain the finalizer does not delete PVCs.
//	AC-2.3.14 — under Delete the finalizer deletes selector-matching PVCs.
//	AC-2.3.15 — the value at deletion time wins (not retroactive).
//
// Note: envtest has no kube-controller-manager, so a "deleted" PVC stays
// Terminating behind the pvc-protection finalizer. "Deleted" is therefore
// asserted as NotFound OR non-nil DeletionTimestamp.
var _ = Describe("Finalizer reclaimPolicy gating", func() {
	ctx := context.Background()

	makePVC := func(namespace, name string, cluster *nomadv1alpha1.NomadCluster) {
		pvc := &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Labels:    phases.GetSelectorLabels(cluster),
			},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceStorage: resource.MustParse("1Gi"),
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, pvc)).To(Succeed())
	}

	pvcDeleted := func(namespace, name string) bool {
		pvc := &corev1.PersistentVolumeClaim{}
		err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, pvc)
		if errors.IsNotFound(err) {
			return true
		}
		Expect(err).NotTo(HaveOccurred())
		return pvc.DeletionTimestamp != nil
	}

	// deleteAndReconcile deletes the cluster (deletionTimestamp set, held by
	// the finalizer) and runs one reconcile so handleDeletion executes the
	// PVC gate and releases the finalizer.
	deleteAndReconcile := func(namespace string, cluster *nomadv1alpha1.NomadCluster) {
		Expect(k8sClient.Delete(ctx, cluster)).To(Succeed())
		_, err := reconcileCluster(ctx, types.NamespacedName{
			Name: cluster.Name, Namespace: namespace,
		})
		Expect(err).NotTo(HaveOccurred())
	}

	type scenario struct {
		name          string
		policyAtBirth string // "" = rely on admission default
		policyAtDeath string // "" = leave unchanged
		wantDeleted   bool
	}

	scenarios := []scenario{
		{name: "omitted policy defaults to Retain and preserves PVCs", policyAtBirth: "", wantDeleted: false},
		{name: "explicit Retain preserves PVCs", policyAtBirth: nomadv1alpha1.ReclaimPolicyRetain, wantDeleted: false},
		{name: "Delete removes selector-matching PVCs", policyAtBirth: nomadv1alpha1.ReclaimPolicyDelete, wantDeleted: true},
		{name: "policy flipped Delete to Retain before deletion is not retroactive", policyAtBirth: nomadv1alpha1.ReclaimPolicyDelete, policyAtDeath: nomadv1alpha1.ReclaimPolicyRetain, wantDeleted: false},
	}

	for i, sc := range scenarios {
		namespace := fmt.Sprintf("reclaim-test-%d", i)

		It(sc.name, func() {
			createTestNamespace(ctx, namespace)

			cluster := newTestCluster(namespace, "reclaim-check")
			cluster.Spec.Persistence.ReclaimPolicy = sc.policyAtBirth
			// Pre-set the finalizer so handleDeletion is reached without a
			// full create-reconcile cycle.
			controllerutil.AddFinalizer(cluster, nomadClusterFinalizer)
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			// AC-2.3.12: admission must have defaulted an omitted policy.
			fetched := &nomadv1alpha1.NomadCluster{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "reclaim-check", Namespace: namespace,
			}, fetched)).To(Succeed())
			if sc.policyAtBirth == "" {
				Expect(fetched.Spec.Persistence.ReclaimPolicy).To(Equal(nomadv1alpha1.ReclaimPolicyRetain))
			}

			if sc.policyAtDeath != "" {
				fetched.Spec.Persistence.ReclaimPolicy = sc.policyAtDeath
				Expect(k8sClient.Update(ctx, fetched)).To(Succeed())
			}

			pvcName := "data-reclaim-check-0"
			makePVC(namespace, pvcName, fetched)

			deleteAndReconcile(namespace, fetched)

			Expect(pvcDeleted(namespace, pvcName)).To(Equal(sc.wantDeleted))
		})
	}
})
