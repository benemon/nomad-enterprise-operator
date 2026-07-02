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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/internal/controller/phases"
)

// C3 (neo-gwt): the bootstrap-token Secret has no ownerReference, so the
// deletion finalizer must delete it explicitly — last, after the
// best-effort Nomad-side ACL cleanup (AC-2.4.2 / AC-2.4.3). Two
// scenarios:
//
//   - no Nomad-side resources recorded on status: deletion proceeds
//     straight to the Secret delete;
//   - Nomad-side cleanup fails (status names a policy but Nomad is
//     unreachable from envtest): failure is non-fatal and the Secret is
//     still deleted.
//
// In both cases the finalizer is released (cluster gone).
var _ = Describe("C3 bootstrap Secret finalizer lifecycle", func() {
	ctx := context.Background()

	makeBootstrapSecret := func(namespace string, cluster *nomadv1alpha1.NomadCluster) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      phases.BootstrapSecretName(cluster.Name),
				Namespace: namespace,
				Labels: map[string]string{
					phases.BootstrapSecretClusterLabel: cluster.Name,
				},
			},
			StringData: map[string]string{"secret-id": "test-bootstrap-token"},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	}

	secretGone := func(namespace, name string) bool {
		secret := &corev1.Secret{}
		err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, secret)
		return errors.IsNotFound(err)
	}

	type scenario struct {
		name             string
		nomadSidePolicy  bool // status.operatorStatusPolicyName set → cleanup attempted (and fails)
		expectSecretGone bool
	}

	scenarios := []scenario{
		{name: "deletes the bootstrap Secret when no Nomad-side cleanup is recorded", nomadSidePolicy: false, expectSecretGone: true},
		{name: "deletes the bootstrap Secret even when Nomad-side cleanup fails (AC-2.4.3)", nomadSidePolicy: true, expectSecretGone: true},
	}

	for i, sc := range scenarios {
		sc := sc
		namespace := fmt.Sprintf("bootstrap-secret-test-%d", i)

		It(sc.name, func() {
			createTestNamespace(ctx, namespace)

			cluster := newTestCluster(namespace, "c3-check")
			controllerutil.AddFinalizer(cluster, nomadClusterFinalizer)
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			makeBootstrapSecret(namespace, cluster)

			if sc.nomadSidePolicy {
				fetched := &nomadv1alpha1.NomadCluster{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name: "c3-check", Namespace: namespace,
				}, fetched)).To(Succeed())
				fetched.Status.OperatorStatusPolicyName = "c3-check-operator-status"
				Expect(k8sClient.Status().Update(ctx, fetched)).To(Succeed())
			}

			fetched := &nomadv1alpha1.NomadCluster{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "c3-check", Namespace: namespace,
			}, fetched)).To(Succeed())
			Expect(k8sClient.Delete(ctx, fetched)).To(Succeed())

			_, err := reconcileCluster(ctx, types.NamespacedName{
				Name: "c3-check", Namespace: namespace,
			})
			Expect(err).NotTo(HaveOccurred())

			// AC-2.4.3: bootstrap Secret deleted last, regardless of the
			// Nomad-side cleanup outcome.
			Expect(secretGone(namespace, phases.BootstrapSecretName("c3-check"))).To(Equal(sc.expectSecretGone))

			// Finalizer released — cluster is actually gone.
			gone := &nomadv1alpha1.NomadCluster{}
			getErr := k8sClient.Get(ctx, types.NamespacedName{
				Name: "c3-check", Namespace: namespace,
			}, gone)
			Expect(errors.IsNotFound(getErr)).To(BeTrue(), "cluster should be deleted after finalizer release")
		})
	}
})
