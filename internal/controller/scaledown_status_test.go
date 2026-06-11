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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
)

// D2a (neo-1ve.1): the scale-down status field is established here so
// D2b's reconcile loop and D2c's admission rule can both depend on a
// stable shape. The tests verify the field round-trips through the
// apiserver via the status subresource and that clearing to nil is
// preserved on re-read — that nil-clear behaviour is the contract
// D2b will rely on when scale-down completes (AC-2.3.7's final clause:
// "operator clears status.scaleDown entirely").
var _ = Describe("status.scaleDown round-trip (D2a)", func() {
	const namespace = "scaledown-status-test"

	ctx := context.Background()

	BeforeEach(func() {
		// Every It shares one namespace; tolerate AlreadyExists.
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
		if err := k8sClient.Create(ctx, ns); err != nil && !errors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	It("round-trips through status.scaleDown.removedPeers", func() {
		cluster := newTestCluster(namespace, "round-trip")
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

		// Populate the new status field via the status subresource —
		// the same code path D2b's reconcile loop will use to append
		// a removed peer ID after each successful RaftRemovePeer call.
		cluster.Status.ScaleDown = &nomadv1alpha1.ScaleDownStatus{
			RemovedPeers: []string{"peer-id-1", "peer-id-2"},
		}
		Expect(k8sClient.Status().Update(ctx, cluster)).To(Succeed())

		fetched := &nomadv1alpha1.NomadCluster{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: "round-trip", Namespace: namespace,
		}, fetched)).To(Succeed())

		Expect(fetched.Status.ScaleDown).NotTo(BeNil())
		Expect(fetched.Status.ScaleDown.RemovedPeers).To(Equal([]string{"peer-id-1", "peer-id-2"}))
	})

	It("clears to nil when the operation completes", func() {
		cluster := newTestCluster(namespace, "clear-on-complete")
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

		// Simulate an operation in flight, then completion.
		cluster.Status.ScaleDown = &nomadv1alpha1.ScaleDownStatus{
			RemovedPeers: []string{"peer-id-1"},
		}
		Expect(k8sClient.Status().Update(ctx, cluster)).To(Succeed())

		fetched := &nomadv1alpha1.NomadCluster{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: "clear-on-complete", Namespace: namespace,
		}, fetched)).To(Succeed())
		fetched.Status.ScaleDown = nil
		Expect(k8sClient.Status().Update(ctx, fetched)).To(Succeed())

		// Re-read to confirm the apiserver dropped the field rather
		// than persisting an empty struct (the omitempty contract D2c
		// will rely on to gate concurrent edits).
		cleared := &nomadv1alpha1.NomadCluster{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: "clear-on-complete", Namespace: namespace,
		}, cleared)).To(Succeed())
		Expect(cleared.Status.ScaleDown).To(BeNil())
	})
})
