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

// D2c (neo-1ve.3): CEL admission rule on the NomadCluster type for
// AC-2.3.5a — spec.replicas cannot be edited while a scale-down is in
// flight (status.scaleDown.removedPeers non-empty).
//
// AC-2.3.5 / 2.3.6 (degraded-quorum opt-in) were originally designed
// as a CEL rule too, but CRD validation rules on K8s 1.36 cannot
// access metadata.annotations or metadata.labels — only structural
// schema fields. Those ACs are therefore enforced by the operator's
// ScaleDownPhase, with dedicated unit tests under
// internal/controller/phases/scaledown_test.go. The annotation
// remains the public contract.
var _ = Describe("Scale-down admission rules (D2c)", func() {
	const namespace = "scaledown-admission-test"

	ctx := context.Background()

	BeforeEach(func() {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
		if err := k8sClient.Create(ctx, ns); err != nil && !errors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	// AC-2.3.5a: while status.scaleDown.removedPeers is non-empty, no
	// spec.replicas edits are accepted — down, up, revert, anything.
	It("rejects every spec.replicas edit while a scale-down operation is in flight", func() {
		cluster := newTestCluster(namespace, "inflight-block")
		cluster.Spec.Replicas = 3
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

		// Seed the in-flight marker via the status subresource.
		fetched := &nomadv1alpha1.NomadCluster{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: "inflight-block", Namespace: namespace,
		}, fetched)).To(Succeed())
		fetched.Status.ScaleDown = &nomadv1alpha1.ScaleDownStatus{
			RemovedPeers: []string{"peer-id-1"},
		}
		Expect(k8sClient.Status().Update(ctx, fetched)).To(Succeed())

		// Attempt each kind of replica change; all must fail with the
		// in-flight message. Covers AC-2.3.5a's "any value" clause:
		// scale up (5) and scale down further (1). The enum
		// {1, 3, 5} prevents intermediate values, and a no-op patch to
		// the current value (3) trivially passes the rule's
		// "self.spec.replicas == oldSelf.spec.replicas" clause so we
		// don't test that — it isn't what AC-2.3.5a guards against.
		attempts := []int32{5, 1}
		for _, target := range attempts {
			refetched := &nomadv1alpha1.NomadCluster{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "inflight-block", Namespace: namespace,
			}, refetched)).To(Succeed())
			refetched.Spec.Replicas = target
			err := k8sClient.Update(ctx, refetched)
			Expect(err).To(HaveOccurred(),
				"spec.replicas → %d should be rejected mid-operation", target)
			Expect(err.Error()).To(ContainSubstring("scale-down operation is in progress"),
				"rejection message must name the in-flight reason")
		}

		// And non-replica edits remain allowed mid-operation (the rule
		// gates on spec.replicas equality, not the rest of the spec).
		refetched := &nomadv1alpha1.NomadCluster{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: "inflight-block", Namespace: namespace,
		}, refetched)).To(Succeed())
		refetched.Spec.Server.ACL.Enabled = !refetched.Spec.Server.ACL.Enabled
		Expect(k8sClient.Update(ctx, refetched)).To(Succeed())
	})

	// AC-2.3.5a: once the operator clears status.scaleDown (operation
	// complete), spec.replicas edits are accepted again.
	It("re-accepts spec.replicas edits once status.scaleDown is cleared", func() {
		cluster := newTestCluster(namespace, "post-completion")
		cluster.Spec.Replicas = 3
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

		// Set status.scaleDown populated (operation in flight).
		fetched := &nomadv1alpha1.NomadCluster{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: "post-completion", Namespace: namespace,
		}, fetched)).To(Succeed())
		fetched.Status.ScaleDown = &nomadv1alpha1.ScaleDownStatus{
			RemovedPeers: []string{"peer-id-1"},
		}
		Expect(k8sClient.Status().Update(ctx, fetched)).To(Succeed())

		// Clear it (operator's finalize path).
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: "post-completion", Namespace: namespace,
		}, fetched)).To(Succeed())
		fetched.Status.ScaleDown = nil
		Expect(k8sClient.Status().Update(ctx, fetched)).To(Succeed())

		// Now replica edits are accepted again.
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: "post-completion", Namespace: namespace,
		}, fetched)).To(Succeed())
		fetched.Spec.Replicas = 5
		Expect(k8sClient.Update(ctx, fetched)).To(Succeed(),
			"spec.replicas edits must be accepted once status.scaleDown clears")
	})

	// Initial creation is exempt from the transition rule — neither
	// rule references self.spec without comparing to oldSelf, so CREATE
	// with any valid replica count is accepted. This is what lets the
	// existing 1-replica test fixtures and the design's "single-instance
	// development cluster" flow keep working.
	It("accepts initial creation with replicas=1", func() {
		cluster := newTestCluster(namespace, "create-one-replica")
		cluster.Spec.Replicas = 1
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed(),
			"CREATE is exempt from transition rules; replicas=1 must be accepted")
	})
})
