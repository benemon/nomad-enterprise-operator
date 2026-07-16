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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
)

// failingNomadAPI errors on policy creation, driving the
// TokenCreationFailed path.
type failingNomadAPI struct {
	nomad.NomadAPI
}

func (f *failingNomadAPI) CreateACLPolicy(_, _, _, _ string) error {
	return fmt.Errorf("nomad unreachable")
}

// drainEvents empties the FakeRecorder channel.
func drainEvents(rec *record.FakeRecorder) []string {
	var events []string
	for {
		select {
		case e := <-rec.Events:
			events = append(events, e)
		default:
			return events
		}
	}
}

// Events fire once per transition and the Degraded condition tracks
// agent health past a grace window (neo-2um.4), matching the snapshot
// controller's setDegraded pattern.
var _ = Describe("NomadAutoscaler Events and Degraded condition (neo-2um.4)", func() {
	var (
		ctx        context.Context
		namespace  string
		autoscaler *nomadv1alpha1.NomadAutoscaler
		recorder   *record.FakeRecorder
	)

	newReconciler := func(factory func(nomad.ClientConfig) (nomad.NomadAPI, error)) *NomadAutoscalerReconciler {
		return &NomadAutoscalerReconciler{
			Client:             k8sClient,
			Scheme:             k8sClient.Scheme(),
			Recorder:           recorder,
			NomadClientFactory: factory,
		}
	}

	// setupCluster creates a bootstrapped cluster with the secrets the
	// token path reads, same fixture as the full-reconcile suite.
	setupCluster := func() {
		createTestNamespace(ctx, namespace)
		createLicenseSecret(ctx, namespace)

		cluster := newTestCluster(namespace, "nomad")
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
		cluster.Status.ACLBootstrapped = true
		cluster.Status.ACLBootstrapSecretName = testACLBootstrapSecretName
		Expect(k8sClient.Status().Update(ctx, cluster)).To(Succeed())

		createBootstrapSecret(ctx, namespace, testACLBootstrapSecretName)
		createBootstrapSecret(ctx, namespace, "nomad-operator-management")
		createTLSSecret(ctx, namespace, "nomad")
	}

	BeforeEach(func() {
		ctx = context.Background()
		namespace = fmt.Sprintf("test-autoscaler-degraded-%d", time.Now().UnixNano())
		recorder = record.NewFakeRecorder(10)
		setupCluster()

		autoscaler = newTestAutoscaler(namespace, "as", "nomad")
		Expect(k8sClient.Create(ctx, autoscaler)).To(Succeed())
	})

	AfterEach(func() {
		_ = k8sClient.Delete(ctx, autoscaler)
	})

	nsName := func() types.NamespacedName {
		return types.NamespacedName{Name: autoscaler.Name, Namespace: namespace}
	}

	readyReason := func() string {
		fetched := &nomadv1alpha1.NomadAutoscaler{}
		Expect(k8sClient.Get(ctx, nsName(), fetched)).To(Succeed())
		cond := meta.FindStatusCondition(fetched.Status.Conditions, "Ready")
		Expect(cond).NotTo(BeNil())
		return cond.Reason
	}

	degraded := func() *metav1.Condition {
		fetched := &nomadv1alpha1.NomadAutoscaler{}
		Expect(k8sClient.Get(ctx, nsName(), fetched)).To(Succeed())
		return meta.FindStatusCondition(fetched.Status.Conditions, "Degraded")
	}

	It("emits a TokenCreationFailed Warning once per transition, not per retry", func() {
		reconciler := newReconciler(func(nomad.ClientConfig) (nomad.NomadAPI, error) {
			return &failingNomadAPI{}, nil
		})

		// Finalizer pass, then two failing token passes.
		for i := 0; i < 3; i++ {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nsName()})
			Expect(err).NotTo(HaveOccurred())
		}

		Expect(readyReason()).To(Equal("TokenCreationFailed"))
		events := drainEvents(recorder)
		Expect(events).To(HaveLen(1), "one Warning per transition, not per retry: %v", events)
		Expect(events[0]).To(ContainSubstring("Warning TokenCreationFailed"))
	})

	Describe("Degraded condition", func() {
		var (
			reconciler *NomadAutoscalerReconciler
			deploy     *appsv1.Deployment
		)

		// setDeploymentStatus writes the agent Deployment's status
		// subresource: envtest has no deployment controller, so tests
		// author the observed state directly.
		setDeploymentStatus := func(ready int32, conditions ...appsv1.DeploymentCondition) {
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "as-autoscaler-agent", Namespace: namespace,
			}, deploy)).To(Succeed())
			deploy.Status.Replicas = ready
			deploy.Status.ReadyReplicas = ready
			deploy.Status.Conditions = conditions
			Expect(k8sClient.Status().Update(ctx, deploy)).To(Succeed())
		}

		reconcileOnce := func() reconcile.Result {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nsName()})
			Expect(err).NotTo(HaveOccurred())
			return result
		}

		BeforeEach(func() {
			capturedRules := ""
			reconciler = newReconciler(func(nomad.ClientConfig) (nomad.NomadAPI, error) {
				return &stubNomadAPI{capturedRules: &capturedRules}, nil
			})
			deploy = &appsv1.Deployment{}

			// Finalizer pass, then a full pass creating the Deployment.
			reconcileOnce()
			reconcileOnce()
			drainEvents(recorder)
		})

		It("stays healthy within the grace window and requeues to re-check", func() {
			setDeploymentStatus(0, appsv1.DeploymentCondition{
				Type:               appsv1.DeploymentAvailable,
				Status:             corev1.ConditionFalse,
				LastTransitionTime: metav1.Now(),
			})

			result := reconcileOnce()

			cond := degraded()
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal("AgentHealthy"))
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))
			Expect(result.RequeueAfter).To(BeNumerically("<=", autoscalerDegradedGrace+time.Second),
				"must requeue to fire the transition when the grace window lapses")
			Expect(drainEvents(recorder)).To(BeEmpty())
		})

		It("degrades with one Warning after the grace window, and recovers", func() {
			setDeploymentStatus(0, appsv1.DeploymentCondition{
				Type:               appsv1.DeploymentAvailable,
				Status:             corev1.ConditionFalse,
				LastTransitionTime: metav1.NewTime(time.Now().Add(-2 * autoscalerDegradedGrace)),
			})

			reconcileOnce()
			reconcileOnce()

			cond := degraded()
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			Expect(cond.Reason).To(Equal("AgentUnavailable"))

			events := drainEvents(recorder)
			Expect(events).To(HaveLen(1), "one Warning per transition into Degraded: %v", events)
			Expect(events[0]).To(ContainSubstring("Warning AutoscalerDegraded"))

			By("recovering once the agent is available again")
			setDeploymentStatus(1, appsv1.DeploymentCondition{
				Type:   appsv1.DeploymentAvailable,
				Status: corev1.ConditionTrue,
			})
			reconcileOnce()

			cond = degraded()
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal("AgentHealthy"))
			Expect(readyReason()).To(Equal("Deployed"))
		})

		It("degrades as RolloutStuck when the progress deadline is exceeded", func() {
			// Old ReplicaSet keeps readyReplicas at desired (surge), so
			// only the Progressing condition betrays the stuck rollout.
			setDeploymentStatus(1, appsv1.DeploymentCondition{
				Type:   appsv1.DeploymentProgressing,
				Status: corev1.ConditionFalse,
				Reason: "ProgressDeadlineExceeded",
			})

			reconcileOnce()

			cond := degraded()
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			Expect(cond.Reason).To(Equal("RolloutStuck"))
			Expect(readyReason()).To(Equal("Deployed"),
				"Ready stays True on the old ReplicaSet — Degraded carries the signal")

			events := drainEvents(recorder)
			Expect(events).To(HaveLen(1))
			Expect(events[0]).To(ContainSubstring("Warning AutoscalerDegraded"))
		})

		It("keeps Degraded=True when replica loss follows a stuck rollout (neo-2um.20)", func() {
			stuck := appsv1.DeploymentCondition{
				Type:   appsv1.DeploymentProgressing,
				Status: corev1.ConditionFalse,
				Reason: "ProgressDeadlineExceeded",
			}

			By("a stuck surge rollout degrades (old ReplicaSet keeps ready==desired)")
			setDeploymentStatus(1, stuck)
			reconcileOnce()
			Expect(degraded().Reason).To(Equal("RolloutStuck"))

			By("an old-RS pod dying flips Available=False inside the grace window")
			setDeploymentStatus(0, stuck, appsv1.DeploymentCondition{
				Type:               appsv1.DeploymentAvailable,
				Status:             corev1.ConditionFalse,
				LastTransitionTime: metav1.Now(),
			})
			reconcileOnce()

			cond := degraded()
			Expect(cond.Status).To(Equal(metav1.ConditionTrue),
				"Degraded must not clear to AgentHealthy while the incident worsens")
			Expect(cond.Reason).To(Equal("RolloutStuck"))

			events := drainEvents(recorder)
			Expect(events).To(HaveLen(1), "exactly one Warning for the whole incident: %v", events)
			Expect(events[0]).To(ContainSubstring("Warning AutoscalerDegraded"))
		})
	})
})
