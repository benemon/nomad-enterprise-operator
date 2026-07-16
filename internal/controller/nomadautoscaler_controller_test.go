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
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
)

// newTestAutoscaler creates a NomadAutoscaler with test defaults.
func newTestAutoscaler(namespace, name, clusterName string) *nomadv1alpha1.NomadAutoscaler {
	return &nomadv1alpha1.NomadAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: nomadv1alpha1.NomadAutoscalerSpec{
			ClusterRef: nomadv1alpha1.ClusterReference{
				Name: clusterName,
			},
		},
	}
}

func reconcileAutoscaler(ctx context.Context, name types.NamespacedName, factory func(nomad.ClientConfig) (nomad.NomadAPI, error)) (reconcile.Result, error) {
	reconciler := &NomadAutoscalerReconciler{
		Client:             k8sClient,
		Scheme:             k8sClient.Scheme(),
		NomadClientFactory: factory,
	}
	return reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: name})
}

// createTLSSecret creates the cluster TLS secret the controller reads
// the CA from.
func createTLSSecret(ctx context.Context, namespace, clusterName string) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterName + "-tls",
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ca.crt": []byte("test-ca"),
		},
	}
	Expect(k8sClient.Create(ctx, secret)).To(Succeed())
}

// stubNomadAPI satisfies just enough of NomadAPI for the token path,
// capturing the policy rules the controller submits. The optional
// fields drive the token-lifecycle specs; unset, every method answers
// with the fixed test token.
type stubNomadAPI struct {
	nomad.NomadAPI

	capturedRules *string
	policyCalls   *int                                  // counts CreateACLPolicy raft writes
	tokenGone     bool                                  // GetACLToken misses, forcing a re-mint
	token         *nomad.ACLTokenResult                 // GetACLToken result override
	mint          func() (*nomad.ACLTokenResult, error) // CreateACLTokenWithPolicies override
	deletedTokens *[]string                             // records DeleteACLToken accessors
}

func (s *stubNomadAPI) CreateACLPolicy(_, _, _, rules string) error {
	if s.policyCalls != nil {
		*s.policyCalls++
	}
	*s.capturedRules = rules
	return nil
}

func (s *stubNomadAPI) CreateACLTokenWithPolicies(_, _ string, _ []string) (*nomad.ACLTokenResult, error) {
	if s.mint != nil {
		return s.mint()
	}
	return &nomad.ACLTokenResult{AccessorID: "test-accessor", SecretID: "test-secret"}, nil
}

func (s *stubNomadAPI) GetACLToken(_, _ string) (*nomad.ACLTokenResult, error) {
	if s.tokenGone {
		return nil, nil
	}
	if s.token != nil {
		return s.token, nil
	}
	return &nomad.ACLTokenResult{AccessorID: "test-accessor", SecretID: "test-secret"}, nil
}

func (s *stubNomadAPI) DeleteACLToken(_, accessor string) error {
	if s.deletedTokens != nil {
		*s.deletedTokens = append(*s.deletedTokens, accessor)
	}
	return nil
}

var _ = Describe("NomadAutoscaler Controller", func() {
	Context("Missing NomadCluster Reference", func() {
		var (
			ctx        context.Context
			namespace  string
			autoscaler *nomadv1alpha1.NomadAutoscaler
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = fmt.Sprintf("test-autoscaler-missing-cluster-%d", time.Now().UnixNano())
			createTestNamespace(ctx, namespace)
		})

		AfterEach(func() {
			if autoscaler != nil {
				_ = k8sClient.Delete(ctx, autoscaler)
			}
		})

		It("should set error condition when cluster doesn't exist", func() {
			autoscaler = newTestAutoscaler(namespace, "test-autoscaler", "non-existent-cluster")
			Expect(k8sClient.Create(ctx, autoscaler)).To(Succeed())

			nsName := types.NamespacedName{Name: autoscaler.Name, Namespace: namespace}

			By("First reconcile to add finalizer")
			result, err := reconcileAutoscaler(ctx, nsName, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(time.Second))

			By("Second reconcile to check cluster")
			result, err = reconcileAutoscaler(ctx, nsName, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			Expect(k8sClient.Get(ctx, nsName, autoscaler)).To(Succeed())
			var found bool
			for _, cond := range autoscaler.Status.Conditions {
				if cond.Type == "Ready" && cond.Status == metav1.ConditionFalse && cond.Reason == "ClusterNotFound" {
					found = true
				}
			}
			Expect(found).To(BeTrue(), "Expected Ready=False condition with ClusterNotFound reason")
		})
	})

	Context("Cluster Not Bootstrapped", func() {
		var (
			ctx        context.Context
			namespace  string
			cluster    *nomadv1alpha1.NomadCluster
			autoscaler *nomadv1alpha1.NomadAutoscaler
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = fmt.Sprintf("test-autoscaler-not-bootstrapped-%d", time.Now().UnixNano())
			createTestNamespace(ctx, namespace)
			createLicenseSecret(ctx, namespace)
		})

		AfterEach(func() {
			if autoscaler != nil {
				_ = k8sClient.Delete(ctx, autoscaler)
			}
			if cluster != nil {
				_ = k8sClient.Delete(ctx, cluster)
			}
		})

		It("should wait when cluster ACL is not bootstrapped", func() {
			cluster = newTestCluster(namespace, "nomad")
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			autoscaler = newTestAutoscaler(namespace, "test-autoscaler", "nomad")
			Expect(k8sClient.Create(ctx, autoscaler)).To(Succeed())

			nsName := types.NamespacedName{Name: autoscaler.Name, Namespace: namespace}

			for i := 0; i < 2; i++ {
				_, err := reconcileAutoscaler(ctx, nsName, nil)
				Expect(err).NotTo(HaveOccurred())
			}

			Expect(k8sClient.Get(ctx, nsName, autoscaler)).To(Succeed())
			var found bool
			for _, cond := range autoscaler.Status.Conditions {
				if cond.Type == "Ready" && cond.Status == metav1.ConditionFalse && cond.Reason == "WaitingForACLBootstrap" {
					found = true
				}
			}
			Expect(found).To(BeTrue(), "Expected Ready=False condition with WaitingForACLBootstrap reason")
		})
	})

	Context("Full reconcile with mocked Nomad API", func() {
		var (
			ctx           context.Context
			namespace     string
			cluster       *nomadv1alpha1.NomadCluster
			autoscaler    *nomadv1alpha1.NomadAutoscaler
			capturedRules string
			factory       func(nomad.ClientConfig) (nomad.NomadAPI, error)
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = fmt.Sprintf("test-autoscaler-full-%d", time.Now().UnixNano())
			createTestNamespace(ctx, namespace)
			createLicenseSecret(ctx, namespace)

			cluster = newTestCluster(namespace, "nomad")
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
			cluster.Status.ACLBootstrapped = true
			cluster.Status.ACLBootstrapSecretName = testACLBootstrapSecretName
			Expect(k8sClient.Status().Update(ctx, cluster)).To(Succeed())

			createBootstrapSecret(ctx, namespace, testACLBootstrapSecretName)
			createBootstrapSecret(ctx, namespace, "nomad-operator-management")
			createTLSSecret(ctx, namespace, "nomad")

			capturedRules = ""
			//nolint:unparam // signature fixed by NomadClientFactory
			factory = func(_ nomad.ClientConfig) (nomad.NomadAPI, error) {
				return &stubNomadAPI{capturedRules: &capturedRules}, nil
			}
		})

		AfterEach(func() {
			if autoscaler != nil {
				_ = k8sClient.Delete(ctx, autoscaler)
			}
			if cluster != nil {
				_ = k8sClient.Delete(ctx, cluster)
			}
		})

		reconcileToSteadyState := func(nsName types.NamespacedName) {
			// Finalizer, then full pass.
			for i := 0; i < 2; i++ {
				_, err := reconcileAutoscaler(ctx, nsName, factory)
				Expect(err).NotTo(HaveOccurred())
			}
		}

		It("should create all child resources for a single-replica instance", func() {
			autoscaler = newTestAutoscaler(namespace, "as", "nomad")
			Expect(k8sClient.Create(ctx, autoscaler)).To(Succeed())
			nsName := types.NamespacedName{Name: autoscaler.Name, Namespace: namespace}

			reconcileToSteadyState(nsName)

			By("ConfigMap holds the rendered agent HCL")
			cm := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "as-autoscaler-config", Namespace: namespace}, cm)).To(Succeed())
			hcl := cm.Data["autoscaler.hcl"]
			Expect(hcl).To(ContainSubstring(fmt.Sprintf("https://nomad-internal.%s.svc:4646", namespace)))
			Expect(hcl).To(ContainSubstring(`namespace = "default"`))
			Expect(hcl).To(ContainSubstring("prometheus_metrics = true"))
			Expect(hcl).NotTo(ContainSubstring("high_availability"), "single replica must not render the HA block")

			By("token Secret carries the minted token under the shared keys")
			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "as-autoscaler-token", Namespace: namespace}, secret)).To(Succeed())
			Expect(string(secret.Data["secret-id"])).To(Equal("test-secret"))
			Expect(string(secret.Data["accessor-id"])).To(Equal("test-accessor"))

			By("Deployment runs the enterprise image with config checksum and surge rollout")
			deploy := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "as-autoscaler-agent", Namespace: namespace}, deploy)).To(Succeed())
			Expect(*deploy.Spec.Replicas).To(Equal(int32(1)))
			container := deploy.Spec.Template.Spec.Containers[0]
			Expect(container.Image).To(Equal("hashicorp/nomad-autoscaler-enterprise:0.5.0-ent"))
			Expect(container.ImagePullPolicy).To(Equal(corev1.PullAlways),
				"apiserver-defaulted pullPolicy must reach the pod (retag defence)")
			Expect(container.Command).To(ContainElement("nomad-autoscaler"))
			Expect(deploy.Spec.Template.Annotations).To(HaveKey("checksum/config"))
			Expect(deploy.Spec.Strategy.RollingUpdate.MaxUnavailable.IntValue()).To(Equal(0))
			Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil(), "single replica needs no anti-affinity")

			By("no PodDisruptionBudget for a single replica")
			pdb := &policyv1.PodDisruptionBudget{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: "as-autoscaler", Namespace: namespace}, pdb)
			Expect(err).To(HaveOccurred())

			By("metrics Service is created")
			svc := &corev1.Service{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "as-autoscaler-metrics", Namespace: namespace}, svc)).To(Succeed())
			Expect(svc.Labels).To(HaveKeyWithValue("nomad.hashicorp.com/metrics", "true"))

			By("minted policy grants scale on the default namespace and node read")
			Expect(capturedRules).To(ContainSubstring(`namespace "default"`))
			Expect(capturedRules).To(ContainSubstring(`policy = "scale"`))
			Expect(capturedRules).To(ContainSubstring("node {"))
			Expect(capturedRules).NotTo(ContainSubstring("submit-recommendation"), "DAS disabled must not grant recommendations")
			Expect(capturedRules).NotTo(ContainSubstring("variables"), "single replica must not grant the lock variable")

			By("status records the child resources")
			Expect(k8sClient.Get(ctx, nsName, autoscaler)).To(Succeed())
			Expect(autoscaler.Status.TokenAccessorID).To(Equal("test-accessor"))
			Expect(autoscaler.Status.PolicyName).To(Equal("autoscaler-agent-" + namespace + "-as"))
			Expect(autoscaler.Status.DeploymentName).To(Equal("as-autoscaler-agent"))
		})

		It("should render HA config, lock ACL, PDB, and anti-affinity for replicas > 1", func() {
			autoscaler = newTestAutoscaler(namespace, "ha", "nomad")
			autoscaler.Spec.Replicas = 2
			autoscaler.Spec.DynamicApplicationSizing.Enabled = true
			autoscaler.Spec.DynamicApplicationSizing.PrometheusURL = "http://das-prometheus:9090"
			autoscaler.Spec.Namespaces = []string{"payments"}
			Expect(k8sClient.Create(ctx, autoscaler)).To(Succeed())
			nsName := types.NamespacedName{Name: autoscaler.Name, Namespace: namespace}

			reconcileToSteadyState(nsName)

			By("agent HCL renders the HA block with the per-instance lock path")
			cm := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "ha-autoscaler-config", Namespace: namespace}, cm)).To(Succeed())
			hcl := cm.Data["autoscaler.hcl"]
			Expect(hcl).To(ContainSubstring("high_availability"))
			Expect(hcl).To(ContainSubstring(fmt.Sprintf("nomad-autoscaler/%s/ha/lock", namespace)))
			Expect(hcl).To(ContainSubstring(`namespace = "payments"`))

			By("policy grants scale+DAS on payments and the lock variable in the lock namespace")
			Expect(capturedRules).To(ContainSubstring(`namespace "payments"`))
			Expect(capturedRules).To(ContainSubstring("submit-recommendation"))
			Expect(capturedRules).To(ContainSubstring(`namespace "default"`))
			Expect(capturedRules).To(ContainSubstring(fmt.Sprintf("nomad-autoscaler/%s/ha/lock", namespace)))

			By("Deployment gets 2 replicas and anti-affinity")
			deploy := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "ha-autoscaler-agent", Namespace: namespace}, deploy)).To(Succeed())
			Expect(*deploy.Spec.Replicas).To(Equal(int32(2)))
			Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())

			By("PodDisruptionBudget protects the standby")
			pdb := &policyv1.PodDisruptionBudget{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "ha-autoscaler", Namespace: namespace}, pdb)).To(Succeed())
			Expect(pdb.Spec.MinAvailable.IntValue()).To(Equal(1))
		})

		It("should remove the PDB when replicas drops back to 1", func() {
			autoscaler = newTestAutoscaler(namespace, "shrink", "nomad")
			autoscaler.Spec.Replicas = 2
			Expect(k8sClient.Create(ctx, autoscaler)).To(Succeed())
			nsName := types.NamespacedName{Name: autoscaler.Name, Namespace: namespace}

			reconcileToSteadyState(nsName)

			pdb := &policyv1.PodDisruptionBudget{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "shrink-autoscaler", Namespace: namespace}, pdb)).To(Succeed())

			Expect(k8sClient.Get(ctx, nsName, autoscaler)).To(Succeed())
			autoscaler.Spec.Replicas = 1
			Expect(k8sClient.Update(ctx, autoscaler)).To(Succeed())

			_, err := reconcileAutoscaler(ctx, nsName, factory)
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, types.NamespacedName{Name: "shrink-autoscaler", Namespace: namespace}, pdb)
			Expect(err).To(HaveOccurred(), "PDB must be deleted when HA mode is off")
		})

		It("rolls the agent Deployment when the token is re-minted, and only then (neo-2um.16)", func() {
			autoscaler = newTestAutoscaler(namespace, "remint", "nomad")
			Expect(k8sClient.Create(ctx, autoscaler)).To(Succeed())
			nsName := types.NamespacedName{Name: autoscaler.Name, Namespace: namespace}
			deployName := types.NamespacedName{Name: "remint-autoscaler-agent", Namespace: namespace}

			reconcileToSteadyState(nsName)

			deploy := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, deployName, deploy)).To(Succeed())
			initialSecrets := deploy.Spec.Template.Annotations["checksum/secrets"]
			initialConfig := deploy.Spec.Template.Annotations["checksum/config"]
			Expect(initialSecrets).NotTo(BeEmpty())

			By("re-minting after the recorded token vanished from Nomad")
			rotated := &nomad.ACLTokenResult{AccessorID: "accessor-2", SecretID: "rotated-secret"}
			remintFactory := func(_ nomad.ClientConfig) (nomad.NomadAPI, error) {
				return &stubNomadAPI{
					capturedRules: &capturedRules,
					tokenGone:     true,
					mint:          func() (*nomad.ACLTokenResult, error) { return rotated, nil },
				}, nil
			}
			_, err := reconcileAutoscaler(ctx, nsName, remintFactory)
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, deployName, deploy)).To(Succeed())
			Expect(deploy.Spec.Template.Annotations["checksum/secrets"]).NotTo(Equal(initialSecrets),
				"a token re-mint must perturb the pod template so the Deployment rolls")
			Expect(deploy.Spec.Template.Annotations["checksum/config"]).To(Equal(initialConfig))
			rotatedSecrets := deploy.Spec.Template.Annotations["checksum/secrets"]

			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "remint-autoscaler-token", Namespace: namespace}, secret)).To(Succeed())
			Expect(string(secret.Data["secret-id"])).To(Equal("rotated-secret"))

			By("a config-only change must not perturb the secrets checksum (no double roll)")
			Expect(k8sClient.Get(ctx, nsName, autoscaler)).To(Succeed())
			autoscaler.Spec.LogLevel = "DEBUG"
			Expect(k8sClient.Update(ctx, autoscaler)).To(Succeed())
			steadyFactory := func(_ nomad.ClientConfig) (nomad.NomadAPI, error) {
				return &stubNomadAPI{capturedRules: &capturedRules, token: rotated}, nil
			}
			_, err = reconcileAutoscaler(ctx, nsName, steadyFactory)
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, deployName, deploy)).To(Succeed())
			Expect(deploy.Spec.Template.Annotations["checksum/config"]).NotTo(Equal(initialConfig))
			Expect(deploy.Spec.Template.Annotations["checksum/secrets"]).To(Equal(rotatedSecrets))
		})

		It("skips the policy upsert at steady state and re-upserts on spec change (neo-2um.21)", func() {
			policyCalls := 0
			countingFactory := func(_ nomad.ClientConfig) (nomad.NomadAPI, error) {
				return &stubNomadAPI{capturedRules: &capturedRules, policyCalls: &policyCalls}, nil
			}

			autoscaler = newTestAutoscaler(namespace, "upsert", "nomad")
			Expect(k8sClient.Create(ctx, autoscaler)).To(Succeed())
			nsName := types.NamespacedName{Name: autoscaler.Name, Namespace: namespace}

			for i := 0; i < 2; i++ {
				_, err := reconcileAutoscaler(ctx, nsName, countingFactory)
				Expect(err).NotTo(HaveOccurred())
			}
			afterCreate := policyCalls
			Expect(afterCreate).To(BeNumerically(">=", 1), "the first full pass must upsert the policy")

			By("steady-state passes issue no raft write")
			for i := 0; i < 2; i++ {
				_, err := reconcileAutoscaler(ctx, nsName, countingFactory)
				Expect(err).NotTo(HaveOccurred())
			}
			Expect(policyCalls).To(Equal(afterCreate),
				"reconciles without a spec change must not upsert the ACL policy")

			By("a spec change re-upserts so the policy tracks the CR")
			Expect(k8sClient.Get(ctx, nsName, autoscaler)).To(Succeed())
			autoscaler.Spec.Namespaces = []string{"payments"}
			Expect(k8sClient.Update(ctx, autoscaler)).To(Succeed())
			_, err := reconcileAutoscaler(ctx, nsName, countingFactory)
			Expect(err).NotTo(HaveOccurred())
			Expect(policyCalls).To(Equal(afterCreate + 1))
			Expect(capturedRules).To(ContainSubstring(`namespace "payments"`))
		})

		It("mints exactly once when the mint response is lost to a network error (neo-2um.17)", func() {
			// An LB address makes the old in-helper retry reachable: the
			// spec proves the mint no longer takes that path.
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "nomad", Namespace: namespace}, cluster)).To(Succeed())
			cluster.Status.AdvertiseAddress = "10.0.0.100"
			Expect(k8sClient.Status().Update(ctx, cluster)).To(Succeed())

			mintCalls := 0
			lostFactory := func(_ nomad.ClientConfig) (nomad.NomadAPI, error) {
				return &stubNomadAPI{
					capturedRules: &capturedRules,
					mint: func() (*nomad.ACLTokenResult, error) {
						mintCalls++
						return nil, &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("connection refused")}
					},
				}, nil
			}

			autoscaler = newTestAutoscaler(namespace, "mintonce", "nomad")
			Expect(k8sClient.Create(ctx, autoscaler)).To(Succeed())
			nsName := types.NamespacedName{Name: autoscaler.Name, Namespace: namespace}

			for i := 0; i < 2; i++ {
				_, err := reconcileAutoscaler(ctx, nsName, lostFactory)
				Expect(err).NotTo(HaveOccurred())
			}

			Expect(mintCalls).To(Equal(1),
				"a network error on mint must not be retried within the pass — the create may have committed")
			Expect(k8sClient.Get(ctx, nsName, autoscaler)).To(Succeed())
			cond := meta.FindStatusCondition(autoscaler.Status.Conditions, "Ready")
			Expect(cond).NotTo(BeNil())
			Expect(cond.Reason).To(Equal("TokenCreationFailed"))
		})

		It("flips Ready when the management secret loses its secret-id (neo-2um.18)", func() {
			autoscaler = newTestAutoscaler(namespace, "emptymgmt", "nomad")
			Expect(k8sClient.Create(ctx, autoscaler)).To(Succeed())
			nsName := types.NamespacedName{Name: autoscaler.Name, Namespace: namespace}

			reconcileToSteadyState(nsName)

			// Author agent readiness so the CR is genuinely Ready first.
			deploy := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "emptymgmt-autoscaler-agent", Namespace: namespace}, deploy)).To(Succeed())
			deploy.Status.Replicas = 1
			deploy.Status.ReadyReplicas = 1
			Expect(k8sClient.Status().Update(ctx, deploy)).To(Succeed())
			_, err := reconcileAutoscaler(ctx, nsName, factory)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Get(ctx, nsName, autoscaler)).To(Succeed())
			Expect(meta.IsStatusConditionTrue(autoscaler.Status.Conditions, "Ready")).To(BeTrue())

			By("emptying the management secret's secret-id")
			mgmt := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "nomad-operator-management", Namespace: namespace}, mgmt)).To(Succeed())
			mgmt.Data["secret-id"] = nil
			Expect(k8sClient.Update(ctx, mgmt)).To(Succeed())

			_, err = reconcileAutoscaler(ctx, nsName, factory)
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, nsName, autoscaler)).To(Succeed())
			cond := meta.FindStatusCondition(autoscaler.Status.Conditions, "Ready")
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse), "a stalled reconcile must not keep reporting Ready=True")
			Expect(cond.Reason).To(Equal("WaitingForManagementToken"))
			Expect(cond.Message).To(ContainSubstring("empty secret-id"))
		})
	})

	Context("Cluster with ACLs disabled", func() {
		var (
			ctx        context.Context
			namespace  string
			cluster    *nomadv1alpha1.NomadCluster
			autoscaler *nomadv1alpha1.NomadAutoscaler
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = fmt.Sprintf("test-autoscaler-acls-disabled-%d", time.Now().UnixNano())
			createTestNamespace(ctx, namespace)
			createLicenseSecret(ctx, namespace)
		})

		AfterEach(func() {
			if autoscaler != nil {
				_ = k8sClient.Delete(ctx, autoscaler)
			}
			if cluster != nil {
				_ = k8sClient.Delete(ctx, cluster)
			}
		})

		It("reports the terminal ACLsDisabled reason with a single Warning (neo-2um.19)", func() {
			cluster = newTestCluster(namespace, "nomad")
			cluster.Spec.Server.ACL.Enabled = ptr.To(false)
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			autoscaler = newTestAutoscaler(namespace, "test-autoscaler", "nomad")
			Expect(k8sClient.Create(ctx, autoscaler)).To(Succeed())
			nsName := types.NamespacedName{Name: autoscaler.Name, Namespace: namespace}

			recorder := record.NewFakeRecorder(10)
			reconciler := &NomadAutoscalerReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: recorder,
			}
			// Finalizer pass, then two gated passes: the Warning must not
			// repeat per retry.
			for i := 0; i < 3; i++ {
				_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nsName})
				Expect(err).NotTo(HaveOccurred())
			}

			Expect(k8sClient.Get(ctx, nsName, autoscaler)).To(Succeed())
			cond := meta.FindStatusCondition(autoscaler.Status.Conditions, "Ready")
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal("ACLsDisabled"),
				"ACL-disabled must read as terminal misconfiguration, not an infinite bootstrap wait")

			events := drainEvents(recorder)
			Expect(events).To(HaveLen(1), "one Warning per transition, not per retry: %v", events)
			Expect(events[0]).To(ContainSubstring("Warning ACLsDisabled"))
		})
	})
})

// The status patch is the only durable record of a minted accessor: if
// it fails, the mint must be unwound or every retry of the failure
// leaks a fresh, permanently orphaned token (neo-2um.17). A fake
// client stands in because envtest cannot be made to fail a patch.
var _ = Describe("NomadAutoscaler token mint unwind (neo-2um.17)", func() {
	It("best-effort deletes the minted token when the status patch fails", func() {
		ctx := context.Background()
		autoscaler := newTestAutoscaler("mint-unwind", "as", "nomad")
		cluster := newTestCluster("mint-unwind", "nomad")
		tlsSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "nomad-tls", Namespace: "mint-unwind"},
			Data:       map[string][]byte{"ca.crt": []byte("test-ca")},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(k8sClient.Scheme()).
			WithObjects(autoscaler, cluster, tlsSecret).
			WithStatusSubresource(autoscaler).
			WithInterceptorFuncs(interceptor.Funcs{
				SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
					return fmt.Errorf("simulated status patch failure")
				},
			}).
			Build()

		deleted := []string{}
		capturedRules := ""
		r := &NomadAutoscalerReconciler{
			Client: fakeClient,
			Scheme: k8sClient.Scheme(),
			NomadClientFactory: func(nomad.ClientConfig) (nomad.NomadAPI, error) {
				return &stubNomadAPI{capturedRules: &capturedRules, deletedTokens: &deleted}, nil
			},
		}

		_, err := r.ensureAutoscalerToken(ctx, autoscaler, cluster, "root-token")
		Expect(err).To(MatchError(ContainSubstring("failed to patch status")))
		Expect(deleted).To(ConsistOf("test-accessor"),
			"the unrecorded mint must be unwound so retries cannot accumulate orphans")
	})
})
