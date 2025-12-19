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
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
)

// Test helper functions

func createTestNamespace(ctx context.Context, name string) *corev1.Namespace {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	Expect(k8sClient.Create(ctx, ns)).To(Succeed())
	return ns
}

func createLicenseSecret(ctx context.Context, namespace, name string) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"license": []byte("test-license-key"),
		},
	}
	Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	return secret
}

func createTLSSecret(ctx context.Context, namespace, name string) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ca.crt":     []byte("-----BEGIN CERTIFICATE-----\ntest-ca\n-----END CERTIFICATE-----"),
			"server.crt": []byte("-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----"),
			"server.key": []byte("-----BEGIN RSA PRIVATE KEY-----\ntest-key\n-----END RSA PRIVATE KEY-----"),
		},
	}
	Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	return secret
}

func createGossipSecret(ctx context.Context, namespace, name, key string) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"gossip-key": []byte(key),
		},
	}
	Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	return secret
}

// newTestCluster creates a NomadCluster with sensible test defaults.
// IMPORTANT: Sets loadBalancerIP to bypass envtest's lack of LoadBalancer controller.
// IMPORTANT: Disables OpenShift features since envtest doesn't have Route CRDs.
func newTestCluster(namespace, name string) *nomadv1alpha1.NomadCluster {
	return &nomadv1alpha1.NomadCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: nomadv1alpha1.NomadClusterSpec{
			Replicas: 3,
			License: nomadv1alpha1.LicenseSpec{
				SecretName: "nomad-license",
			},
			Topology: nomadv1alpha1.TopologySpec{
				Region:     "us-west-1",
				Datacenter: "dc1",
			},
			// Set LoadBalancerIP to bypass AdvertiseResolver waiting for LB IP
			// envtest doesn't have a LoadBalancer controller
			Services: nomadv1alpha1.ServicesSpec{
				External: nomadv1alpha1.ExternalServiceSpec{
					LoadBalancerIP: "10.0.0.100",
				},
			},
			// Disable OpenShift features - envtest doesn't have Route/ServiceMonitor CRDs
			OpenShift: nomadv1alpha1.OpenShiftSpec{
				Enabled: false,
			},
		},
	}
}

func reconcileCluster(ctx context.Context, name types.NamespacedName) (reconcile.Result, error) {
	reconciler := &NomadClusterReconciler{
		Client:     k8sClient,
		Scheme:     k8sClient.Scheme(),
		RESTConfig: cfg,
	}
	return reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: name})
}

var _ = Describe("NomadCluster Controller", func() {
	const timeout = time.Second * 10
	const interval = time.Millisecond * 250

	Context("Happy Path - Minimal Valid Cluster", func() {
		var (
			ctx       context.Context
			namespace string
			cluster   *nomadv1alpha1.NomadCluster
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = fmt.Sprintf("test-happy-path-%d", time.Now().UnixNano())
			createTestNamespace(ctx, namespace)
			createLicenseSecret(ctx, namespace, "nomad-license")
		})

		AfterEach(func() {
			// Cleanup
			if cluster != nil {
				_ = k8sClient.Delete(ctx, cluster)
			}
			ns := &corev1.Namespace{}
			_ = k8sClient.Get(ctx, types.NamespacedName{Name: namespace}, ns)
			_ = k8sClient.Delete(ctx, ns)
		})

		It("should create all required resources", func() {
			By("Creating a NomadCluster resource")
			cluster = newTestCluster(namespace, "test-cluster")
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			namespacedName := types.NamespacedName{Name: "test-cluster", Namespace: namespace}

			By("Running reconciliation multiple times to progress through phases")
			// First reconcile - adds finalizer
			result, err := reconcileCluster(ctx, namespacedName)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(time.Second))

			// Continue reconciling until we get a stable state
			for i := 0; i < 10; i++ {
				result, err = reconcileCluster(ctx, namespacedName)
				if err != nil {
					break
				}
				if result.RequeueAfter == 30*time.Second {
					// Default requeue interval means reconciliation completed
					break
				}
			}

			By("Verifying ServiceAccount was created")
			sa := &corev1.ServiceAccount{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster",
					Namespace: namespace,
				}, sa)
			}, timeout, interval).Should(Succeed())

			By("Verifying Role was created")
			role := &rbacv1.Role{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster",
					Namespace: namespace,
				}, role)
			}, timeout, interval).Should(Succeed())

			By("Verifying RoleBinding was created")
			rb := &rbacv1.RoleBinding{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster",
					Namespace: namespace,
				}, rb)
			}, timeout, interval).Should(Succeed())

			By("Verifying headless Service was created")
			headlessSvc := &corev1.Service{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster-headless",
					Namespace: namespace,
				}, headlessSvc)
			}, timeout, interval).Should(Succeed())
			Expect(headlessSvc.Spec.ClusterIP).To(Equal("None"))

			By("Verifying internal Service was created")
			internalSvc := &corev1.Service{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster-internal",
					Namespace: namespace,
				}, internalSvc)
			}, timeout, interval).Should(Succeed())

			By("Verifying external Service was created")
			externalSvc := &corev1.Service{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster-external",
					Namespace: namespace,
				}, externalSvc)
			}, timeout, interval).Should(Succeed())
			Expect(externalSvc.Spec.Type).To(Equal(corev1.ServiceTypeLoadBalancer))

			By("Verifying gossip secret was auto-created")
			gossipSecret := &corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster-gossip",
					Namespace: namespace,
				}, gossipSecret)
			}, timeout, interval).Should(Succeed())
			Expect(gossipSecret.Data).To(HaveKey("gossip-key"))

			By("Verifying ConfigMap was created")
			cm := &corev1.ConfigMap{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster-config",
					Namespace: namespace,
				}, cm)
			}, timeout, interval).Should(Succeed())
			Expect(cm.Data).To(HaveKey("server.hcl"))
			Expect(cm.Data["server.hcl"]).To(ContainSubstring(`region     = "us-west-1"`))
			Expect(cm.Data["server.hcl"]).To(ContainSubstring(`datacenter = "dc1"`))

			By("Verifying StatefulSet was created")
			sts := &appsv1.StatefulSet{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster",
					Namespace: namespace,
				}, sts)
			}, timeout, interval).Should(Succeed())
			Expect(*sts.Spec.Replicas).To(Equal(int32(3)))

			By("Verifying cluster status is updated")
			updatedCluster := &nomadv1alpha1.NomadCluster{}
			Eventually(func() nomadv1alpha1.ClusterPhase {
				_ = k8sClient.Get(ctx, namespacedName, updatedCluster)
				return updatedCluster.Status.Phase
			}, timeout, interval).ShouldNot(Equal(nomadv1alpha1.ClusterPhase("")))
		})
	})

	Context("Missing License Secret", func() {
		var (
			ctx       context.Context
			namespace string
			cluster   *nomadv1alpha1.NomadCluster
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = fmt.Sprintf("test-missing-license-%d", time.Now().UnixNano())
			createTestNamespace(ctx, namespace)
			// Intentionally NOT creating the license secret
		})

		AfterEach(func() {
			if cluster != nil {
				_ = k8sClient.Delete(ctx, cluster)
			}
			ns := &corev1.Namespace{}
			_ = k8sClient.Get(ctx, types.NamespacedName{Name: namespace}, ns)
			_ = k8sClient.Delete(ctx, ns)
		})

		It("should fail reconciliation with clear error", func() {
			By("Creating a NomadCluster without license secret")
			cluster = newTestCluster(namespace, "test-cluster")
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			namespacedName := types.NamespacedName{Name: "test-cluster", Namespace: namespace}

			By("Running reconciliation")
			// First reconcile adds finalizer
			_, _ = reconcileCluster(ctx, namespacedName)
			// Second reconcile should fail at secrets phase
			result, err := reconcileCluster(ctx, namespacedName)

			By("Verifying reconciliation returns error")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("license secret"))
			Expect(result.RequeueAfter).To(Equal(30 * time.Second))

			By("Verifying status shows failure")
			updatedCluster := &nomadv1alpha1.NomadCluster{}
			Eventually(func() nomadv1alpha1.ClusterPhase {
				_ = k8sClient.Get(ctx, namespacedName, updatedCluster)
				return updatedCluster.Status.Phase
			}, timeout, interval).Should(Equal(nomadv1alpha1.ClusterPhaseFailed))
		})
	})

	Context("TLS Enabled - Missing TLS Secret", func() {
		var (
			ctx       context.Context
			namespace string
			cluster   *nomadv1alpha1.NomadCluster
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = fmt.Sprintf("test-missing-tls-%d", time.Now().UnixNano())
			createTestNamespace(ctx, namespace)
			createLicenseSecret(ctx, namespace, "nomad-license")
			// Intentionally NOT creating the TLS secret
		})

		AfterEach(func() {
			if cluster != nil {
				_ = k8sClient.Delete(ctx, cluster)
			}
			ns := &corev1.Namespace{}
			_ = k8sClient.Get(ctx, types.NamespacedName{Name: namespace}, ns)
			_ = k8sClient.Delete(ctx, ns)
		})

		It("should fail when TLS enabled but secret missing", func() {
			By("Creating a NomadCluster with TLS enabled but no TLS secret")
			cluster = newTestCluster(namespace, "test-cluster")
			cluster.Spec.Server.TLS.Enabled = true
			cluster.Spec.Server.TLS.SecretName = "nomad-tls"
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			namespacedName := types.NamespacedName{Name: "test-cluster", Namespace: namespace}

			By("Running reconciliation multiple times")
			for i := 0; i < 5; i++ {
				_, _ = reconcileCluster(ctx, namespacedName)
			}

			By("Verifying status shows failure")
			updatedCluster := &nomadv1alpha1.NomadCluster{}
			Eventually(func() nomadv1alpha1.ClusterPhase {
				_ = k8sClient.Get(ctx, namespacedName, updatedCluster)
				return updatedCluster.Status.Phase
			}, timeout, interval).Should(Equal(nomadv1alpha1.ClusterPhaseFailed))

			By("Verifying error message mentions TLS")
			Expect(updatedCluster.Status.Conditions).NotTo(BeEmpty())
			foundTLSError := false
			for _, cond := range updatedCluster.Status.Conditions {
				if cond.Type == nomadv1alpha1.ConditionTypeReady && cond.Status == metav1.ConditionFalse {
					if containsIgnoreCase(cond.Message, "TLS") || containsIgnoreCase(cond.Message, "tls") {
						foundTLSError = true
						break
					}
				}
			}
			Expect(foundTLSError).To(BeTrue(), "Expected TLS-related error in conditions")
		})
	})

	Context("TLS Enabled - Valid TLS Secret", func() {
		var (
			ctx       context.Context
			namespace string
			cluster   *nomadv1alpha1.NomadCluster
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = fmt.Sprintf("test-valid-tls-%d", time.Now().UnixNano())
			createTestNamespace(ctx, namespace)
			createLicenseSecret(ctx, namespace, "nomad-license")
			createTLSSecret(ctx, namespace, "nomad-tls")
		})

		AfterEach(func() {
			if cluster != nil {
				_ = k8sClient.Delete(ctx, cluster)
			}
			ns := &corev1.Namespace{}
			_ = k8sClient.Get(ctx, types.NamespacedName{Name: namespace}, ns)
			_ = k8sClient.Delete(ctx, ns)
		})

		It("should create resources with TLS configuration", func() {
			By("Creating a NomadCluster with TLS enabled")
			cluster = newTestCluster(namespace, "test-cluster")
			cluster.Spec.Server.TLS.Enabled = true
			cluster.Spec.Server.TLS.SecretName = "nomad-tls"
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			namespacedName := types.NamespacedName{Name: "test-cluster", Namespace: namespace}

			By("Running reconciliation")
			for i := 0; i < 10; i++ {
				result, err := reconcileCluster(ctx, namespacedName)
				if err != nil {
					Fail(fmt.Sprintf("Reconciliation failed with error: %v", err))
				}
				if !result.Requeue && result.RequeueAfter == 30*time.Second {
					break
				}
			}

			By("Verifying ConfigMap contains TLS configuration")
			cm := &corev1.ConfigMap{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster-config",
					Namespace: namespace,
				}, cm)
			}, timeout, interval).Should(Succeed())
			Expect(cm.Data["server.hcl"]).To(ContainSubstring("tls {"))
			Expect(cm.Data["server.hcl"]).To(ContainSubstring("http = true"))
			Expect(cm.Data["server.hcl"]).To(ContainSubstring("rpc  = true"))
			Expect(cm.Data["server.hcl"]).To(ContainSubstring(`ca_file   = "/nomad/tls/ca.crt"`))

			By("Verifying StatefulSet has TLS volume mount")
			sts := &appsv1.StatefulSet{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster",
					Namespace: namespace,
				}, sts)
			}, timeout, interval).Should(Succeed())

			// Check that TLS volume is present
			foundTLSVolume := false
			for _, vol := range sts.Spec.Template.Spec.Volumes {
				if vol.Name == "tls" {
					foundTLSVolume = true
					Expect(vol.Secret).NotTo(BeNil())
					Expect(vol.Secret.SecretName).To(Equal("nomad-tls"))
					break
				}
			}
			Expect(foundTLSVolume).To(BeTrue(), "Expected TLS volume in StatefulSet")
		})
	})

	Context("Gossip Key Auto-Generation", func() {
		var (
			ctx       context.Context
			namespace string
			cluster   *nomadv1alpha1.NomadCluster
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = fmt.Sprintf("test-gossip-auto-%d", time.Now().UnixNano())
			createTestNamespace(ctx, namespace)
			createLicenseSecret(ctx, namespace, "nomad-license")
		})

		AfterEach(func() {
			if cluster != nil {
				_ = k8sClient.Delete(ctx, cluster)
			}
			ns := &corev1.Namespace{}
			_ = k8sClient.Get(ctx, types.NamespacedName{Name: namespace}, ns)
			_ = k8sClient.Delete(ctx, ns)
		})

		It("should auto-generate gossip key when not specified", func() {
			By("Creating a NomadCluster without gossip.secretName")
			cluster = newTestCluster(namespace, "test-cluster")
			// Do not set cluster.Spec.Gossip.SecretName - let it auto-generate
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			namespacedName := types.NamespacedName{Name: "test-cluster", Namespace: namespace}

			By("Running reconciliation")
			for i := 0; i < 10; i++ {
				_, _ = reconcileCluster(ctx, namespacedName)
			}

			By("Verifying gossip secret was auto-created")
			gossipSecret := &corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster-gossip",
					Namespace: namespace,
				}, gossipSecret)
			}, timeout, interval).Should(Succeed())
			Expect(gossipSecret.Data).To(HaveKey("gossip-key"))

			// Verify key is valid base64 and correct length (32 bytes encoded)
			gossipKey := string(gossipSecret.Data["gossip-key"])
			Expect(gossipKey).To(HaveLen(44)) // 32 bytes in base64 = 44 chars

			By("Verifying owner reference is set")
			Expect(gossipSecret.OwnerReferences).NotTo(BeEmpty())
			Expect(gossipSecret.OwnerReferences[0].Name).To(Equal("test-cluster"))
		})
	})

	Context("Gossip Key External Reference", func() {
		var (
			ctx       context.Context
			namespace string
			cluster   *nomadv1alpha1.NomadCluster
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = fmt.Sprintf("test-gossip-ext-%d", time.Now().UnixNano())
			createTestNamespace(ctx, namespace)
			createLicenseSecret(ctx, namespace, "nomad-license")
			createGossipSecret(ctx, namespace, "external-gossip", "my-external-key-1234567890123456789012")
		})

		AfterEach(func() {
			if cluster != nil {
				_ = k8sClient.Delete(ctx, cluster)
			}
			ns := &corev1.Namespace{}
			_ = k8sClient.Get(ctx, types.NamespacedName{Name: namespace}, ns)
			_ = k8sClient.Delete(ctx, ns)
		})

		It("should use existing gossip secret when specified", func() {
			By("Creating a NomadCluster with external gossip secret")
			cluster = newTestCluster(namespace, "test-cluster")
			cluster.Spec.Gossip.SecretName = "external-gossip"
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			namespacedName := types.NamespacedName{Name: "test-cluster", Namespace: namespace}

			By("Running reconciliation")
			for i := 0; i < 10; i++ {
				_, _ = reconcileCluster(ctx, namespacedName)
			}

			By("Verifying no auto-generated secret was created")
			autoSecret := &corev1.Secret{}
			err := k8sClient.Get(ctx, types.NamespacedName{
				Name:      "test-cluster-gossip",
				Namespace: namespace,
			}, autoSecret)
			Expect(errors.IsNotFound(err)).To(BeTrue(), "Auto-generated gossip secret should not exist")

			By("Verifying ConfigMap uses the external gossip key")
			cm := &corev1.ConfigMap{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster-config",
					Namespace: namespace,
				}, cm)
			}, timeout, interval).Should(Succeed())
			Expect(cm.Data["server.hcl"]).To(ContainSubstring("my-external-key"))
		})
	})

	Context("ACL Enabled", func() {
		var (
			ctx       context.Context
			namespace string
			cluster   *nomadv1alpha1.NomadCluster
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = fmt.Sprintf("test-acl-%d", time.Now().UnixNano())
			createTestNamespace(ctx, namespace)
			createLicenseSecret(ctx, namespace, "nomad-license")
		})

		AfterEach(func() {
			if cluster != nil {
				_ = k8sClient.Delete(ctx, cluster)
			}
			ns := &corev1.Namespace{}
			_ = k8sClient.Get(ctx, types.NamespacedName{Name: namespace}, ns)
			_ = k8sClient.Delete(ctx, ns)
		})

		It("should configure ACL in generated HCL", func() {
			By("Creating a NomadCluster with ACL enabled")
			cluster = newTestCluster(namespace, "test-cluster")
			cluster.Spec.Server.ACL.Enabled = true
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			namespacedName := types.NamespacedName{Name: "test-cluster", Namespace: namespace}

			By("Running reconciliation")
			for i := 0; i < 10; i++ {
				_, _ = reconcileCluster(ctx, namespacedName)
			}

			By("Verifying ConfigMap contains ACL configuration")
			cm := &corev1.ConfigMap{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster-config",
					Namespace: namespace,
				}, cm)
			}, timeout, interval).Should(Succeed())
			Expect(cm.Data["server.hcl"]).To(ContainSubstring("acl {"))
			Expect(cm.Data["server.hcl"]).To(ContainSubstring("enabled = true"))
		})
	})

	Context("Default Values Applied", func() {
		var (
			ctx       context.Context
			namespace string
			cluster   *nomadv1alpha1.NomadCluster
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = fmt.Sprintf("test-defaults-%d", time.Now().UnixNano())
			createTestNamespace(ctx, namespace)
			createLicenseSecret(ctx, namespace, "nomad-license")
		})

		AfterEach(func() {
			if cluster != nil {
				_ = k8sClient.Delete(ctx, cluster)
			}
			ns := &corev1.Namespace{}
			_ = k8sClient.Get(ctx, types.NamespacedName{Name: namespace}, ns)
			_ = k8sClient.Delete(ctx, ns)
		})

		It("should apply default region and datacenter", func() {
			By("Creating a NomadCluster with minimal spec")
			cluster = &nomadv1alpha1.NomadCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: namespace,
				},
				Spec: nomadv1alpha1.NomadClusterSpec{
					License: nomadv1alpha1.LicenseSpec{
						SecretName: "nomad-license",
					},
					// Leave topology empty to test defaults
					// Set LoadBalancerIP to bypass AdvertiseResolver waiting for LB IP
					Services: nomadv1alpha1.ServicesSpec{
						External: nomadv1alpha1.ExternalServiceSpec{
							LoadBalancerIP: "10.0.0.200",
						},
					},
					// Disable OpenShift features - envtest doesn't have Route/ServiceMonitor CRDs
					OpenShift: nomadv1alpha1.OpenShiftSpec{
						Enabled: false,
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			namespacedName := types.NamespacedName{Name: "test-cluster", Namespace: namespace}

			By("Running reconciliation")
			for i := 0; i < 10; i++ {
				_, _ = reconcileCluster(ctx, namespacedName)
			}

			By("Verifying ConfigMap uses default values")
			cm := &corev1.ConfigMap{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster-config",
					Namespace: namespace,
				}, cm)
			}, timeout, interval).Should(Succeed())

			// Default region is "global"
			Expect(cm.Data["server.hcl"]).To(ContainSubstring(`region     = "global"`))
			// Default datacenter should be namespace name
			Expect(cm.Data["server.hcl"]).To(ContainSubstring(fmt.Sprintf(`datacenter = "%s"`, namespace)))
		})
	})

	Context("Cluster Deletion", func() {
		var (
			ctx       context.Context
			namespace string
			cluster   *nomadv1alpha1.NomadCluster
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = fmt.Sprintf("test-deletion-%d", time.Now().UnixNano())
			createTestNamespace(ctx, namespace)
			createLicenseSecret(ctx, namespace, "nomad-license")
		})

		AfterEach(func() {
			ns := &corev1.Namespace{}
			_ = k8sClient.Get(ctx, types.NamespacedName{Name: namespace}, ns)
			_ = k8sClient.Delete(ctx, ns)
		})

		It("should handle deletion with finalizer", func() {
			By("Creating a NomadCluster")
			cluster = newTestCluster(namespace, "test-cluster")
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			namespacedName := types.NamespacedName{Name: "test-cluster", Namespace: namespace}

			By("Running reconciliation to add finalizer")
			_, _ = reconcileCluster(ctx, namespacedName)

			By("Verifying finalizer was added")
			updatedCluster := &nomadv1alpha1.NomadCluster{}
			Eventually(func() bool {
				_ = k8sClient.Get(ctx, namespacedName, updatedCluster)
				for _, f := range updatedCluster.Finalizers {
					if f == "nomad.hashicorp.com/finalizer" {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())

			By("Deleting the cluster")
			Expect(k8sClient.Delete(ctx, cluster)).To(Succeed())

			By("Running reconciliation to handle deletion")
			_, err := reconcileCluster(ctx, namespacedName)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying cluster is deleted")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, namespacedName, &nomadv1alpha1.NomadCluster{})
				return errors.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())
		})
	})

	Context("StatefulSet Replicas Update", func() {
		var (
			ctx       context.Context
			namespace string
			cluster   *nomadv1alpha1.NomadCluster
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = fmt.Sprintf("test-replicas-%d", time.Now().UnixNano())
			createTestNamespace(ctx, namespace)
			createLicenseSecret(ctx, namespace, "nomad-license")
		})

		AfterEach(func() {
			if cluster != nil {
				_ = k8sClient.Delete(ctx, cluster)
			}
			ns := &corev1.Namespace{}
			_ = k8sClient.Get(ctx, types.NamespacedName{Name: namespace}, ns)
			_ = k8sClient.Delete(ctx, ns)
		})

		It("should update StatefulSet when replicas change", func() {
			By("Creating a NomadCluster with 3 replicas")
			cluster = newTestCluster(namespace, "test-cluster")
			cluster.Spec.Replicas = 3
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			namespacedName := types.NamespacedName{Name: "test-cluster", Namespace: namespace}

			By("Running initial reconciliation")
			for i := 0; i < 10; i++ {
				_, _ = reconcileCluster(ctx, namespacedName)
			}

			By("Verifying StatefulSet has 3 replicas")
			sts := &appsv1.StatefulSet{}
			Eventually(func() int32 {
				_ = k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster",
					Namespace: namespace,
				}, sts)
				if sts.Spec.Replicas == nil {
					return 0
				}
				return *sts.Spec.Replicas
			}, timeout, interval).Should(Equal(int32(3)))

			By("Updating cluster to 5 replicas")
			updatedCluster := &nomadv1alpha1.NomadCluster{}
			Expect(k8sClient.Get(ctx, namespacedName, updatedCluster)).To(Succeed())
			updatedCluster.Spec.Replicas = 5
			Expect(k8sClient.Update(ctx, updatedCluster)).To(Succeed())

			By("Running reconciliation after update")
			for i := 0; i < 10; i++ {
				_, _ = reconcileCluster(ctx, namespacedName)
			}

			By("Verifying StatefulSet now has 5 replicas")
			Eventually(func() int32 {
				_ = k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster",
					Namespace: namespace,
				}, sts)
				if sts.Spec.Replicas == nil {
					return 0
				}
				return *sts.Spec.Replicas
			}, timeout, interval).Should(Equal(int32(5)))

			By("Verifying ConfigMap has updated bootstrap_expect")
			cm := &corev1.ConfigMap{}
			Eventually(func() bool {
				_ = k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-cluster-config",
					Namespace: namespace,
				}, cm)
				return containsString(cm.Data["server.hcl"], "bootstrap_expect = 5")
			}, timeout, interval).Should(BeTrue())
		})
	})
})

// Helper functions for assertions

func containsIgnoreCase(s, substr string) bool {
	return containsString(s, substr)
}

func containsString(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
