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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
)

// A7 (neo-1u5): the in-code defaultTLSCertKey/defaultTLSKeyKey fallbacks were
// removed in favour of CRD defaulting. That removal is only safe if admission
// materialises the nested tls.crt/tls.key defaults when `secretKeys` is
// omitted entirely — which requires +kubebuilder:default={} on the parent
// field. This test pins that contract: if the {} default is ever dropped from
// the CRD, an omitted secretKeys would reach the controller with empty key
// names and certificate loading would silently look up "" in the Secret.
//
// SecretKeys stay user-configurable (B3 review decision): ESO/VSO-populated
// Secrets often don't follow the kubernetes.io/tls key convention.
var _ = Describe("CASecretKeys CRD defaulting", func() {
	const namespace = "secretkeys-defaulting-test"

	ctx := context.Background()

	BeforeEach(func() {
		createTestNamespace(ctx, namespace)
	})

	It("materialises tls.crt/tls.key when secretKeys is omitted", func() {
		cluster := &nomadv1alpha1.NomadCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "defaulting-check",
				Namespace: namespace,
			},
			Spec: nomadv1alpha1.NomadClusterSpec{
				Replicas: 1,
				License: nomadv1alpha1.LicenseSpec{
					SecretName: "nomad-license",
				},
				Server: nomadv1alpha1.ServerSpec{
					TLS: nomadv1alpha1.TLSSpec{
						CA: &nomadv1alpha1.CASpec{
							SecretName: "user-ca",
							// SecretKeys intentionally omitted — admission
							// must fill it via the {} default.
						},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

		fetched := &nomadv1alpha1.NomadCluster{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Name: "defaulting-check", Namespace: namespace,
		}, fetched)).To(Succeed())

		Expect(fetched.Spec.Server.TLS.CA.SecretKeys.Certificate).To(Equal("tls.crt"))
		Expect(fetched.Spec.Server.TLS.CA.SecretKeys.PrivateKey).To(Equal("tls.key"))

		Expect(k8sClient.Delete(ctx, fetched)).To(Succeed())
	})
})
