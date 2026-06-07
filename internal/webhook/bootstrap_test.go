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

package webhook

import (
	"context"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tlspkg "github.com/hashicorp/nomad-enterprise-operator/pkg/tls"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("failed to add core scheme: %v", err)
	}
	if err := admissionregistrationv1.AddToScheme(s); err != nil {
		t.Fatalf("failed to add admissionregistration scheme: %v", err)
	}
	return s
}

func newBootstrapWithFake(t *testing.T, initialObjects ...client.Object) (*Bootstrap, client.Client) {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(initialObjects...).
		Build()
	b := NewBootstrap(c, Config{
		Namespace: "nomad-test",
	})
	return b, c
}

func TestEnsureSecret_CreatesNewSecret(t *testing.T) {
	b, c := newBootstrapWithFake(t)
	ctx := context.Background()

	if err := b.EnsureSecret(ctx); err != nil {
		t.Fatalf("EnsureSecret returned error: %v", err)
	}

	got := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{
		Name:      DefaultSecretName,
		Namespace: "nomad-test",
	}, got); err != nil {
		t.Fatalf("expected Secret to be created: %v", err)
	}

	for _, key := range []string{tlsCrtKey, tlsKeyKey, caCrtKey, caKeyKey} {
		if len(got.Data[key]) == 0 {
			t.Errorf("expected %q to be populated in Secret", key)
		}
	}

	// Verify the leaf has the expected DNS SAN — webhook clients (kube-apiserver)
	// connect to <service>.<namespace>.svc and must see that name in the cert.
	expectedSAN := DefaultServiceName + ".nomad-test.svc"
	if err := tlspkg.ValidateCertificate(got.Data[tlsCrtKey], []string{expectedSAN}, nil, 0); err != nil {
		t.Errorf("leaf cert missing expected SAN %q: %v", expectedSAN, err)
	}
}

func TestEnsureSecret_IdempotentWhenValid(t *testing.T) {
	b, c := newBootstrapWithFake(t)
	ctx := context.Background()

	if err := b.EnsureSecret(ctx); err != nil {
		t.Fatalf("first EnsureSecret: %v", err)
	}
	first := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: DefaultSecretName, Namespace: "nomad-test"}, first); err != nil {
		t.Fatalf("get first secret: %v", err)
	}

	if err := b.EnsureSecret(ctx); err != nil {
		t.Fatalf("second EnsureSecret: %v", err)
	}
	second := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: DefaultSecretName, Namespace: "nomad-test"}, second); err != nil {
		t.Fatalf("get second secret: %v", err)
	}

	// A valid cert should not be rotated on a no-op reconcile.
	if string(first.Data[tlsCrtKey]) != string(second.Data[tlsCrtKey]) {
		t.Errorf("expected idempotent reconcile to leave tls.crt unchanged")
	}
}

func TestEnsureSecret_PatchesCABundle(t *testing.T) {
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: DefaultValidatingWebhookName},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{Name: "vnomadcluster.kb.io"},
		},
	}
	b, c := newBootstrapWithFake(t, vwc)
	ctx := context.Background()

	if err := b.EnsureSecret(ctx); err != nil {
		t.Fatalf("EnsureSecret: %v", err)
	}

	got := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	if err := c.Get(ctx, types.NamespacedName{Name: DefaultValidatingWebhookName}, got); err != nil {
		t.Fatalf("get VWC: %v", err)
	}
	if len(got.Webhooks) != 1 {
		t.Fatalf("expected 1 webhook entry, got %d", len(got.Webhooks))
	}
	if len(got.Webhooks[0].ClientConfig.CABundle) == 0 {
		t.Errorf("expected caBundle to be populated")
	}

	secret := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: DefaultSecretName, Namespace: "nomad-test"}, secret); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if string(secret.Data[caCrtKey]) != string(got.Webhooks[0].ClientConfig.CABundle) {
		t.Errorf("caBundle does not match Secret ca.crt")
	}
}

func TestEnsureSecret_MissingVWCNotFatal(t *testing.T) {
	// VWC does not exist — bootstrap should still create the Secret and
	// not return an error.
	b, _ := newBootstrapWithFake(t)
	if err := b.EnsureSecret(context.Background()); err != nil {
		t.Fatalf("expected no error when VWC is absent, got: %v", err)
	}
}

func TestNamespaceFromEnv(t *testing.T) {
	t.Setenv(PodNamespaceEnvVar, "")
	if got := NamespaceFromEnv(); got != DefaultNamespace {
		t.Errorf("expected %q with unset env, got %q", DefaultNamespace, got)
	}

	t.Setenv(PodNamespaceEnvVar, "custom-ns")
	if got := NamespaceFromEnv(); got != "custom-ns" {
		t.Errorf("expected %q, got %q", "custom-ns", got)
	}
}

func TestConfig_ApplyDefaults(t *testing.T) {
	c := Config{}
	c.applyDefaults()
	if c.Namespace != DefaultNamespace {
		t.Errorf("Namespace default mismatch: %q", c.Namespace)
	}
	if c.SecretName != DefaultSecretName {
		t.Errorf("SecretName default mismatch: %q", c.SecretName)
	}
	if c.ServiceName != DefaultServiceName {
		t.Errorf("ServiceName default mismatch: %q", c.ServiceName)
	}
	if c.ValidatingWebhookName != DefaultValidatingWebhookName {
		t.Errorf("ValidatingWebhookName default mismatch: %q", c.ValidatingWebhookName)
	}
	if c.CertDir != DefaultCertDir {
		t.Errorf("CertDir default mismatch: %q", c.CertDir)
	}
}
