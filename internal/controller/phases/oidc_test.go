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
	"testing"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestOIDCPhase_Disabled(t *testing.T) {
	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.OIDC = nil

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithRuntimeObjects(cluster).
		WithStatusSubresource(cluster).
		Build()

	phaseCtx := &PhaseContext{
		Client: fakeClient,
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}

	phase := NewOIDCPhase(phaseCtx)
	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
	if result.Requeue {
		t.Fatal("Execute() should not request requeue when OIDC is disabled")
	}
}

func TestOIDCPhase_CRDNotRegistered(t *testing.T) {
	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.OIDC = &nomadv1alpha1.OIDCSpec{
		Enabled: true,
		KeycloakRef: corev1.LocalObjectReference{
			Name: "my-keycloak",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithRuntimeObjects(cluster).
		WithStatusSubresource(cluster).
		Build()

	phaseCtx := &PhaseContext{
		Client: fakeClient,
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}

	phase := NewOIDCPhase(phaseCtx)
	result := phase.Execute(context.Background(), cluster)

	// Should requeue (not hard error) because Keycloak CRDs are not registered
	if result.Error != nil {
		t.Fatalf("Execute() should not return hard error when CRDs missing, got: %v", result.Error)
	}
	if !result.Requeue {
		t.Fatal("Execute() should request requeue when Keycloak CRDs are not available")
	}
}

func TestOIDCPhase_CreatesClientSecret(t *testing.T) {
	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.OIDC = &nomadv1alpha1.OIDCSpec{
		Enabled: true,
		KeycloakRef: corev1.LocalObjectReference{
			Name: "my-keycloak",
		},
	}
	cluster.Status.OIDC.ClientSecretName = ""

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithRuntimeObjects(cluster).
		WithStatusSubresource(cluster).
		Build()

	phaseCtx := &PhaseContext{
		Client: fakeClient,
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}

	phase := NewOIDCPhase(phaseCtx)
	// Execute will create the secret then requeue waiting for CRDs — that is acceptable
	_ = phase.Execute(context.Background(), cluster)

	// Verify the secret was created
	secret := &corev1.Secret{}
	err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster-oidc-client-secret",
		Namespace: "test-ns",
	}, secret)
	if err != nil {
		t.Fatalf("Failed to get OIDC client secret: %v", err)
	}

	// The fake client stores StringData in StringData (not Data)
	clientSecret := string(secret.Data["client-secret"])
	if clientSecret == "" {
		clientSecret = secret.StringData["client-secret"]
	}
	if clientSecret == "" {
		t.Fatal("OIDC client secret should have key 'client-secret' populated")
	}

	// Verify status was updated
	updatedCluster := &nomadv1alpha1.NomadCluster{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster",
		Namespace: "test-ns",
	}, updatedCluster); err != nil {
		t.Fatalf("Failed to re-fetch cluster: %v", err)
	}
	if updatedCluster.Status.OIDC.ClientSecretName != "test-cluster-oidc-client-secret" {
		t.Errorf("ClientSecretName = %q, want %q",
			updatedCluster.Status.OIDC.ClientSecretName, "test-cluster-oidc-client-secret")
	}
}

func TestOIDCPhase_ClientSecretIdempotent(t *testing.T) {
	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.OIDC = &nomadv1alpha1.OIDCSpec{
		Enabled: true,
		KeycloakRef: corev1.LocalObjectReference{
			Name: "my-keycloak",
		},
	}
	cluster.Status.OIDC.ClientSecretName = "test-cluster-oidc-client-secret"

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-oidc-client-secret",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"client-secret": []byte("existing-secret-value"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithRuntimeObjects(existingSecret, cluster).
		WithStatusSubresource(cluster).
		Build()

	phaseCtx := &PhaseContext{
		Client: fakeClient,
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}

	phase := NewOIDCPhase(phaseCtx)
	// Execute will read the existing secret and then requeue on CRD check
	_ = phase.Execute(context.Background(), cluster)

	// Verify the secret was not regenerated
	secret := &corev1.Secret{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster-oidc-client-secret",
		Namespace: "test-ns",
	}, secret); err != nil {
		t.Fatalf("Failed to get OIDC client secret: %v", err)
	}
	if string(secret.Data["client-secret"]) != "existing-secret-value" {
		t.Errorf("client-secret = %q, want %q",
			string(secret.Data["client-secret"]), "existing-secret-value")
	}
}

func TestOIDCPhase_DefaultBindingRules(t *testing.T) {
	rules := buildDefaultBindingRules()

	if len(rules) != 1 {
		t.Fatalf("expected 1 default binding rule, got %d", len(rules))
	}

	if rules[0].KeycloakGroup != "/nomad-admins" {
		t.Errorf("KeycloakGroup = %q, want %q", rules[0].KeycloakGroup, "/nomad-admins")
	}
	if rules[0].NomadRole != "nomad-admins" {
		t.Errorf("NomadRole = %q, want %q", rules[0].NomadRole, "nomad-admins")
	}
	if rules[0].PolicyRules == "" {
		t.Error("PolicyRules should not be empty")
	}
}

func TestOIDCPhase_BuildsRedirectURIs(t *testing.T) {
	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.OpenShift.Route.Enabled = true
	cluster.Status.RouteHost = "nomad.apps.example.com"

	phaseCtx := &PhaseContext{
		Log:              zap.New(zap.UseDevMode(true)),
		AdvertiseAddress: "10.0.0.1",
	}

	phase := NewOIDCPhase(phaseCtx)
	uris := phase.buildRedirectURIs(cluster)

	expected := []string{
		"http://localhost:4649/oidc/callback",
		"https://localhost:4646/ui/settings/tokens",
		"https://nomad.apps.example.com/ui/settings/tokens",
		"https://10.0.0.1:4646/ui/settings/tokens",
	}

	if len(uris) != len(expected) {
		t.Fatalf("expected %d redirect URIs, got %d: %v", len(expected), len(uris), uris)
	}

	for i, uri := range uris {
		if uri != expected[i] {
			t.Errorf("uri[%d] = %q, want %q", i, uri, expected[i])
		}
	}
}
