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
	"strings"
	"testing"

	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad/mocks"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

const testOperatorStatusName = "test-cluster-operator-status"

// TestACLBootstrapPhase_CreatesOperatorStatusToken is the F1 demonstration of
// the NomadAPI mock pattern. The behaviour is unchanged from the previous
// HTTPS-server-on-:4646 version: it asserts the same outcomes (no error / no
// requeue, Secret created with the expected accessor and secret IDs, status
// fields populated, owner reference set) but injects a mocks.MockNomadAPI via
// PhaseContext.NomadClientFactory rather than standing up a real Nomad
// endpoint.
func TestACLBootstrapPhase_CreatesOperatorStatusToken(t *testing.T) {
	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.ACL.Enabled = true
	// Both must be empty so neither idempotency guard fires
	cluster.Status.OperatorStatusSecretName = ""
	cluster.Status.OperatorStatusPolicyName = ""

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithRuntimeObjects(cluster).
		WithStatusSubresource(cluster).
		Build()

	mockNomad := mocks.NewMockNomadAPI(t)
	mockNomad.EXPECT().
		CreateACLPolicy(
			"test-bootstrap-token",
			testOperatorStatusName,
			"Operator day-2 status API access (operator:read, agent:read)",
			nomad.OperatorStatusPolicyRules,
		).
		Return(nil).
		Once()
	mockNomad.EXPECT().
		CreateACLTokenWithPolicies(
			"test-bootstrap-token",
			testOperatorStatusName,
			[]string{testOperatorStatusName},
		).
		Return(&nomad.ACLTokenResult{
			AccessorID: "test-accessor-id",
			SecretID:   "test-secret-id",
			Name:       testOperatorStatusName,
			Type:       "client",
		}, nil).
		Once()

	phaseCtx := &PhaseContext{
		Client: fakeClient,
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
		NomadClientFactory: func(_ nomad.ClientConfig) (nomad.NomadAPI, error) {
			return mockNomad, nil
		},
	}

	phase := NewACLBootstrapPhase(phaseCtx)

	result := phase.ensureOperatorStatusToken(context.Background(), cluster, "test-bootstrap-token")

	// 1. No error and no requeue
	if result.Error != nil {
		t.Fatalf("ensureOperatorStatusToken() error = %v, message = %s", result.Error, result.Message)
	}
	if result.Requeue {
		t.Fatal("ensureOperatorStatusToken() should not request requeue")
	}

	// 2. Secret exists
	secret := &corev1.Secret{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name:      testOperatorStatusName,
		Namespace: "test-ns",
	}, secret); err != nil {
		t.Fatalf("Failed to get operator status secret: %v", err)
	}

	// 3. accessor-id key
	// The fake client does not convert StringData→Data like a real API server,
	// so check both locations.
	accessorID := string(secret.Data["accessor-id"])
	if accessorID == "" {
		accessorID = secret.StringData["accessor-id"]
	}
	if accessorID != "test-accessor-id" {
		t.Errorf("accessor-id = %q, want %q", accessorID, "test-accessor-id")
	}

	// 4. secret-id key
	secretID := string(secret.Data["secret-id"])
	if secretID == "" {
		secretID = secret.StringData["secret-id"]
	}
	if secretID != "test-secret-id" {
		t.Errorf("secret-id = %q, want %q", secretID, "test-secret-id")
	}

	// 5. Status field: OperatorStatusSecretName
	// Re-fetch the cluster to see persisted status
	updatedCluster := cluster.DeepCopy()
	if err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster",
		Namespace: "test-ns",
	}, updatedCluster); err != nil {
		t.Fatalf("Failed to re-fetch cluster: %v", err)
	}
	if updatedCluster.Status.OperatorStatusSecretName != testOperatorStatusName {
		t.Errorf("OperatorStatusSecretName = %q, want %q",
			updatedCluster.Status.OperatorStatusSecretName, testOperatorStatusName)
	}

	// 6. Status field: OperatorStatusPolicyName
	if updatedCluster.Status.OperatorStatusPolicyName != testOperatorStatusName {
		t.Errorf("OperatorStatusPolicyName = %q, want %q",
			updatedCluster.Status.OperatorStatusPolicyName, testOperatorStatusName)
	}

	// Verify owner reference is set
	if len(secret.OwnerReferences) == 0 {
		t.Error("operator status secret should have an owner reference")
	} else {
		found := false
		for _, ref := range secret.OwnerReferences {
			if strings.Contains(ref.Name, "test-cluster") {
				found = true
				break
			}
		}
		if !found {
			t.Error("operator status secret owner reference should reference the cluster")
		}
	}
}

func TestACLBootstrapPhase_OperatorStatusTokenIdempotent(t *testing.T) {
	// Pre-existing operator status secret
	opSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testOperatorStatusName,
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"accessor-id": []byte("existing-accessor"),
			"secret-id":   []byte("existing-secret"),
		},
	}

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.ACL.Enabled = true
	cluster.Status.OperatorStatusSecretName = testOperatorStatusName
	cluster.Status.OperatorStatusPolicyName = testOperatorStatusName

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithRuntimeObjects(opSecret, cluster).
		WithStatusSubresource(cluster).
		Build()

	phaseCtx := &PhaseContext{
		Client: fakeClient,
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}

	phase := NewACLBootstrapPhase(phaseCtx)

	result := phase.ensureOperatorStatusToken(context.Background(), cluster, "bootstrap-token")

	if result.Error != nil {
		t.Fatalf("ensureOperatorStatusToken() error = %v", result.Error)
	}

	// Verify the existing secret was not modified
	secret := &corev1.Secret{}
	err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name:      testOperatorStatusName,
		Namespace: "test-ns",
	}, secret)
	if err != nil {
		t.Fatalf("Failed to get operator status secret: %v", err)
	}
	if string(secret.Data["accessor-id"]) != "existing-accessor" {
		t.Errorf("accessor-id = %q, want %q", string(secret.Data["accessor-id"]), "existing-accessor")
	}
	if string(secret.Data["secret-id"]) != "existing-secret" {
		t.Errorf("secret-id = %q, want %q", string(secret.Data["secret-id"]), "existing-secret")
	}
}

// TestObservedStateDiff_NoWriteWhenMatches covers C2 (neo-95g) /
// AC-2.5.1–3: the operator-owned ACL policies are reconciled via
// GET-then-write-on-diff, not unconditional upsert. The phase is driven
// through three reconcile invocations in the already-bootstrapped
// steady state:
//
//  1. policies missing → both written (bootstrap-equivalent create);
//  2. observed matches desired → ZERO write-method calls (AC-2.5.1);
//  3. manual edit to the anonymous policy between reconciles → exactly
//     that policy is written back to desired (AC-2.5.2 / AC-2.5.3).
//
// mocks.NewMockNomadAPI(t) fails the test on any call without a
// matching expectation, so invocation 2 having no CreateACLPolicy
// expectation IS the zero-writes assertion.
func TestObservedStateDiff_NoWriteWhenMatches(t *testing.T) {
	const bootstrapToken = "test-bootstrap-token"

	anonymousDesired := &nomad.ACLPolicyResult{
		Name:        "anonymous",
		Description: "Allow anonymous read access for cluster visibility",
		Rules:       nomad.AnonymousPolicyRules,
	}
	statusDesired := &nomad.ACLPolicyResult{
		Name:        testOperatorStatusName,
		Description: "Operator day-2 status API access (operator:read, agent:read)",
		Rules:       nomad.OperatorStatusPolicyRules,
	}

	// Steady state: bootstrap secret and operator-status secret exist,
	// status fields persisted — so Execute goes straight to policy
	// reconciliation with no token/bootstrap calls.
	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.ACL.Enabled = true
	cluster.Status.OperatorStatusSecretName = testOperatorStatusName
	cluster.Status.OperatorStatusPolicyName = testOperatorStatusName

	bootstrapSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      BootstrapSecretName("test-cluster"),
			Namespace: "test-ns",
		},
		Data: map[string][]byte{"secret-id": []byte(bootstrapToken)},
	}
	opSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testOperatorStatusName,
			Namespace: "test-ns",
		},
		Data: map[string][]byte{"secret-id": []byte("op-token")},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithRuntimeObjects(bootstrapSecret, opSecret, cluster).
		WithStatusSubresource(cluster).
		Build()

	mockNomad := mocks.NewMockNomadAPI(t)
	phase := NewACLBootstrapPhase(&PhaseContext{
		Client: fakeClient,
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
		NomadClientFactory: func(_ nomad.ClientConfig) (nomad.NomadAPI, error) {
			return mockNomad, nil
		},
	})

	// Invocation 1: policies missing — both created.
	mockNomad.EXPECT().GetACLPolicy(bootstrapToken, anonymousDesired.Name).Return(nil, nil).Once()
	mockNomad.EXPECT().CreateACLPolicy(bootstrapToken, anonymousDesired.Name, anonymousDesired.Description, anonymousDesired.Rules).Return(nil).Once()
	mockNomad.EXPECT().GetACLPolicy(bootstrapToken, statusDesired.Name).Return(nil, nil).Once()
	mockNomad.EXPECT().CreateACLPolicy(bootstrapToken, statusDesired.Name, statusDesired.Description, statusDesired.Rules).Return(nil).Once()

	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatalf("Execute() invocation 1 error = %v", result.Error)
	}

	// Invocation 2 (AC-2.5.1): observed matches desired — GETs only,
	// zero writes. No CreateACLPolicy expectation is registered, so any
	// write call fails the test.
	mockNomad.EXPECT().GetACLPolicy(bootstrapToken, anonymousDesired.Name).Return(anonymousDesired, nil).Once()
	mockNomad.EXPECT().GetACLPolicy(bootstrapToken, statusDesired.Name).Return(statusDesired, nil).Once()

	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatalf("Execute() invocation 2 error = %v", result.Error)
	}

	// Invocation 3 (AC-2.5.2 / AC-2.5.3): the anonymous policy was
	// manually edited between reconciles — it alone is written back to
	// desired; the untouched operator-status policy is not written.
	edited := &nomad.ACLPolicyResult{
		Name:        anonymousDesired.Name,
		Description: anonymousDesired.Description,
		Rules:       `namespace "default" { policy = "write" }`,
	}
	mockNomad.EXPECT().GetACLPolicy(bootstrapToken, anonymousDesired.Name).Return(edited, nil).Once()
	mockNomad.EXPECT().CreateACLPolicy(bootstrapToken, anonymousDesired.Name, anonymousDesired.Description, anonymousDesired.Rules).Return(nil).Once()
	mockNomad.EXPECT().GetACLPolicy(bootstrapToken, statusDesired.Name).Return(statusDesired, nil).Once()

	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatalf("Execute() invocation 3 error = %v", result.Error)
	}
}

// TestBootstrapSecretNoOwnerRef covers C3 (neo-gwt) / AC-2.4.1: the
// bootstrap-token Secret (and the external-bootstrap marker variant,
// which shares its name) is created WITHOUT an ownerReference — so
// Kubernetes GC cannot delete it before the finalizer's Nomad-side
// cleanup has used the token — and carries the cluster back-link label
// that the README orphan-cleanup procedure selects on.
func TestBootstrapSecretNoOwnerRef(t *testing.T) {
	assertC3Shape := func(t *testing.T, secret *corev1.Secret) {
		t.Helper()
		if n := len(secret.OwnerReferences); n != 0 {
			t.Errorf("bootstrap secret has %d ownerReferences, want 0", n)
		}
		if got := secret.Labels[BootstrapSecretClusterLabel]; got != "test-cluster" {
			t.Errorf("label %s = %q, want %q", BootstrapSecretClusterLabel, got, "test-cluster")
		}
	}

	t.Run("token secret", func(t *testing.T) {
		cluster := newTestCluster("test-cluster", "test-ns")
		fakeClient := fake.NewClientBuilder().WithScheme(scheme.Scheme).Build()
		phase := NewACLBootstrapPhase(&PhaseContext{
			Client: fakeClient,
			Scheme: scheme.Scheme,
			Log:    zap.New(zap.UseDevMode(true)),
		})

		result := phase.storeBootstrapToken(context.Background(), cluster,
			BootstrapSecretName("test-cluster"), &nomad.ACLBootstrapResult{
				AccessorID: "acc", SecretID: "sec", Name: "Bootstrap Token", Type: "management",
			})
		if result.Error != nil {
			t.Fatalf("storeBootstrapToken() error = %v", result.Error)
		}

		secret := &corev1.Secret{}
		if err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name: BootstrapSecretName("test-cluster"), Namespace: "test-ns",
		}, secret); err != nil {
			t.Fatalf("Failed to get bootstrap secret: %v", err)
		}
		assertC3Shape(t, secret)
	})

	t.Run("external-bootstrap marker secret", func(t *testing.T) {
		cluster := newTestCluster("test-cluster", "test-ns")
		fakeClient := fake.NewClientBuilder().WithScheme(scheme.Scheme).Build()
		phase := NewACLBootstrapPhase(&PhaseContext{
			Client: fakeClient,
			Scheme: scheme.Scheme,
			Log:    zap.New(zap.UseDevMode(true)),
		})

		result := phase.createMarkerSecret(context.Background(), cluster, BootstrapSecretName("test-cluster"))
		if result.Error != nil {
			t.Fatalf("createMarkerSecret() error = %v", result.Error)
		}

		secret := &corev1.Secret{}
		if err := fakeClient.Get(context.Background(), types.NamespacedName{
			Name: BootstrapSecretName("test-cluster"), Namespace: "test-ns",
		}, secret); err != nil {
			t.Fatalf("Failed to get marker secret: %v", err)
		}
		assertC3Shape(t, secret)
	})
}

// TestEnsureBootstrapSecretOwnership covers the C3 retrofit path: a
// pre-C3 bootstrap Secret (ownerReference present, cluster label
// missing) is migrated in place, and a second pass makes no further
// change.
func TestEnsureBootstrapSecretOwnership(t *testing.T) {
	cluster := newTestCluster("test-cluster", "test-ns")

	preC3 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      BootstrapSecretName("test-cluster"),
			Namespace: "test-ns",
			Labels:    GetLabels(cluster),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "nomad.hashicorp.com/v1alpha1",
				Kind:       "NomadCluster",
				Name:       "test-cluster",
				UID:        cluster.UID,
			}},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(preC3).Build()
	phase := NewACLBootstrapPhase(&PhaseContext{
		Client: fakeClient,
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	})

	if err := phase.ensureBootstrapSecretOwnership(context.Background(), cluster, preC3); err != nil {
		t.Fatalf("ensureBootstrapSecretOwnership() error = %v", err)
	}

	migrated := &corev1.Secret{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name: preC3.Name, Namespace: "test-ns",
	}, migrated); err != nil {
		t.Fatalf("Failed to get migrated secret: %v", err)
	}
	if n := len(migrated.OwnerReferences); n != 0 {
		t.Errorf("ownerReferences after migration = %d, want 0", n)
	}
	if got := migrated.Labels[BootstrapSecretClusterLabel]; got != "test-cluster" {
		t.Errorf("label %s = %q, want %q", BootstrapSecretClusterLabel, got, "test-cluster")
	}

	// Second pass: already migrated — must be a no-op (no error, same
	// resourceVersion).
	before := migrated.ResourceVersion
	if err := phase.ensureBootstrapSecretOwnership(context.Background(), cluster, migrated); err != nil {
		t.Fatalf("second ensureBootstrapSecretOwnership() error = %v", err)
	}
	after := &corev1.Secret{}
	if err := fakeClient.Get(context.Background(), types.NamespacedName{
		Name: preC3.Name, Namespace: "test-ns",
	}, after); err != nil {
		t.Fatalf("Failed to re-get secret: %v", err)
	}
	if after.ResourceVersion != before {
		t.Errorf("second pass wrote (resourceVersion %s -> %s), want no-op", before, after.ResourceVersion)
	}
}
