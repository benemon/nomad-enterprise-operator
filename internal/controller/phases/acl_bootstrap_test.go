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
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

const testOperatorStatusName = "test-cluster-operator-status"

func TestACLBootstrapPhase_CreatesOperatorStatusToken(t *testing.T) {
	// Start a test HTTP server on port 4646 to stub Nomad API calls.
	// LoadBalancerAddress hardcodes :4646, so the server must listen there.
	listener, err := net.Listen("tcp", "127.0.0.1:4646")
	if err != nil {
		t.Skipf("Skipping: port 4646 not available: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/acl/policy/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	})
	mux.HandleFunc("/v1/acl/token", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"AccessorID": "test-accessor-id",
			"SecretID":   "test-secret-id",
			"Name":       testOperatorStatusName,
			"Type":       "client",
			"CreateTime": "2025-01-01T00:00:00Z",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	ts := httptest.NewUnstartedServer(mux)
	_ = ts.Listener.Close()
	ts.Listener = listener
	ts.StartTLS()
	defer ts.Close()

	// Extract the test server's CA cert so the Nomad client trusts it
	serverCACert := ts.TLS.Certificates[0].Certificate[0]
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCACert})

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

	phaseCtx := &PhaseContext{
		Client:           fakeClient,
		Scheme:           scheme.Scheme,
		Log:              zap.New(zap.UseDevMode(true)),
		AdvertiseAddress: "127.0.0.1",
		CACert:           caCertPEM,
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
