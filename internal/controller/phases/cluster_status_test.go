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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestClusterStatusPhase_UsesOperatorStatusToken(t *testing.T) {
	opSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-operator-status",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"accessor-id": []byte("op-accessor"),
			"secret-id":   []byte("op-secret-token"),
		},
	}

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.ACL.Enabled = true
	cluster.Status.OperatorStatusSecretName = "test-cluster-operator-status"

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithRuntimeObjects(opSecret, cluster).
		Build()

	phaseCtx := &PhaseContext{
		Client: fakeClient,
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}

	phase := NewClusterStatusPhase(phaseCtx)

	token, err := phase.getOperatorStatusToken(context.Background(), cluster)
	if err != nil {
		t.Fatalf("getOperatorStatusToken() error = %v", err)
	}
	if token != "op-secret-token" {
		t.Errorf("token = %q, want %q", token, "op-secret-token")
	}
}

func TestClusterStatusPhase_FallsBackToBootstrapToken(t *testing.T) {
	bootstrapSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-acl-bootstrap",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"accessor-id": []byte("bootstrap-accessor"),
			"secret-id":   []byte("bootstrap-secret-token"),
		},
	}

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.ACL.Enabled = true
	// OperatorStatusSecretName is empty — should fall back to bootstrap

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithRuntimeObjects(bootstrapSecret, cluster).
		Build()

	phaseCtx := &PhaseContext{
		Client: fakeClient,
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}

	phase := NewClusterStatusPhase(phaseCtx)

	token, err := phase.getOperatorStatusToken(context.Background(), cluster)
	if err != nil {
		t.Fatalf("getOperatorStatusToken() error = %v", err)
	}
	if token != "bootstrap-secret-token" {
		t.Errorf("token = %q, want %q", token, "bootstrap-secret-token")
	}
}
