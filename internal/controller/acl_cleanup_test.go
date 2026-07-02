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
	"testing"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/internal/controller/phases"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad/mocks"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestCleanupNomadACLResourcesOrder covers C4 (neo-ikf) / AC-2.4.7:
// deletion revokes BOTH derived credentials — management token+policy
// first, then status token+policy — authenticated with the bootstrap
// token, and resolves everything by deterministic name (the status
// cache fields are deliberately left empty here to prove the leak
// window is closed).
func TestCleanupNomadACLResourcesOrder(t *testing.T) {
	const bootToken = "boot-secret-id"
	mgmtName := phases.OperatorManagementSecretName("test-cluster")
	statusName := "test-cluster-operator-status"

	cluster := &nomadv1alpha1.NomadCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster", Namespace: "test-ns"},
	}
	// Status cache fields intentionally NOT set.

	secretOf := func(name, accessor string) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "test-ns"},
			Data: map[string][]byte{
				phases.SecretKeyAccessorID: []byte(accessor),
				"secret-id":                []byte(name + "-secret"),
			},
		}
	}
	bootstrapSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      phases.BootstrapSecretName("test-cluster"),
			Namespace: "test-ns",
		},
		Data: map[string][]byte{"secret-id": []byte(bootToken)},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(bootstrapSecret, secretOf(mgmtName, "mgmt-acc"), secretOf(statusName, "status-acc")).
		Build()

	var calls []string
	step := func(name string) { calls = append(calls, name) }

	mockNomad := mocks.NewMockNomadAPI(t)
	mockNomad.EXPECT().DeleteACLToken(bootToken, "mgmt-acc").
		Run(func(_, _ string) { step("token:mgmt") }).Return(nil).Once()
	mockNomad.EXPECT().DeleteACLPolicy(bootToken, mgmtName).
		Run(func(_, _ string) { step("policy:mgmt") }).Return(nil).Once()
	mockNomad.EXPECT().DeleteACLToken(bootToken, "status-acc").
		Run(func(_, _ string) { step("token:status") }).Return(nil).Once()
	mockNomad.EXPECT().DeleteACLPolicy(bootToken, statusName).
		Run(func(_, _ string) { step("policy:status") }).Return(nil).Once()

	r := &NomadClusterReconciler{
		Client: fakeClient,
		Scheme: scheme.Scheme,
		NomadClientFactory: func(_ nomad.ClientConfig) (nomad.NomadAPI, error) {
			return mockNomad, nil
		},
	}

	if err := r.cleanupNomadACLResources(context.Background(), cluster); err != nil {
		t.Fatalf("cleanupNomadACLResources() error = %v", err)
	}

	want := []string{"token:mgmt", "policy:mgmt", "token:status", "policy:status"}
	if len(calls) != len(want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("calls = %v, want %v (AC-2.4.7 order)", calls, want)
		}
	}
}
