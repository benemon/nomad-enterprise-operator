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
	"errors"
	"testing"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad/mocks"
	"github.com/stretchr/testify/mock"
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

	cluster := newTestCluster("test-ns", "test-cluster")
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

	cluster := newTestCluster("test-ns", "test-cluster")
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

// TestNomadVersionProbed covers AC-4.7.1 (probe populates
// PhaseContext.NomadVersion) and AC-4.7.2 (probe failure is non-fatal
// and does not gate other status enrichment). The cases also exercise
// the empty-version response path so a Nomad agent returning blank
// fields cannot silently propagate as "no version observed".
func TestNomadVersionProbed(t *testing.T) {
	// readyPod returns a pod that CheckPodsReady will accept, so
	// ClusterStatusPhase proceeds past its readiness short-circuit.
	readyPod := func(cluster *nomadv1alpha1.NomadCluster) *corev1.Pod {
		labels := GetSelectorLabels(cluster)
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cluster.Name + "-0",
				Namespace: cluster.Namespace,
				Labels:    labels,
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				Conditions: []corev1.PodCondition{
					{Type: corev1.PodReady, Status: corev1.ConditionTrue},
				},
			},
		}
	}

	// stubNonVersionCalls installs success responses for the rest of
	// the ClusterStatusPhase Nomad calls so the only thing under test
	// is the AgentSelf path. Returning nil for License/Autopilot would
	// short-circuit those branches before the AC-4.7.2 assertion, so
	// realistic shapes are returned.
	stubNonVersionCalls := func(m *mocks.MockNomadAPI) {
		m.EXPECT().GetLeader().Return("10.0.0.1:4647", nil)
		m.EXPECT().GetLicense(mock.Anything, mock.Anything).
			Return(&nomad.LicenseResult{LicenseID: "lic-1"}, nil)
		m.EXPECT().GetAutopilotHealth(mock.Anything, mock.Anything).
			Return(&nomad.AutopilotHealthResult{Healthy: true}, nil)
	}

	type tc struct {
		name        string
		setupMock   func(*mocks.MockNomadAPI)
		wantVersion string
		wantLicense bool
	}
	cases := []tc{
		{
			name: "AC-4.7.1: probe succeeds → NomadVersion populated",
			setupMock: func(m *mocks.MockNomadAPI) {
				stubNonVersionCalls(m)
				m.EXPECT().AgentSelf(mock.Anything).
					Return(&nomad.AgentSelfResult{Version: "1.11.0+ent"}, nil)
			},
			wantVersion: "1.11.0+ent",
			wantLicense: true,
		},
		{
			name: "AC-4.7.2: probe fails → other status enrichment still runs",
			setupMock: func(m *mocks.MockNomadAPI) {
				stubNonVersionCalls(m)
				m.EXPECT().AgentSelf(mock.Anything).
					Return(nil, errors.New("permission denied"))
			},
			wantVersion: "",
			wantLicense: true,
		},
		{
			name: "empty version response leaves NomadVersion unset",
			setupMock: func(m *mocks.MockNomadAPI) {
				stubNonVersionCalls(m)
				m.EXPECT().AgentSelf(mock.Anything).
					Return(&nomad.AgentSelfResult{Version: ""}, nil)
			},
			wantVersion: "",
			wantLicense: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cluster := newTestCluster("test-ns", "test-cluster")
			cluster.Spec.Replicas = 1

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme.Scheme).
				WithRuntimeObjects(cluster, readyPod(cluster)).
				Build()

			mockNomad := mocks.NewMockNomadAPI(t)
			c.setupMock(mockNomad)

			phaseCtx := &PhaseContext{
				Client: fakeClient,
				Scheme: scheme.Scheme,
				Log:    zap.New(zap.UseDevMode(true)),
				NomadClientFactory: func(_ nomad.ClientConfig) (nomad.NomadAPI, error) {
					return mockNomad, nil
				},
			}

			phase := NewClusterStatusPhase(phaseCtx)
			result := phase.Execute(context.Background(), cluster)
			if result.Error != nil {
				t.Fatalf("Execute() error = %v, message = %s", result.Error, result.Message)
			}

			if got := phaseCtx.NomadVersion; got != c.wantVersion {
				t.Errorf("NomadVersion = %q, want %q", got, c.wantVersion)
			}
			if c.wantLicense && phaseCtx.License == nil {
				t.Error("License should be populated even when AgentSelf failed (AC-4.7.2)")
			}
		})
	}
}
