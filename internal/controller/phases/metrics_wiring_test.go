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
	"time"

	"k8s.io/utils/ptr"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/internal/metrics"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad/mocks"
	tlspkg "github.com/hashicorp/nomad-enterprise-operator/pkg/tls"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// D4 (neo-how) wiring tests: each asserts that the relevant code path
// populates its F4 metric handle. Metrics are process-global, so every
// test uses its own cluster/namespace label values.

type dummyPhase struct{}

func (dummyPhase) Name() string { return "DummyPhase" }
func (dummyPhase) Execute(context.Context, *nomadv1alpha1.NomadCluster) PhaseResult {
	return OK()
}

// TestPhaseDurationRecorded covers D4a / AC-8.1.1: TimedExecute
// observes the phase duration histogram with cluster/namespace/phase
// labels.
func TestPhaseDurationRecorded(t *testing.T) {
	cluster := newTestCluster("d4a-ns", "d4a-cluster")

	TimedExecute(context.Background(), dummyPhase{}, cluster)

	families, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	for _, fam := range families {
		if fam.GetName() != "nomad_operator_phase_duration_seconds" {
			continue
		}
		for _, m := range fam.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["cluster"] == "d4a-cluster" && labels["namespace"] == "d4a-ns" && labels["phase"] == "DummyPhase" {
				if m.GetHistogram().GetSampleCount() < 1 {
					t.Fatal("histogram series exists but has no observations")
				}
				return
			}
		}
	}
	t.Fatal("no phase_duration series recorded for DummyPhase")
}

// TestCertExpiryGaugeSet covers D4c / AC-8.1.3: the CA and server cert
// expiry gauges carry the certificates' NotAfter as Unix seconds.
func TestCertExpiryGaugeSet(t *testing.T) {
	cluster := newTestCluster("d4c-ns", "d4c-cluster")
	phase := &CertificatePhase{PhaseContext: &PhaseContext{
		Client: fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(),
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}}

	ca, err := tlspkg.GenerateCA("D4c Test CA")
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}
	caCert, err := tlspkg.ParseCertificate(ca.CACertPEM)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	phase.updateCAStatus(cluster, "operator-generated", ca)

	got := testutil.ToFloat64(metrics.CertExpiry.WithLabelValues("d4c-cluster", "d4c-ns", "ca"))
	if want := float64(caCert.NotAfter.Unix()); got != want {
		t.Errorf("ca expiry gauge = %v, want %v", got, want)
	}

	// Server path: no existing secret, so a fresh cert is issued and the
	// gauge must track it.
	if result := phase.ensureServerCertificate(context.Background(), cluster, ca, ca.CACertPEM); result.Error != nil {
		t.Fatalf("ensureServerCertificate() error = %v", result.Error)
	}
	serverExpiry := testutil.ToFloat64(metrics.CertExpiry.WithLabelValues("d4c-cluster", "d4c-ns", "server"))
	if serverExpiry <= float64(time.Now().Unix()) {
		t.Errorf("server expiry gauge = %v, want a future Unix timestamp", serverExpiry)
	}
}

// TestLicenseAndVersionGauges covers D4d / AC-8.1.4 / AC-8.1.7: license
// expiry exported as Unix seconds; version exported as an info gauge
// whose previous series is deleted on version change.
func TestLicenseAndVersionGauges(t *testing.T) {
	expiry := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)

	readyPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "d4d-cluster-0",
			Namespace: "d4d-ns",
			Labels:    GetSelectorLabels(newTestCluster("d4d-ns", "d4d-cluster")),
		},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}

	runWith := func(t *testing.T, version string) {
		t.Helper()
		cluster := newTestCluster("d4d-ns", "d4d-cluster")
		cluster.Spec.Replicas = 1

		mockNomad := mocks.NewMockNomadAPI(t)
		mockNomad.EXPECT().GetLeader().Return("10.0.0.1:4647", nil)
		mockNomad.EXPECT().GetLicense(mock.Anything, mock.Anything).
			Return(&nomad.LicenseResult{LicenseID: "lic-1", ExpirationTime: expiry.Format(time.RFC3339)}, nil)
		mockNomad.EXPECT().GetAutopilotHealth(mock.Anything, mock.Anything).
			Return(&nomad.AutopilotHealthResult{Healthy: true}, nil)
		mockNomad.EXPECT().AgentSelf(mock.Anything).
			Return(&nomad.AgentSelfResult{Version: version}, nil)

		phase := NewClusterStatusPhase(&PhaseContext{
			Client: fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(readyPod.DeepCopy()).Build(),
			Scheme: scheme.Scheme,
			Log:    zap.New(zap.UseDevMode(true)),
			NomadClientFactory: func(_ nomad.ClientConfig) (nomad.NomadAPI, error) {
				return mockNomad, nil
			},
		})
		if result := phase.Execute(context.Background(), cluster); result.Error != nil {
			t.Fatalf("Execute() error = %v", result.Error)
		}
	}

	runWith(t, "1.11.0+ent")

	if got := testutil.ToFloat64(metrics.LicenseExpiry.WithLabelValues("d4d-cluster", "d4d-ns")); got != float64(expiry.Unix()) {
		t.Errorf("license expiry gauge = %v, want %v", got, float64(expiry.Unix()))
	}
	if got := testutil.ToFloat64(metrics.NomadVersionInfo.WithLabelValues("d4d-cluster", "d4d-ns", "1.11.0+ent")); got != 1 {
		t.Errorf("version info gauge = %v, want 1", got)
	}

	// Version change: exactly one series per cluster — the old one is
	// deleted (checked via Gather, since WithLabelValues would recreate
	// the series it queries).
	runWith(t, "1.11.1+ent")

	families, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	for _, fam := range families {
		if fam.GetName() != "nomad_operator_nomad_version_info" {
			continue
		}
		for _, m := range fam.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["cluster"] == "d4d-cluster" && labels["version"] == "1.11.0+ent" {
				t.Error("stale version series 1.11.0+ent not deleted on version change")
			}
		}
	}
	if got := testutil.ToFloat64(metrics.NomadVersionInfo.WithLabelValues("d4d-cluster", "d4d-ns", "1.11.1+ent")); got != 1 {
		t.Errorf("new version info gauge = %v, want 1", got)
	}
}

// TestACLBootstrapFailureCounted covers D4e / AC-8.1.5: a genuine
// bootstrap failure increments the counter; an "already bootstrapped
// externally" outcome does not.
func TestACLBootstrapFailureCounted(t *testing.T) {
	newFixture := func(name string, bootstrapErr error) (*ACLBootstrapPhase, *nomadv1alpha1.NomadCluster) {
		cluster := newTestCluster("d4e-ns", name)
		cluster.Spec.Server.ACL.Enabled = ptr.To(true)
		readyPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name + "-0",
				Namespace: "d4e-ns",
				Labels:    GetSelectorLabels(cluster),
			},
			Status: corev1.PodStatus{
				Phase:      corev1.PodRunning,
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			},
		}
		mockNomad := mocks.NewMockNomadAPI(t)
		mockNomad.EXPECT().BootstrapACL().Return(nil, bootstrapErr).Once()
		return NewACLBootstrapPhase(&PhaseContext{
			Client: fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(cluster, readyPod).WithStatusSubresource(cluster).Build(),
			Scheme: scheme.Scheme,
			Log:    zap.New(zap.UseDevMode(true)),
			NomadClientFactory: func(_ nomad.ClientConfig) (nomad.NomadAPI, error) {
				return mockNomad, nil
			},
		}), cluster
	}

	t.Run("genuine failure increments", func(t *testing.T) {
		phase, cluster := newFixture("d4e-fail", errors.New("acl bootstrap exploded"))
		before := testutil.ToFloat64(metrics.ACLBootstrapFailures.WithLabelValues("d4e-fail", "d4e-ns"))

		result := phase.Execute(context.Background(), cluster)
		if result.Error == nil {
			t.Fatal("Execute() expected error from failed bootstrap")
		}

		after := testutil.ToFloat64(metrics.ACLBootstrapFailures.WithLabelValues("d4e-fail", "d4e-ns"))
		if after-before != 1 {
			t.Errorf("failure counter delta = %v, want 1", after-before)
		}
	})

	t.Run("already bootstrapped externally does not increment", func(t *testing.T) {
		phase, cluster := newFixture("d4e-ext", nomad.ErrAlreadyBootstrapped)
		before := testutil.ToFloat64(metrics.ACLBootstrapFailures.WithLabelValues("d4e-ext", "d4e-ns"))

		result := phase.Execute(context.Background(), cluster)
		if result.Error != nil {
			t.Fatalf("Execute() error = %v, want marker-secret path", result.Error)
		}

		after := testutil.ToFloat64(metrics.ACLBootstrapFailures.WithLabelValues("d4e-ext", "d4e-ns"))
		if after != before {
			t.Errorf("failure counter delta = %v, want 0 for external bootstrap", after-before)
		}
	})
}
