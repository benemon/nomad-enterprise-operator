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
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/internal/controller/phases"
)

// neo-dic: fake-client unit coverage of updateFinalStatus and its
// status-updater family, plus the secret→cluster watch mapping. These
// paths run on every reconcile in production but were unreachable in
// envtest (phases requeue before updateFinalStatus on clusters with no
// real pods), which is why they sat at 0%.

func newFinalStatusFixture(t *testing.T, objs ...client.Object) (*NomadClusterReconciler, *record.FakeRecorder) {
	t.Helper()
	_ = nomadv1alpha1.AddToScheme(scheme.Scheme)
	builder := fake.NewClientBuilder().WithScheme(scheme.Scheme)
	// Mirror the D5 field indexes SetupWithManager registers on the real
	// cache, using the same shared extractors.
	for key, extract := range secretRefIndexes {
		builder = builder.WithIndex(&nomadv1alpha1.NomadCluster{}, key, func(obj client.Object) []string {
			if name := extract(obj.(*nomadv1alpha1.NomadCluster)); name != "" {
				return []string{name}
			}
			return nil
		})
	}
	for _, o := range objs {
		builder = builder.WithObjects(o)
		if c, ok := o.(*nomadv1alpha1.NomadCluster); ok {
			builder = builder.WithStatusSubresource(c)
		}
	}
	recorder := record.NewFakeRecorder(5)
	return &NomadClusterReconciler{
		Client:   builder.Build(),
		Scheme:   scheme.Scheme,
		Recorder: recorder,
	}, recorder
}

// TestReadyTruePrecondition covers C9 / AC-2.5.5: Ready=True requires
// StatefulSet at desired replicas AND a valid license AND healthy
// autopilot — and when it holds, status.conditions contains EXACTLY one
// entry (AC-2.5.4). Also pins the one-shot InitialReconcileComplete
// Event debounce.
func TestReadyTruePrecondition(t *testing.T) {
	cluster := newTestCluster("fs-ns", "fs-cluster")
	cluster.Spec.Server.ACL.Enabled = true

	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "fs-cluster", Namespace: "fs-ns"},
		Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To(int32(3))},
		Status:     appsv1.StatefulSetStatus{ReadyReplicas: 3, CurrentReplicas: 3},
	}
	bootstrapSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "fs-cluster-acl-bootstrap", Namespace: "fs-ns"}}

	r, recorder := newFinalStatusFixture(t, cluster, sts, bootstrapSecret)

	phaseCtx := &phases.PhaseContext{
		AdvertiseAddress: "10.0.0.9",
		LeaderAddress:    "10.0.0.1:4647",
		NomadVersion:     "1.11.0+ent",
		License: &nomadv1alpha1.LicenseStatus{
			Valid:          true,
			LicenseID:      "lic-1",
			ExpirationTime: time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
		},
		Autopilot: &nomadv1alpha1.AutopilotStatus{Healthy: true},
	}

	drive := func() {
		snapshot := cluster.DeepCopy()
		if err := r.updateFinalStatus(context.Background(), cluster, phaseCtx, snapshot); err != nil {
			t.Fatalf("updateFinalStatus() error = %v", err)
		}
	}
	drive()

	// AC-2.5.4: exactly one condition, type Ready.
	if len(cluster.Status.Conditions) != 1 || cluster.Status.Conditions[0].Type != "Ready" {
		t.Fatalf("conditions = %+v, want exactly one Ready entry", cluster.Status.Conditions)
	}
	if c := cluster.Status.Conditions[0]; c.Status != metav1.ConditionTrue || c.Reason != "ClusterReady" {
		t.Errorf("Ready = %s/%s, want True/ClusterReady", c.Status, c.Reason)
	}

	// AC-2.5.7: sub-fields are the source of truth.
	if cluster.Status.Phase != nomadv1alpha1.ClusterPhaseRunning {
		t.Errorf("phase = %q, want Running", cluster.Status.Phase)
	}
	if cluster.Status.ReadyReplicas != 3 || cluster.Status.CurrentReplicas != 3 {
		t.Errorf("replicas = %d/%d, want 3/3", cluster.Status.ReadyReplicas, cluster.Status.CurrentReplicas)
	}
	if cluster.Status.AdvertiseAddress != "10.0.0.9" || cluster.Status.LeaderAddress != "10.0.0.1:4647" {
		t.Errorf("addresses not propagated: %+v", cluster.Status)
	}
	if cluster.Status.NomadVersion != "1.11.0+ent" {
		t.Errorf("nomadVersion = %q", cluster.Status.NomadVersion)
	}
	if !cluster.Status.ACLBootstrapped {
		t.Error("aclBootstrapped not set despite bootstrap secret present")
	}
	if cluster.Status.License == nil || !cluster.Status.License.Valid {
		t.Error("license sub-field not populated")
	}
	if cluster.Status.Autopilot == nil || !cluster.Status.Autopilot.Healthy {
		t.Error("autopilot sub-field not populated")
	}

	// One-shot InitialReconcileComplete: emitted on first Ready, marker
	// persisted, no re-emission on the next pass.
	if !cluster.Status.InitialReconcileEventEmitted {
		t.Fatal("InitialReconcileEventEmitted not set")
	}
	var events []string
	for len(recorder.Events) > 0 {
		events = append(events, <-recorder.Events)
	}
	if len(events) != 1 || !strings.Contains(events[0], "InitialReconcileComplete") {
		t.Fatalf("events = %v, want exactly one InitialReconcileComplete", events)
	}
	drive()
	if len(recorder.Events) != 0 {
		t.Error("InitialReconcileComplete re-emitted on second pass")
	}
}

// TestReadyReasonMapping covers C9 / AC-2.5.6: each degraded sub-state
// maps to its documented Ready=False Reason; an unknown probe state
// (nil license/autopilot) does not fail Ready.
func TestReadyReasonMapping(t *testing.T) {
	readySTS := func() *appsv1.StatefulSet {
		return &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: "fs-cluster", Namespace: "fs-map-ns"},
			Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To(int32(3))},
			Status:     appsv1.StatefulSetStatus{ReadyReplicas: 3, CurrentReplicas: 3},
		}
	}

	cases := []struct {
		name       string
		sts        *appsv1.StatefulSet // nil = no StatefulSet
		phaseCtx   *phases.PhaseContext
		preStatus  func(*nomadv1alpha1.NomadCluster) // seed status before the call
		wantStatus metav1.ConditionStatus
		wantReason string
		wantPhase  nomadv1alpha1.ClusterPhase
	}{
		{
			// neo-ru9: an expired CA names the cause even though it also
			// breaks replicas — precedence over WaitingForReplicas.
			name:     "expired CA with no ready replicas -> CAExpired, not WaitingForReplicas",
			sts:      nil,
			phaseCtx: &phases.PhaseContext{},
			preStatus: func(c *nomadv1alpha1.NomadCluster) {
				c.Status.CertificateAuthority = &nomadv1alpha1.CertificateAuthorityStatus{
					ExpiryTime: time.Now().Add(-time.Hour).Format(time.RFC3339),
				}
			},
			wantStatus: metav1.ConditionFalse,
			wantReason: "CAExpired",
			wantPhase:  nomadv1alpha1.ClusterPhaseRunning,
		},
		{
			name:     "unexpired CA does not trip CAExpired",
			sts:      readySTS(),
			phaseCtx: &phases.PhaseContext{},
			preStatus: func(c *nomadv1alpha1.NomadCluster) {
				c.Status.CertificateAuthority = &nomadv1alpha1.CertificateAuthorityStatus{
					ExpiryTime: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
			},
			wantStatus: metav1.ConditionTrue,
			wantReason: "ClusterReady",
			wantPhase:  nomadv1alpha1.ClusterPhaseRunning,
		},
		{
			name:       "no ready replicas -> WaitingForReplicas",
			sts:        nil,
			phaseCtx:   &phases.PhaseContext{},
			wantStatus: metav1.ConditionFalse,
			wantReason: "WaitingForReplicas",
			wantPhase:  nomadv1alpha1.ClusterPhaseCreating,
		},
		{
			name: "invalid license -> LicenseExpired",
			sts:  readySTS(),
			phaseCtx: &phases.PhaseContext{
				License: &nomadv1alpha1.LicenseStatus{Valid: false},
			},
			wantStatus: metav1.ConditionFalse,
			wantReason: "LicenseExpired",
			wantPhase:  nomadv1alpha1.ClusterPhaseRunning,
		},
		{
			name: "unhealthy autopilot -> AutopilotUnhealthy",
			sts:  readySTS(),
			phaseCtx: &phases.PhaseContext{
				License:   &nomadv1alpha1.LicenseStatus{Valid: true},
				Autopilot: &nomadv1alpha1.AutopilotStatus{Healthy: false},
			},
			wantStatus: metav1.ConditionFalse,
			wantReason: "AutopilotUnhealthy",
			wantPhase:  nomadv1alpha1.ClusterPhaseRunning,
		},
		{
			name:       "unknown probe state does not fail Ready",
			sts:        readySTS(),
			phaseCtx:   &phases.PhaseContext{}, // nil License/Autopilot = probe miss
			wantStatus: metav1.ConditionTrue,
			wantReason: "ClusterReady",
			wantPhase:  nomadv1alpha1.ClusterPhaseRunning,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cluster := newTestCluster("fs-map-ns", "fs-cluster")
			objs := []client.Object{cluster}
			if tc.sts != nil {
				objs = append(objs, tc.sts)
			}
			r, _ := newFinalStatusFixture(t, objs...)

			if tc.preStatus != nil {
				tc.preStatus(cluster)
			}
			if err := r.updateFinalStatus(context.Background(), cluster, tc.phaseCtx, cluster.DeepCopy()); err != nil {
				t.Fatalf("updateFinalStatus() error = %v", err)
			}

			if len(cluster.Status.Conditions) != 1 {
				t.Fatalf("conditions = %+v, want exactly one (AC-2.5.4)", cluster.Status.Conditions)
			}
			c := cluster.Status.Conditions[0]
			if c.Type != "Ready" || c.Status != tc.wantStatus || c.Reason != tc.wantReason {
				t.Errorf("Ready = %s/%s/%s, want Ready/%s/%s", c.Type, c.Status, c.Reason, tc.wantStatus, tc.wantReason)
			}
			if cluster.Status.Phase != tc.wantPhase {
				t.Errorf("phase = %q, want %q", cluster.Status.Phase, tc.wantPhase)
			}
		})
	}
}

// TestFindClustersReferencingSecret covers the watch mapping used for
// rolling restarts on external Secret changes: clusters referencing the
// Secret via license, user CA, or gossip get a reconcile request;
// operator-owned (NomadCluster-owned) Secrets are skipped.
func TestFindClustersReferencingSecret(t *testing.T) {
	licenseUser := newTestCluster("map-ns", "license-user") // references nomad-license by default
	caUser := newTestCluster("map-ns", "ca-user")
	caUser.Spec.License.SecretName = "other-license"
	caUser.Spec.Server.TLS.CA = &nomadv1alpha1.CASpec{SecretName: "corp-ca"}
	gossipUser := newTestCluster("map-ns", "gossip-user")
	gossipUser.Spec.License.SecretName = "other-license"
	gossipUser.Spec.Gossip.SecretName = "shared-gossip"

	r, _ := newFinalStatusFixture(t, licenseUser, caUser, gossipUser)

	requestsFor := func(secret *corev1.Secret) int {
		return len(r.findClustersReferencingSecret(context.Background(), secret))
	}

	if n := requestsFor(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "nomad-license", Namespace: "map-ns"}}); n != 1 {
		t.Errorf("license secret mapped to %d clusters, want 1", n)
	}
	if n := requestsFor(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "corp-ca", Namespace: "map-ns"}}); n != 1 {
		t.Errorf("CA secret mapped to %d clusters, want 1", n)
	}
	if n := requestsFor(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "shared-gossip", Namespace: "map-ns"}}); n != 1 {
		t.Errorf("gossip secret mapped to %d clusters, want 1", n)
	}
	if n := requestsFor(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "map-ns"}}); n != 0 {
		t.Errorf("unrelated secret mapped to %d clusters, want 0", n)
	}

	// Operator-owned Secrets are handled by Owns() and must not fan out.
	owned := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "nomad-license", Namespace: "map-ns",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "nomad.hashicorp.com/v1alpha1", Kind: "NomadCluster",
			Name: "license-user", UID: "uid",
		}},
	}}
	if n := requestsFor(owned); n != 0 {
		t.Errorf("owned secret mapped to %d clusters, want 0", n)
	}
}

// A missing license Secret is accepted at admission but surfaces the
// LicenseSecretNotFound reason + one Warning Event; the reason clears
// when the Secret appears.
func TestLicenseSecretNotFoundReason(t *testing.T) {
	cluster := newTestCluster("lsnf-ns", "lsnf")
	cluster.Spec.License.SecretName = "does-not-exist-yet"

	r, recorder := newFinalStatusFixture(t, cluster)

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "lsnf", Namespace: "lsnf-ns"}}
	// First reconcile adds the finalizer; second runs the phases.
	for i := 0; i < 2; i++ {
		if _, err := r.Reconcile(context.Background(), req); err != nil && i == 0 {
			t.Fatalf("finalizer reconcile error = %v", err)
		}
	}

	got := &nomadv1alpha1.NomadCluster{}
	if err := r.Get(context.Background(), req.NamespacedName, got); err != nil {
		t.Fatal(err)
	}
	ready := meta.FindStatusCondition(got.Status.Conditions, "Ready")
	if ready == nil || ready.Reason != "LicenseSecretNotFound" {
		t.Fatalf("Ready reason = %+v, want LicenseSecretNotFound", ready)
	}
	if !strings.Contains(ready.Message, "does-not-exist-yet") {
		t.Errorf("message should name the missing Secret: %q", ready.Message)
	}

	// Exactly one Warning Event on the transition; a repeat reconcile
	// in the same state must not re-emit.
	if _, err := r.Reconcile(context.Background(), req); err == nil {
		t.Fatal("reconcile with missing secret should still error")
	}
	var events []string
	for len(recorder.Events) > 0 {
		e := <-recorder.Events
		if strings.Contains(e, "LicenseSecretNotFound") {
			events = append(events, e)
		}
	}
	if len(events) != 1 {
		t.Fatalf("LicenseSecretNotFound events = %d, want exactly 1 (transition-only)", len(events))
	}

	// Secret appears -> the reason clears on the next reconcile.
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "does-not-exist-yet", Namespace: "lsnf-ns"},
		Data:       map[string][]byte{"license": []byte("lic")},
	}
	if err := r.Create(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	_, _ = r.Reconcile(context.Background(), req)
	if err := r.Get(context.Background(), req.NamespacedName, got); err != nil {
		t.Fatal(err)
	}
	ready = meta.FindStatusCondition(got.Status.Conditions, "Ready")
	if ready == nil || ready.Reason == "LicenseSecretNotFound" {
		t.Fatalf("reason not cleared after Secret creation: %+v", ready)
	}
}
