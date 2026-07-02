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

func condition(cluster *nomadv1alpha1.NomadCluster, condType string) *metav1.Condition {
	return meta.FindStatusCondition(cluster.Status.Conditions, condType)
}

// TestUpdateFinalStatusReadyPath drives the full status-update family
// with a ready StatefulSet and a fully-populated phase context, and
// pins the one-shot InitialReconcileComplete Event debounce.
func TestUpdateFinalStatusReadyPath(t *testing.T) {
	cluster := newTestCluster("fs-ns", "fs-cluster")
	cluster.Spec.Server.ACL.Enabled = true

	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "fs-cluster", Namespace: "fs-ns"},
		Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To(int32(3))},
		Status:     appsv1.StatefulSetStatus{ReadyReplicas: 3, CurrentReplicas: 3},
	}
	internalSvc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "fs-cluster-internal", Namespace: "fs-ns"}}
	externalSvc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "fs-cluster-external", Namespace: "fs-ns"}}
	bootstrapSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "fs-cluster-acl-bootstrap", Namespace: "fs-ns"}}

	r, recorder := newFinalStatusFixture(t, cluster, sts, internalSvc, externalSvc, bootstrapSecret)

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
	for _, want := range []struct{ condType, reason string }{
		{nomadv1alpha1.ConditionTypeReady, "ClusterReady"},
		{nomadv1alpha1.ConditionTypeLicenseValid, "LicenseActive"},
	} {
		c := condition(cluster, want.condType)
		if c == nil || c.Status != metav1.ConditionTrue || c.Reason != want.reason {
			t.Errorf("condition %s = %+v, want True/%s", want.condType, c, want.reason)
		}
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

// TestUpdateFinalStatusDegradedPaths covers the not-ready branches:
// missing StatefulSet, missing services, expired license, license
// probe failure, unhealthy autopilot.
func TestUpdateFinalStatusDegradedPaths(t *testing.T) {
	cluster := newTestCluster("fs-deg-ns", "fs-cluster")
	cluster.Spec.Server.ACL.Enabled = true
	r, _ := newFinalStatusFixture(t, cluster)

	phaseCtx := &phases.PhaseContext{
		License:   &nomadv1alpha1.LicenseStatus{Valid: false},
		Autopilot: &nomadv1alpha1.AutopilotStatus{Healthy: false},
	}
	snapshot := cluster.DeepCopy()
	if err := r.updateFinalStatus(context.Background(), cluster, phaseCtx, snapshot); err != nil {
		t.Fatalf("updateFinalStatus() error = %v", err)
	}

	if cluster.Status.Phase != nomadv1alpha1.ClusterPhaseCreating {
		t.Errorf("phase = %q, want Creating with no StatefulSet", cluster.Status.Phase)
	}
	if c := condition(cluster, nomadv1alpha1.ConditionTypeReady); c == nil || c.Status != metav1.ConditionFalse {
		t.Errorf("Ready = %+v, want False", c)
	}
	if c := condition(cluster, nomadv1alpha1.ConditionTypeLicenseValid); c == nil || c.Reason != "LicenseExpired" {
		t.Errorf("LicenseValid = %+v, want LicenseExpired", c)
	}
	if cluster.Status.ACLBootstrapped {
		t.Error("aclBootstrapped set without bootstrap secret")
	}

	// License probe failure → Unknown.
	cluster2 := newTestCluster("fs-deg-ns", "fs-cluster2")
	r2, _ := newFinalStatusFixture(t, cluster2)
	phaseCtx2 := &phases.PhaseContext{LicenseError: context.DeadlineExceeded}
	if err := r2.updateFinalStatus(context.Background(), cluster2, phaseCtx2, cluster2.DeepCopy()); err != nil {
		t.Fatalf("updateFinalStatus() error = %v", err)
	}
	if c := condition(cluster2, nomadv1alpha1.ConditionTypeLicenseValid); c == nil || c.Status != metav1.ConditionUnknown {
		t.Errorf("LicenseValid = %+v, want Unknown on probe failure", c)
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
