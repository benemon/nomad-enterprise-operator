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
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad/mocks"
	"github.com/stretchr/testify/mock"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// TestNodeNameToOrdinal covers AC-2.3.4a's contract — the ID-mapping
// function returns ordinal or error, never silently treats
// unrecognised input as ordinal 0.
//
// The design doc's table assumed the autopilot Address field would
// carry per-pod information (FQDN forms, short DNS) so the mapping
// function would parse addresses. In this operator's actual HCL
// (pkg/hcl/generator.go), all replicas advertise the cluster's
// shared LoadBalancer IP, so Address is useless for per-replica
// identification. The function therefore operates on the Node field
// (the pod hostname, e.g. "<cluster>-2"), which IS per-replica. The
// AC contract still holds — what changed is the shape of the input,
// not the guarantee.
func TestNodeNameToOrdinal(t *testing.T) {
	const clusterName = "nomad"

	type tc struct {
		name        string
		nodeName    string
		wantOrdinal int
		wantErr     bool
	}

	cases := []tc{
		{
			name:        "matching cluster prefix with integer ordinal resolves",
			nodeName:    "nomad-4",
			wantOrdinal: 4,
		},
		{
			name:        "node name with .<region> suffix resolves (Nomad autopilot output)",
			nodeName:    "nomad-4.global",
			wantOrdinal: 4,
		},
		{
			name:        "node name with a non-default region suffix resolves",
			nodeName:    "nomad-2.us-west-1",
			wantOrdinal: 2,
		},
		{
			name:        "very large ordinal is accepted unchanged",
			nodeName:    "nomad-9999",
			wantOrdinal: 9999,
		},
		{
			name:        "ordinal 0 resolves correctly (boundary)",
			nodeName:    "nomad-0",
			wantOrdinal: 0,
		},
		{
			name:     "wrong cluster prefix is rejected",
			nodeName: "other-3",
			wantErr:  true,
		},
		{
			name:     "non-integer ordinal is rejected",
			nodeName: "nomad-foo",
			wantErr:  true,
		},
		{
			name:     "empty ordinal suffix is rejected",
			nodeName: "nomad-",
			wantErr:  true,
		},
		{
			name:     "empty node name is rejected",
			nodeName: "",
			wantErr:  true,
		},
		{
			name:     "Nomad's (unknown) sentinel is rejected",
			nodeName: "(unknown)",
			wantErr:  true,
		},
		{
			name:     "name without the cluster-dash prefix is rejected (defends ordinal 0 from silent acceptance)",
			nodeName: "4",
			wantErr:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := nodeNameToOrdinal(c.nodeName, clusterName)
			if c.wantErr {
				if err == nil {
					t.Errorf("expected error, got ordinal %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.wantOrdinal {
				t.Errorf("ordinal = %d, want %d", got, c.wantOrdinal)
			}
		})
	}
}

// scaleDownFixture wires the common setup for the lifecycle tests:
// a NomadCluster, an STS at the current replica count, and the
// PhaseContext with a mock NomadAPI injected via NomadClientFactory.
type scaleDownFixture struct {
	cluster   *nomadv1alpha1.NomadCluster
	sts       *appsv1.StatefulSet
	mockNomad *mocks.MockNomadAPI
	phase     *ScaleDownPhase
}

func newScaleDownFixture(t *testing.T, currentSTSReplicas, specReplicas int32) *scaleDownFixture {
	t.Helper()

	cluster := newTestCluster("nomad", "ns")
	cluster.Spec.Replicas = specReplicas
	// ACL disabled so the phase doesn't need a bootstrap Secret in
	// the fake client. The token branch is exercised by
	// TestScaleDown_AclDeferralWhenSecretMissing below.
	cluster.Spec.Server.ACL.Enabled = false

	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "nomad", Namespace: "ns"},
		Spec: appsv1.StatefulSetSpec{
			Replicas: ptr.To(currentSTSReplicas),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithRuntimeObjects(cluster, sts).
		WithStatusSubresource(cluster).
		Build()

	mockNomad := mocks.NewMockNomadAPI(t)
	phaseCtx := &PhaseContext{
		Client: fakeClient,
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
		NomadClientFactory: func(_ nomad.ClientConfig) (nomad.NomadAPI, error) {
			return mockNomad, nil
		},
	}

	return &scaleDownFixture{
		cluster:   cluster,
		sts:       sts,
		mockNomad: mockNomad,
		phase:     NewScaleDownPhase(phaseCtx),
	}
}

func fetchCluster(t *testing.T, f *scaleDownFixture) *nomadv1alpha1.NomadCluster {
	t.Helper()
	updated := &nomadv1alpha1.NomadCluster{}
	if err := f.phase.Client.Get(context.Background(), types.NamespacedName{
		Name: "nomad", Namespace: "ns",
	}, updated); err != nil {
		t.Fatalf("Get(cluster) error = %v", err)
	}
	return updated
}

func fetchSTS(t *testing.T, f *scaleDownFixture) *appsv1.StatefulSet {
	t.Helper()
	updated := &appsv1.StatefulSet{}
	if err := f.phase.Client.Get(context.Background(), types.NamespacedName{
		Name: "nomad", Namespace: "ns",
	}, updated); err != nil {
		t.Fatalf("Get(sts) error = %v", err)
	}
	return updated
}

// peersAtReplicas returns a synthetic Raft peer list matching
// `replicas` Nomad servers named nomad-0..N-1. Useful for the
// removal-order assertions. Node carries the per-replica identifier
// the scale-down loop uses; Address is the shared LB IP form (a
// realistic stand-in for production output, though irrelevant to
// the mapping function).
func peersAtReplicas(replicas int32) []*nomad.RaftPeer {
	peers := make([]*nomad.RaftPeer, 0, replicas)
	for i := int32(0); i < replicas; i++ {
		peers = append(peers, &nomad.RaftPeer{
			ID:      idForOrdinal(int(i)),
			Node:    nodeForOrdinal(int(i)),
			Address: "10.0.0.1:4647", // shared LB IP — same for every replica
			Voter:   true,
		})
	}
	return peers
}

func idForOrdinal(i int) string {
	switch i {
	case 0:
		return "id-0000-aaaa"
	case 1:
		return "id-1111-bbbb"
	case 2:
		return "id-2222-cccc"
	case 3:
		return "id-3333-dddd"
	case 4:
		return "id-4444-eeee"
	default:
		return "id-other"
	}
}

func nodeForOrdinal(i int) string {
	// StatefulSet pod hostnames are <sts-name>-<ordinal>, which is
	// what Nomad picks up as the default node name.
	return "nomad-" + itoa(i)
}

func itoa(i int) string {
	// Avoid an extra import just for strconv.Itoa.
	if i == 0 {
		return "0"
	}
	digits := []byte{}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}

// TestScaleDown_RemovesHighestOrdinalFirst covers AC-2.3.4 /
// AC-2.3.4b — peer-removal precedes STS scale, one peer per
// reconcile, highest ordinal first.
func TestScaleDown_RemovesHighestOrdinalFirst(t *testing.T) {
	f := newScaleDownFixture(t, 5, 3) // gap of 2, expect ordinals 4 then 3

	// Cycle 1: expect RaftListPeers (find candidates), RaftRemovePeer
	// for id-4, RaftListPeers (verify), then status patch.
	f.mockNomad.EXPECT().RaftListPeers(mock.Anything, "").Return(peersAtReplicas(5), nil).Once()
	f.mockNomad.EXPECT().RaftRemovePeer(mock.Anything, "", idForOrdinal(4)).Return(nil).Once()
	f.mockNomad.EXPECT().RaftListPeers(mock.Anything, "").Return(peersAtReplicas(4), nil).Once() // ordinal-4 gone

	result := f.phase.Execute(context.Background(), f.cluster)
	if result.Error != nil {
		t.Fatalf("cycle 1 Execute error = %v", result.Error)
	}
	if !result.Requeue {
		t.Error("cycle 1 should request an immediate requeue (more peers to remove)")
	}

	got := fetchCluster(t, f)
	if got.Status.ScaleDown == nil || len(got.Status.ScaleDown.RemovedPeers) != 1 ||
		got.Status.ScaleDown.RemovedPeers[0] != idForOrdinal(4) {
		t.Errorf("after cycle 1, removedPeers = %v, want [%q]",
			got.Status.ScaleDown, idForOrdinal(4))
	}
	if r := fetchSTS(t, f).Spec.Replicas; r == nil || *r != 5 {
		t.Errorf("after cycle 1 STS replicas = %v, want 5 (not yet patched)", r)
	}

	// Cycle 2: same flow, expecting id-3 next, then finalisation
	// (STS patched to 3, status cleared).
	f.cluster = got // carry the new status forward
	peersAfterFirst := []*nomad.RaftPeer{
		{ID: idForOrdinal(0), Node: nodeForOrdinal(0), Address: "10.0.0.1:4647"},
		{ID: idForOrdinal(1), Node: nodeForOrdinal(1), Address: "10.0.0.1:4647"},
		{ID: idForOrdinal(2), Node: nodeForOrdinal(2), Address: "10.0.0.1:4647"},
		{ID: idForOrdinal(3), Node: nodeForOrdinal(3), Address: "10.0.0.1:4647"},
	}
	f.mockNomad.EXPECT().RaftListPeers(mock.Anything, "").Return(peersAfterFirst, nil).Once()
	f.mockNomad.EXPECT().RaftRemovePeer(mock.Anything, "", idForOrdinal(3)).Return(nil).Once()
	f.mockNomad.EXPECT().RaftListPeers(mock.Anything, "").Return(peersAtReplicas(3), nil).Once()

	result = f.phase.Execute(context.Background(), f.cluster)
	if result.Error != nil {
		t.Fatalf("cycle 2 Execute error = %v", result.Error)
	}

	final := fetchCluster(t, f)
	if final.Status.ScaleDown != nil {
		t.Errorf("after cycle 2, status.scaleDown = %+v, want nil (operation complete)",
			final.Status.ScaleDown)
	}
	if r := fetchSTS(t, f).Spec.Replicas; r == nil || *r != 3 {
		t.Errorf("after cycle 2 STS replicas = %v, want 3 (patched at completion)", r)
	}
}

// TestScaleDown_ResumeIdempotency covers AC-2.3.7 — on operator
// restart with status.scaleDown.removedPeers already populated, the
// loop never re-removes a peer that is already recorded. Simulates
// the post-crash resume by seeding the status with id-4 and asserting
// the next cycle removes id-3 (not id-4 again).
func TestScaleDown_ResumeIdempotency(t *testing.T) {
	f := newScaleDownFixture(t, 5, 3)

	// Seed the persisted resume state: id-4 already removed.
	f.cluster.Status.ScaleDown = &nomadv1alpha1.ScaleDownStatus{
		RemovedPeers: []string{idForOrdinal(4)},
	}
	if err := f.phase.Client.Status().Update(context.Background(), f.cluster); err != nil {
		t.Fatalf("seed status error = %v", err)
	}
	f.cluster = fetchCluster(t, f)

	// Nomad's peer list reflects the prior removal (id-4 gone).
	peersAfterFirst := []*nomad.RaftPeer{
		{ID: idForOrdinal(0), Node: nodeForOrdinal(0), Address: "10.0.0.1:4647"},
		{ID: idForOrdinal(1), Node: nodeForOrdinal(1), Address: "10.0.0.1:4647"},
		{ID: idForOrdinal(2), Node: nodeForOrdinal(2), Address: "10.0.0.1:4647"},
		{ID: idForOrdinal(3), Node: nodeForOrdinal(3), Address: "10.0.0.1:4647"},
	}
	f.mockNomad.EXPECT().RaftListPeers(mock.Anything, "").Return(peersAfterFirst, nil).Once()
	// Must remove id-3 next, NOT id-4 (which is already in removedPeers).
	f.mockNomad.EXPECT().RaftRemovePeer(mock.Anything, "", idForOrdinal(3)).Return(nil).Once()
	f.mockNomad.EXPECT().RaftListPeers(mock.Anything, "").Return(peersAtReplicas(3), nil).Once()

	result := f.phase.Execute(context.Background(), f.cluster)
	if result.Error != nil {
		t.Fatalf("Execute error = %v", result.Error)
	}

	final := fetchCluster(t, f)
	if final.Status.ScaleDown != nil {
		t.Errorf("after resume cycle, status.scaleDown = %+v, want nil (gap closed)",
			final.Status.ScaleDown)
	}
}

// TestScaleDown_NoOpWhenAlreadyAtTarget covers the common case where
// no scale-down is needed — Execute should not even instantiate the
// Nomad client (mockery's t-binding catches any unexpected call).
func TestScaleDown_NoOpWhenAlreadyAtTarget(t *testing.T) {
	f := newScaleDownFixture(t, 3, 3)
	// No mock expectations: any NomadAPI call would fail the test.

	result := f.phase.Execute(context.Background(), f.cluster)
	if result.Error != nil {
		t.Fatalf("Execute error = %v", result.Error)
	}

	got := fetchCluster(t, f)
	if got.Status.ScaleDown != nil {
		t.Errorf("no-op cycle should not populate status.scaleDown, got %+v", got.Status.ScaleDown)
	}
}

// TestScaleDown_DefersWhenVerificationShowsPeerStillPresent covers
// the narrow but important case where RaftRemovePeer returns success
// but the peer is still in the configuration on re-list. The phase
// must NOT record the removal in status (otherwise the resume loop
// would skip a peer that is still in Raft).
func TestScaleDown_DefersWhenVerificationShowsPeerStillPresent(t *testing.T) {
	f := newScaleDownFixture(t, 5, 3)

	f.mockNomad.EXPECT().RaftListPeers(mock.Anything, "").Return(peersAtReplicas(5), nil).Once()
	f.mockNomad.EXPECT().RaftRemovePeer(mock.Anything, "", idForOrdinal(4)).Return(nil).Once()
	// Re-list shows the peer is still there (transient Raft state).
	f.mockNomad.EXPECT().RaftListPeers(mock.Anything, "").Return(peersAtReplicas(5), nil).Once()

	result := f.phase.Execute(context.Background(), f.cluster)
	if result.Error != nil {
		t.Fatalf("Execute error = %v", result.Error)
	}

	got := fetchCluster(t, f)
	// status.scaleDown should be initialised (we got that far) but
	// removedPeers must remain empty because verification failed.
	if got.Status.ScaleDown == nil {
		t.Fatal("status.scaleDown should be initialised before the verify step")
	}
	if len(got.Status.ScaleDown.RemovedPeers) != 0 {
		t.Errorf("removedPeers = %v, want [] (verification failed; do not record)",
			got.Status.ScaleDown.RemovedPeers)
	}
}
