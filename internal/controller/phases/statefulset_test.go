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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// TestBuildStatefulSet_ChecksumExcludesReplicas covers AC-2.3.4f
// (D2f / neo-1ve.6 / neo-8oy): scale operations must not regenerate
// the pod template's checksum/config annotation. Without this, every
// spec.replicas change triggers a rolling restart of all existing
// pods — neo-8oy is the canonical break, where the rolling restart
// of a 3-replica cluster racing with the scale-down loop causes Raft
// quorum loss and unrecoverable cluster state.
//
// The test builds two StatefulSets from clusters that differ ONLY in
// spec.replicas (3 vs 1) and asserts checksum/config is identical.
// Any future input added to ConfigChecksum's map must preserve this
// invariant or carry its own regression test justifying the choice.
func TestBuildStatefulSet_ChecksumExcludesReplicas(t *testing.T) {
	phaseCtx := &PhaseContext{
		Client:           fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(),
		Scheme:           scheme.Scheme,
		Log:              zap.New(zap.UseDevMode(true)),
		AdvertiseAddress: "10.0.0.5",
		GossipKey:        "fixed-gossip-key-for-test==",
	}
	phase := &StatefulSetPhase{PhaseContext: phaseCtx}

	threeRep := newTestCluster("nomad", "ns")
	threeRep.Spec.Replicas = 3

	oneRep := newTestCluster("nomad", "ns")
	oneRep.Spec.Replicas = 1

	stsThree := phase.buildStatefulSet(context.Background(), threeRep)
	stsOne := phase.buildStatefulSet(context.Background(), oneRep)

	checksumThree := stsThree.Spec.Template.Annotations["checksum/config"]
	checksumOne := stsOne.Spec.Template.Annotations["checksum/config"]

	if checksumThree == "" {
		t.Fatal("checksum/config annotation missing on 3-replica STS")
	}
	if checksumThree != checksumOne {
		t.Errorf("checksum/config drifted across replica counts: %q (N=3) vs %q (N=1) — scale operations must not trigger pod restarts (AC-2.3.4f)",
			checksumThree, checksumOne)
	}
}

// TestAuditPVCIndependent covers AC-4.5.1 (B6 / neo-av7): the audit
// PVC claim template must be present whenever audit is enabled,
// regardless of whether data persistence is enabled. Before B6 the
// audit PVC was nested inside the persistence-enabled branch, so
// audit-enabled clusters with persistence.size="" produced a pod spec
// that mounted an "audit" volume with no backing claim template.
func TestAuditPVCIndependent(t *testing.T) {
	cases := []struct {
		name        string
		persistence bool
		audit       bool
		want        []string // expected claim template names, in order
	}{
		{"persistence on, audit on", true, true, []string{"data", "audit"}},
		{"persistence on, audit off", true, false, []string{"data"}},
		{"persistence off, audit on", false, true, []string{"audit"}},
		{"persistence off, audit off", false, false, nil},
	}

	phase := &StatefulSetPhase{PhaseContext: &PhaseContext{
		Log: zap.New(zap.UseDevMode(true)),
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cluster := newTestCluster("nomad", "ns")
			if tc.persistence {
				cluster.Spec.Persistence.Size = "10Gi"
			}
			cluster.Spec.Server.Audit.Enabled = tc.audit
			if tc.audit {
				cluster.Spec.Server.Audit.Size = "5Gi"
			}

			templates := phase.buildVolumeClaimTemplates(cluster)

			var got []string
			for _, tmpl := range templates {
				got = append(got, tmpl.Name)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("claim templates = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("claim templates = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// TestMaybeMarkAuditPVCMigrated covers AC-4.5.4 (B6 / neo-av7): the
// AuditPVCCreated Event fires exactly once — on first observation of
// a Bound audit PVC — and the status.auditPVCMigrated marker
// suppresses re-emission thereafter (including across operator
// restarts, which is why the debounce is a status field and not
// operator memory).
func TestMaybeMarkAuditPVCMigrated(t *testing.T) {
	boundPVC := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "audit-nomad-0", Namespace: "ns"},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	}
	pendingPVC := boundPVC.DeepCopy()
	pendingPVC.Status.Phase = corev1.ClaimPending

	newPhase := func(objs ...client.Object) (*StatefulSetPhase, *record.FakeRecorder) {
		recorder := record.NewFakeRecorder(5)
		return &StatefulSetPhase{PhaseContext: &PhaseContext{
			Client:   fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(objs...).Build(),
			Log:      zap.New(zap.UseDevMode(true)),
			Recorder: recorder,
		}}, recorder
	}

	drainEvents := func(recorder *record.FakeRecorder) []string {
		var events []string
		for {
			select {
			case e := <-recorder.Events:
				events = append(events, e)
			default:
				return events
			}
		}
	}

	t.Run("bound PVC emits event once and sets marker", func(t *testing.T) {
		phase, recorder := newPhase(boundPVC.DeepCopy())
		cluster := newTestCluster("nomad", "ns")
		cluster.Spec.Server.Audit.Enabled = true

		phase.maybeMarkAuditPVCMigrated(context.Background(), cluster)

		if !cluster.Status.AuditPVCMigrated {
			t.Fatal("status.auditPVCMigrated not set after bound PVC observed")
		}
		events := drainEvents(recorder)
		if len(events) != 1 || !strings.Contains(events[0], "AuditPVCCreated") {
			t.Fatalf("events = %v, want exactly one AuditPVCCreated", events)
		}

		// Second reconcile (simulating operator restart: marker persisted
		// on status) — no re-emission.
		phase.maybeMarkAuditPVCMigrated(context.Background(), cluster)
		if events := drainEvents(recorder); len(events) != 0 {
			t.Fatalf("marker did not suppress re-emission, got %v", events)
		}
	})

	t.Run("pending PVC does not emit or mark", func(t *testing.T) {
		phase, recorder := newPhase(pendingPVC.DeepCopy())
		cluster := newTestCluster("nomad", "ns")
		cluster.Spec.Server.Audit.Enabled = true

		phase.maybeMarkAuditPVCMigrated(context.Background(), cluster)

		if cluster.Status.AuditPVCMigrated {
			t.Fatal("marker set while PVC still Pending")
		}
		if events := drainEvents(recorder); len(events) != 0 {
			t.Fatalf("unexpected events for pending PVC: %v", events)
		}
	})

	t.Run("missing PVC does not emit or mark", func(t *testing.T) {
		phase, recorder := newPhase()
		cluster := newTestCluster("nomad", "ns")
		cluster.Spec.Server.Audit.Enabled = true

		phase.maybeMarkAuditPVCMigrated(context.Background(), cluster)

		if cluster.Status.AuditPVCMigrated {
			t.Fatal("marker set with no PVC present")
		}
		if events := drainEvents(recorder); len(events) != 0 {
			t.Fatalf("unexpected events for missing PVC: %v", events)
		}
	})

	t.Run("audit disabled is a no-op", func(t *testing.T) {
		phase, recorder := newPhase(boundPVC.DeepCopy())
		cluster := newTestCluster("nomad", "ns")
		cluster.Spec.Server.Audit.Enabled = false

		phase.maybeMarkAuditPVCMigrated(context.Background(), cluster)

		if cluster.Status.AuditPVCMigrated {
			t.Fatal("marker set while audit disabled")
		}
		if events := drainEvents(recorder); len(events) != 0 {
			t.Fatalf("unexpected events while audit disabled: %v", events)
		}
	})
}
