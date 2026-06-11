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

	"k8s.io/client-go/kubernetes/scheme"
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
