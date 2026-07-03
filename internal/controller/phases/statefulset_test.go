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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

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

	threeRep := newTestCluster("ns", "nomad")
	threeRep.Spec.Replicas = 3

	oneRep := newTestCluster("ns", "nomad")
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
			cluster := newTestCluster("ns", "nomad")
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

// TestStatefulSetScaleUp covers neo-i4a: increasing spec.replicas must
// flow straight through to the StatefulSet — the D2b guard only
// preserves the existing count while it EXCEEDS the desired count
// (scale-down territory); an up-scale is a plain update.
func TestStatefulSetScaleUp(t *testing.T) {
	cluster := newTestCluster("ns", "nomad")
	cluster.Spec.Replicas = 1

	phaseCtx := &PhaseContext{
		Client:           fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(),
		Scheme:           scheme.Scheme,
		Log:              zap.New(zap.UseDevMode(true)),
		AdvertiseAddress: "10.0.0.5",
		GossipKey:        "fixed-gossip-key-for-test==",
	}
	phase := &StatefulSetPhase{PhaseContext: phaseCtx}

	// Create at 1 replica.
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatalf("Execute() create error = %v", result.Error)
	}

	// Scale up to 3.
	cluster.Spec.Replicas = 3
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatalf("Execute() scale-up error = %v", result.Error)
	}

	sts := &appsv1.StatefulSet{}
	if err := phaseCtx.Client.Get(context.Background(),
		types.NamespacedName{Name: "nomad", Namespace: "ns"}, sts); err != nil {
		t.Fatalf("StatefulSet missing: %v", err)
	}
	if sts.Spec.Replicas == nil || *sts.Spec.Replicas != 3 {
		t.Errorf("sts replicas = %v after scale-up, want 3", sts.Spec.Replicas)
	}
}

// TestPodSecurityContexts covers neo-8xu: both workload pod specs meet
// PSS "restricted" — runAsNonRoot + RuntimeDefault seccomp at pod
// level, no privilege escalation + ALL capabilities dropped +
// read-only root at container level. Identity fields (runAsUser,
// fsGroup) are set explicitly on vanilla Kubernetes and deliberately
// LEFT UNSET on OpenShift, where the SCC injects them from the
// namespace's allocated range.
func TestPodSecurityContexts(t *testing.T) {
	build := func(openshift bool) *appsv1.StatefulSet {
		cluster := newTestCluster("ns", "sec")
		cluster.Spec.OpenShift.Enabled = openshift
		phase := &StatefulSetPhase{PhaseContext: &PhaseContext{
			Client: fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(),
			Scheme: scheme.Scheme,
			Log:    zap.New(zap.UseDevMode(true)),
		}}
		return phase.buildStatefulSet(context.Background(), cluster)
	}

	for _, tc := range []struct {
		name        string
		openshift   bool
		wantUserSet bool
	}{
		{"vanilla sets explicit non-root identity", false, true},
		{"openshift leaves identity to the SCC", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sts := build(tc.openshift)
			pod := sts.Spec.Template.Spec

			sc := pod.SecurityContext
			if sc == nil || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
				t.Fatal("pod runAsNonRoot must be true")
			}
			if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
				t.Fatal("pod seccompProfile must be RuntimeDefault")
			}
			if got := sc.RunAsUser != nil; got != tc.wantUserSet {
				t.Errorf("runAsUser set = %v, want %v", got, tc.wantUserSet)
			}
			if got := sc.FSGroup != nil; got != tc.wantUserSet {
				t.Errorf("fsGroup set = %v, want %v", got, tc.wantUserSet)
			}

			c := pod.Containers[0].SecurityContext
			if c == nil || c.AllowPrivilegeEscalation == nil || *c.AllowPrivilegeEscalation {
				t.Fatal("container allowPrivilegeEscalation must be false")
			}
			if c.ReadOnlyRootFilesystem == nil || !*c.ReadOnlyRootFilesystem {
				t.Fatal("container readOnlyRootFilesystem must be true")
			}
			if c.Capabilities == nil || len(c.Capabilities.Drop) != 1 || c.Capabilities.Drop[0] != "ALL" {
				t.Fatal("container must drop ALL capabilities")
			}

			// Read-only root needs the /tmp scratch mount.
			var tmpMounted bool
			for _, m := range pod.Containers[0].VolumeMounts {
				if m.MountPath == "/tmp" {
					tmpMounted = true
				}
			}
			if !tmpMounted {
				t.Error("read-only root filesystem requires a /tmp scratch mount")
			}
		})
	}
}

// TestImageRef covers neo-4xj: digest pinning takes precedence over the
// tag; without a digest the tag reference is unchanged. Both workloads
// build their reference through this one function.
func TestImageRef(t *testing.T) {
	cases := []struct {
		name   string
		digest string
		want   string
	}{
		{"tag only", "", "hashicorp/nomad:2.0.3-ent"},
		{"digest pinned wins over tag", "sha256:" + strings.Repeat("ab", 32), "hashicorp/nomad@sha256:" + strings.Repeat("ab", 32)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cluster := newTestCluster("ns", "img")
			cluster.Spec.Image.Repository = "hashicorp/nomad"
			cluster.Spec.Image.Tag = "2.0.3-ent"
			cluster.Spec.Image.Digest = tc.digest
			if got := ImageRef(cluster); got != tc.want {
				t.Errorf("ImageRef() = %q, want %q", got, tc.want)
			}
		})
	}

	// Rendered into the StatefulSet container.
	cluster := newTestCluster("ns", "img")
	cluster.Spec.Image.Repository = "hashicorp/nomad"
	cluster.Spec.Image.Digest = "sha256:" + strings.Repeat("cd", 32)
	phase := &StatefulSetPhase{PhaseContext: &PhaseContext{
		Client: fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(),
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}}
	sts := phase.buildStatefulSet(context.Background(), cluster)
	if got := sts.Spec.Template.Spec.Containers[0].Image; got != "hashicorp/nomad@sha256:"+strings.Repeat("cd", 32) {
		t.Errorf("StatefulSet image = %q, want digest reference", got)
	}
}
