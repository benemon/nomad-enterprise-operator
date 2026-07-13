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
	"fmt"
	"strings"
	"testing"

	hclparse "github.com/hashicorp/hcl"
	hclgen "github.com/hashicorp/nomad-enterprise-operator/pkg/hcl"
	"k8s.io/utils/ptr"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// TestBuildStatefulSet_ChecksumExcludesReplicas: clusters differing
// only in spec.replicas must produce identical checksum/config — a
// scale-triggered rolling restart races the scale-down loop and can
// break quorum. New ConfigChecksum inputs must preserve this.
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

// Liveness must be leader-independent (neo-pl4): /v1/agent/health
// 500s during a leaderless window, so an HTTP liveness check kills
// healthy followers mid-election and cascades one OOM into quorum
// loss. Readiness keeps the leader-gated endpoint.
func TestServerProbes(t *testing.T) {
	phase := &StatefulSetPhase{PhaseContext: &PhaseContext{
		Client: fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(),
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}}
	sts := phase.buildStatefulSet(context.Background(), newTestCluster("ns", "probes"))
	c := sts.Spec.Template.Spec.Containers[0]

	live := c.LivenessProbe
	if live == nil || live.TCPSocket == nil || live.TCPSocket.Port.IntValue() != 4646 {
		t.Fatalf("liveness must be a TCP check on 4646, got %+v", live)
	}
	if live.HTTPGet != nil {
		t.Fatal("liveness must not use the leader-dependent HTTP health endpoint")
	}

	ready := c.ReadinessProbe
	if ready == nil || ready.HTTPGet == nil {
		t.Fatalf("readiness must be an HTTP check, got %+v", ready)
	}
	if ready.HTTPGet.Path != "/v1/agent/health" || ready.HTTPGet.Scheme != corev1.URISchemeHTTPS {
		t.Errorf("readiness must gate on HTTPS /v1/agent/health, got %s %s", ready.HTTPGet.Scheme, ready.HTTPGet.Path)
	}
}

// Existing installs carry the pre-fix HTTP liveness shape; needsUpdate
// must report it as drift so the fix converges on operator upgrade,
// and must not report drift once converged (no restart churn).
func TestNeedsUpdateLivenessHandler(t *testing.T) {
	phase := &StatefulSetPhase{PhaseContext: &PhaseContext{
		Client: fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(),
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}}
	desired := phase.buildStatefulSet(context.Background(), newTestCluster("ns", "probes"))

	converged := desired.DeepCopy()
	// API-server defaulting of numeric probe fields must not read as drift.
	converged.Spec.Template.Spec.Containers[0].LivenessProbe.SuccessThreshold = 1
	if update, reason := phase.needsUpdate(converged, desired); update {
		t.Errorf("converged probe shape reported as drift: %s", reason)
	}

	stale := desired.DeepCopy()
	stale.Spec.Template.Spec.Containers[0].LivenessProbe.ProbeHandler = corev1.ProbeHandler{
		HTTPGet: &corev1.HTTPGetAction{
			Path:   "/v1/agent/health",
			Port:   intstr.FromInt(4646),
			Scheme: corev1.URISchemeHTTPS,
		},
	}
	update, reason := phase.needsUpdate(stale, desired)
	if !update {
		t.Fatal("pre-fix HTTP liveness handler must be reported as drift")
	}
	if reason != "liveness probe handler" {
		t.Errorf("unexpected drift reason %q", reason)
	}
}

// Toggling spec.openshift.enabled changes the rendered pod
// securityContext (fixed UID/fsGroup vs SCC-assigned); needsUpdate must
// report that as drift so the toggle reaches a live StatefulSet — on
// OpenShift the pre-toggle template is SCC-rejected outright, so
// without convergence the pod can never schedule (neo-8nc). A
// converged pair must not read as drift (no restart churn).
func TestNeedsUpdateSecurityContext(t *testing.T) {
	phase := &StatefulSetPhase{PhaseContext: &PhaseContext{
		Client: fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(),
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}}
	vanilla := newTestCluster("ns", "scc")
	openshift := newTestCluster("ns", "scc")
	openshift.Spec.OpenShift.Enabled = true

	existing := phase.buildStatefulSet(context.Background(), vanilla)
	desired := phase.buildStatefulSet(context.Background(), openshift)

	update, reason := phase.needsUpdate(existing, desired)
	if !update {
		t.Fatal("openshift.enabled toggle must be reported as securityContext drift")
	}
	if reason != "pod securityContext" {
		t.Errorf("unexpected drift reason %q", reason)
	}

	converged := desired.DeepCopy()
	if update, reason := phase.needsUpdate(converged, desired); update {
		t.Errorf("converged securityContext reported as drift: %s", reason)
	}

	stale := desired.DeepCopy()
	stale.Spec.Template.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem = nil
	update, reason = phase.needsUpdate(stale, desired)
	if !update {
		t.Fatal("container securityContext drift must be reported")
	}
	if reason != "container securityContext" {
		t.Errorf("unexpected drift reason %q", reason)
	}
}

// The audit claim template must exist whenever audit is enabled,
// independent of data persistence — nesting it under persistence once
// produced audit mounts with no backing claim.
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
			cluster.Spec.Server.Audit.Enabled = ptr.To(tc.audit)
			if tc.audit {
				cluster.Spec.Server.Audit.Size = "5Gi"
			}

			templates := phase.buildVolumeClaimTemplates(cluster)

			got := make([]string, 0, len(templates))
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

// Both workloads meet PSS restricted; identity fields are explicit on
// vanilla and deliberately unset on OpenShift (SCC injects them).
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
		{"tag only", "", "hashicorp/nomad:2.0.4-ent"},
		{"digest pinned wins over tag", "sha256:" + strings.Repeat("ab", 32), "hashicorp/nomad@sha256:" + strings.Repeat("ab", 32)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cluster := newTestCluster("ns", "img")
			cluster.Spec.Image.Repository = "hashicorp/nomad"
			cluster.Spec.Image.Tag = "2.0.4-ent"
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

// GH #11: the startup command must strip the pod's own FQDN from
// retry_join — Nomad counts a self-join as success and stops retrying,
// so a parallel pod start loses the peer-DNS race and quorum never
// forms. Also asserts the filtered copy targets a writable,
// memory-backed mount (the rendered config carries the gossip key).
func TestServerCommand_FiltersSelfFromRetryJoin(t *testing.T) {
	phase := &StatefulSetPhase{PhaseContext: newTestPhaseContext()}
	cluster := newTestCluster("neo-smoke", "nomad")

	sts := phase.buildStatefulSet(context.Background(), cluster)
	cmd := sts.Spec.Template.Spec.Containers[0].Command
	if len(cmd) != 3 || cmd[0] != "/bin/sh" || cmd[1] != "-ec" {
		t.Fatalf("command = %v, want [/bin/sh -ec <script>]", cmd)
	}
	script := cmd[2]
	wantFilter := `grep -vF "\"${POD_NAME}.nomad-headless.neo-smoke.svc.cluster.local\""`
	if !strings.Contains(script, wantFilter) {
		t.Errorf("script missing self-FQDN filter %q:\n%s", wantFilter, script)
	}
	if !strings.Contains(script, "exec nomad agent -config=/nomad/config-runtime/server.hcl") {
		t.Errorf("script must exec nomad against the filtered copy:\n%s", script)
	}

	var vol *corev1.Volume
	for i := range sts.Spec.Template.Spec.Volumes {
		if sts.Spec.Template.Spec.Volumes[i].Name == "config-runtime" {
			vol = &sts.Spec.Template.Spec.Volumes[i]
		}
	}
	if vol == nil || vol.EmptyDir == nil ||
		vol.EmptyDir.Medium != corev1.StorageMediumMemory {
		t.Fatalf("config-runtime volume missing or not memory-backed: %+v", vol)
	}
	mounted := false
	for _, m := range sts.Spec.Template.Spec.Containers[0].VolumeMounts {
		if m.Name == "config-runtime" && m.MountPath == "/nomad/config-runtime" && !m.ReadOnly {
			mounted = true
		}
	}
	if !mounted {
		t.Error("config-runtime not mounted writable at /nomad/config-runtime")
	}
}

// Pins the contract between the rendered HCL and the startup filter:
// every retry_join entry sits alone on its own line, so dropping the
// line containing the pod's quoted FQDN removes exactly that entry,
// keeps the peers, and leaves the file valid HCL — including the
// empty-list result at replicas=1.
func TestRetryJoinSelfFilter_RenderedConfigContract(t *testing.T) {
	for _, replicas := range []int32{1, 3} {
		cluster := newTestCluster("neo-smoke", "nomad")
		cluster.Spec.Replicas = replicas
		rendered, err := hclgen.NewGenerator(cluster, "10.0.0.5", "gossip-key==").Generate()
		if err != nil {
			t.Fatalf("replicas=%d: Generate() error: %v", replicas, err)
		}
		for i := int32(0); i < replicas; i++ {
			pod := fmt.Sprintf("nomad-%d", i)
			// grep -vF pattern after the shell expands ${POD_NAME}
			needle := fmt.Sprintf("%q", pod+".nomad-headless.neo-smoke.svc.cluster.local")
			var kept []string
			removed := 0
			for _, line := range strings.Split(rendered, "\n") {
				if strings.Contains(line, needle) {
					removed++
					continue
				}
				kept = append(kept, line)
			}
			if removed != 1 {
				t.Fatalf("pod %s (replicas=%d): filter removed %d lines, want exactly 1", pod, replicas, removed)
			}
			filtered := strings.Join(kept, "\n")
			for j := int32(0); j < replicas; j++ {
				peer := fmt.Sprintf("nomad-%d.nomad-headless.neo-smoke.svc.cluster.local", j)
				has := strings.Contains(filtered, peer)
				if j == i && has {
					t.Errorf("pod %s: own FQDN still present after filter", pod)
				}
				if j != i && !has {
					t.Errorf("pod %s: peer %s missing after filter", pod, peer)
				}
			}
			if _, err := hclparse.Parse(filtered); err != nil {
				t.Errorf("pod %s (replicas=%d): filtered config is not valid HCL: %v", pod, replicas, err)
			}
		}
	}
}

// The GH #11 fix ships as a command change, which needsUpdate ignored
// before — without this check it never reaches a live StatefulSet.
func TestNeedsUpdate_CommandDrift(t *testing.T) {
	phase := &StatefulSetPhase{PhaseContext: newTestPhaseContext()}
	cluster := newTestCluster("ns", "nomad")
	desired := phase.buildStatefulSet(context.Background(), cluster)
	existing := desired.DeepCopy()

	if update, reason := phase.needsUpdate(existing, desired); update {
		t.Fatalf("identical specs reported drift: %q", reason)
	}

	existing.Spec.Template.Spec.Containers[0].Command = []string{"nomad", "agent", "-config=/nomad/config"}
	update, reason := phase.needsUpdate(existing, desired)
	if !update || reason != "container command" {
		t.Errorf("update=%v reason=%q, want update=true reason=%q", update, reason, "container command")
	}
}
