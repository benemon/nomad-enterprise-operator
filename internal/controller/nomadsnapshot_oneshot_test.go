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
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/internal/controller/phases"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad/mocks"
)

// D3 (neo-kk7) unit tests, driven at the reconcileOneShot /
// reconcileRecurring level with a fake client: the Nomad-token
// machinery above that point is orthogonal and already covered by the
// existing NomadSnapshot suite.

func newOneShotSnapshot(name string) *nomadv1alpha1.NomadSnapshot {
	return &nomadv1alpha1.NomadSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "snap-ns"},
		Spec: nomadv1alpha1.NomadSnapshotSpec{
			ClusterRef: nomadv1alpha1.ClusterReference{Name: "test-cluster"},
			Target: nomadv1alpha1.SnapshotTarget{
				S3: &nomadv1alpha1.SnapshotS3Config{Bucket: "b", Region: "eu-west-1"},
			},
		},
	}
}

func newSnapshotReconciler(objs ...client.Object) (*NomadSnapshotReconciler, *record.FakeRecorder) {
	// Plain Go tests can run before the envtest suite's BeforeSuite
	// registers the CRD types; AddToScheme is idempotent.
	_ = nomadv1alpha1.AddToScheme(scheme.Scheme)
	builder := fake.NewClientBuilder().WithScheme(scheme.Scheme)
	for _, o := range objs {
		builder = builder.WithObjects(o)
		if snap, ok := o.(*nomadv1alpha1.NomadSnapshot); ok {
			builder = builder.WithStatusSubresource(snap)
		}
	}
	recorder := record.NewFakeRecorder(5)
	return &NomadSnapshotReconciler{
		Client:   builder.Build(),
		Scheme:   scheme.Scheme,
		Recorder: recorder,
	}, recorder
}

// TestSnapshotOneShotCreatesJob covers AC-2.7.1 / AC-2.7.5: with
// spec.schedule omitted, reconciliation creates a one-shot Job (bounded
// retries, OnFailure restart, checksum annotation) and status reflects
// the operation.
func TestSnapshotOneShotCreatesJob(t *testing.T) {
	snap := newOneShotSnapshot("oneshot")
	cluster := newTestCluster("snap-ns", "test-cluster")
	r, _ := newSnapshotReconciler(snap, cluster)

	if _, err := r.reconcileOneShot(context.Background(), snap, cluster, "https://addr:4646", "cafe1234", "s"); err != nil {
		t.Fatalf("reconcileOneShot() error = %v", err)
	}

	job := &batchv1.Job{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "oneshot-snapshot", Namespace: "snap-ns"}, job); err != nil {
		t.Fatalf("expected Job created: %v", err)
	}
	if job.Spec.Template.Spec.RestartPolicy != corev1.RestartPolicyOnFailure {
		t.Errorf("restartPolicy = %v, want OnFailure", job.Spec.Template.Spec.RestartPolicy)
	}
	if job.Spec.BackoffLimit == nil || *job.Spec.BackoffLimit != 3 {
		t.Errorf("backoffLimit = %v, want 3", job.Spec.BackoffLimit)
	}
	if got := job.Spec.Template.Annotations["checksum/config"]; got != "cafe1234" {
		t.Errorf("checksum/config = %q, want %q", got, "cafe1234")
	}

	if snap.Status.Operation != nomadv1alpha1.SnapshotOperationJob {
		t.Errorf("status.operation = %q, want Job", snap.Status.Operation)
	}
	if snap.Status.JobName != "oneshot-snapshot" {
		t.Errorf("status.jobName = %q, want oneshot-snapshot", snap.Status.JobName)
	}
	if snap.Status.Phase != nomadv1alpha1.SnapshotPhaseRunning {
		t.Errorf("status.phase = %q, want Running", snap.Status.Phase)
	}
}

// TestSnapshotStatusFromJob covers AC-2.7.5 / AC-2.7.8: terminal Job
// states map to phase Succeeded/Failed; failure raises the Degraded
// condition and emits a Warning Event exactly once.
func TestSnapshotStatusFromJob(t *testing.T) {
	now := metav1.Now()

	t.Run("succeeded", func(t *testing.T) {
		snap := newOneShotSnapshot("done")
		cluster := newTestCluster("snap-ns", "test-cluster")
		cluster.Status.NomadVersion = "2.0.4-ent"
		job := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: "done-snapshot", Namespace: "snap-ns"},
			Status:     batchv1.JobStatus{Succeeded: 1, CompletionTime: &now},
		}
		r, recorder := newSnapshotReconciler(snap, cluster, job)

		if _, err := r.reconcileOneShot(context.Background(), snap, cluster, "https://addr:4646", "c", "s"); err != nil {
			t.Fatalf("reconcileOneShot() error = %v", err)
		}
		if snap.Status.Phase != nomadv1alpha1.SnapshotPhaseSucceeded {
			t.Errorf("phase = %q, want Succeeded", snap.Status.Phase)
		}
		if snap.Status.LastSnapshot == nil || snap.Status.LastSnapshot.Status != "Success" {
			t.Errorf("lastSnapshot = %+v, want Success", snap.Status.LastSnapshot)
		}
		// Same-version restore rule: the artifact record freezes the
		// version; the top-level mirror tracks the cluster.
		if snap.Status.LastSnapshot.NomadVersion != "2.0.4-ent" {
			t.Errorf("lastSnapshot.nomadVersion = %q, want 2.0.4-ent", snap.Status.LastSnapshot.NomadVersion)
		}
		if snap.Status.NomadVersion != "2.0.4-ent" {
			t.Errorf("status.nomadVersion = %q, want 2.0.4-ent", snap.Status.NomadVersion)
		}
		if len(recorder.Events) != 0 {
			t.Error("unexpected event on success")
		}
	})

	t.Run("version unknown stays unset", func(t *testing.T) {
		snap := newOneShotSnapshot("noversion")
		cluster := newTestCluster("snap-ns", "test-cluster") // no probe yet
		job := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: "noversion-snapshot", Namespace: "snap-ns"},
			Status:     batchv1.JobStatus{Succeeded: 1, CompletionTime: &now},
		}
		r, _ := newSnapshotReconciler(snap, cluster, job)
		if _, err := r.reconcileOneShot(context.Background(), snap, cluster, "https://addr:4646", "c", "s"); err != nil {
			t.Fatalf("reconcileOneShot() error = %v", err)
		}
		if snap.Status.NomadVersion != "" || snap.Status.LastSnapshot.NomadVersion != "" {
			t.Errorf("unknown version must stay unset, got %q/%q",
				snap.Status.NomadVersion, snap.Status.LastSnapshot.NomadVersion)
		}
	})

	t.Run("failed raises Degraded and emits one Event", func(t *testing.T) {
		snap := newOneShotSnapshot("broken")
		cluster := newTestCluster("snap-ns", "test-cluster")
		job := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: "broken-snapshot", Namespace: "snap-ns"},
			Status: batchv1.JobStatus{Failed: 4, Conditions: []batchv1.JobCondition{
				{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
			}},
		}
		r, recorder := newSnapshotReconciler(snap, cluster, job)

		for i := 0; i < 2; i++ { // second pass must not re-emit
			if _, err := r.reconcileOneShot(context.Background(), snap, cluster, "https://addr:4646", "c", "s"); err != nil {
				t.Fatalf("reconcileOneShot() pass %d error = %v", i, err)
			}
		}
		if snap.Status.Phase != nomadv1alpha1.SnapshotPhaseFailed {
			t.Errorf("phase = %q, want Failed", snap.Status.Phase)
		}
		var degraded bool
		for _, c := range snap.Status.Conditions {
			if c.Type == "Degraded" && c.Status == metav1.ConditionTrue {
				degraded = true
			}
		}
		if !degraded {
			t.Error("Degraded condition not True after Job failure")
		}
		var events []string
		for len(recorder.Events) > 0 {
			events = append(events, <-recorder.Events)
		}
		if len(events) != 1 || !strings.Contains(events[0], "SnapshotDegraded") {
			t.Errorf("events = %v, want exactly one SnapshotDegraded Warning", events)
		}
	})
}

// TestSnapshotModeSwitch covers AC-2.7.3: switching modes in steady
// state deletes the other mode's workload and creates the new one.
func TestSnapshotModeSwitch(t *testing.T) {
	t.Run("recurring to one-shot deletes Deployment", func(t *testing.T) {
		snap := newOneShotSnapshot("flip")
		cluster := newTestCluster("snap-ns", "test-cluster")
		staleDeploy := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "flip-snapshot-agent", Namespace: "snap-ns"},
		}
		r, _ := newSnapshotReconciler(snap, cluster, staleDeploy)

		if _, err := r.reconcileOneShot(context.Background(), snap, cluster, "https://addr:4646", "c", "s"); err != nil {
			t.Fatalf("reconcileOneShot() error = %v", err)
		}

		deploy := &appsv1.Deployment{}
		if err := r.Get(context.Background(), types.NamespacedName{Name: "flip-snapshot-agent", Namespace: "snap-ns"}, deploy); !errors.IsNotFound(err) {
			t.Errorf("stale Deployment still present (err=%v)", err)
		}
		job := &batchv1.Job{}
		if err := r.Get(context.Background(), types.NamespacedName{Name: "flip-snapshot", Namespace: "snap-ns"}, job); err != nil {
			t.Errorf("one-shot Job not created: %v", err)
		}
	})

	t.Run("one-shot to recurring deletes Job", func(t *testing.T) {
		snap := newOneShotSnapshot("flop")
		snap.Spec.Schedule = &nomadv1alpha1.SnapshotSchedule{Interval: "1h", Retain: 24}
		cluster := newTestCluster("snap-ns", "test-cluster")
		staleJob := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: "flop-snapshot", Namespace: "snap-ns"},
			Status:     batchv1.JobStatus{Succeeded: 1},
		}
		r, _ := newSnapshotReconciler(snap, cluster, staleJob)

		if _, err := r.reconcileRecurring(context.Background(), snap, cluster, "https://addr:4646", "c", "s"); err != nil {
			t.Fatalf("reconcileRecurring() error = %v", err)
		}

		job := &batchv1.Job{}
		if err := r.Get(context.Background(), types.NamespacedName{Name: "flop-snapshot", Namespace: "snap-ns"}, job); !errors.IsNotFound(err) {
			t.Errorf("stale Job still present (err=%v)", err)
		}
		deploy := &appsv1.Deployment{}
		if err := r.Get(context.Background(), types.NamespacedName{Name: "flop-snapshot-agent", Namespace: "snap-ns"}, deploy); err != nil {
			t.Errorf("recurring Deployment not created: %v", err)
		}
		if snap.Status.Operation != nomadv1alpha1.SnapshotOperationDeployment {
			t.Errorf("status.operation = %q, want Deployment", snap.Status.Operation)
		}
		if snap.Status.Phase != "" || snap.Status.JobName != "" {
			t.Errorf("one-shot status fields not cleared: phase=%q jobName=%q", snap.Status.Phase, snap.Status.JobName)
		}
	})
}

// TestSnapshotConfigTargetAgnostic covers AC-2.7.4: the target stanzas
// of the generated agent config are byte-identical across modes — only
// the snapshot{} block differs (interval "0" for one-shot).
func TestSnapshotConfigTargetAgnostic(t *testing.T) {
	r := &NomadSnapshotReconciler{}

	oneShot := newOneShotSnapshot("cfg")
	recurring := newOneShotSnapshot("cfg")
	recurring.Spec.Schedule = &nomadv1alpha1.SnapshotSchedule{Interval: "1h", Retain: 24}

	oneShotCfg := r.generateSnapshotConfig(oneShot)
	recurringCfg := r.generateSnapshotConfig(recurring)

	if !strings.Contains(oneShotCfg, `interval = "0"`) {
		t.Errorf("one-shot config missing interval=0:\n%s", oneShotCfg)
	}
	oneShotTarget := oneShotCfg[strings.Index(oneShotCfg, "aws_s3"):]
	recurringTarget := recurringCfg[strings.Index(recurringCfg, "aws_s3"):]
	if oneShotTarget != recurringTarget {
		t.Errorf("target stanzas differ across modes:\none-shot:\n%s\nrecurring:\n%s", oneShotTarget, recurringTarget)
	}

	// AC-2.7.6a foundation: a target change must change the config
	// checksum carried on the pod template, which rolls the Deployment.
	changed := newOneShotSnapshot("cfg")
	changed.Spec.Schedule = recurring.Spec.Schedule
	changed.Spec.Target.S3.Bucket = "other-bucket"
	if phases.ConfigChecksum(map[string]string{"snapshot.hcl": recurringCfg}) ==
		phases.ConfigChecksum(map[string]string{"snapshot.hcl": r.generateSnapshotConfig(changed)}) {
		t.Error("config checksum unchanged after spec.target edit — Deployment would not roll (AC-2.7.6a)")
	}
}

// D3 / AC-2.7.3a: CEL transition rule verified against a real API
// server — adding spec.schedule is rejected while status.phase is
// Running and allowed once the one-shot Job has finished.
var _ = Describe("NomadSnapshot mode-switch admission rule (D3 / AC-2.7.3a)", func() {
	const namespace = "snapshot-admission-test"
	ctx := context.Background()

	BeforeEach(func() {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
		if err := k8sClient.Create(ctx, ns); err != nil && !errors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	It("blocks the switch while the one-shot Job runs, allows it after completion", func() {
		snap := newOneShotSnapshot("modeswitch")
		snap.Namespace = namespace
		Expect(k8sClient.Create(ctx, snap)).To(Succeed())

		key := types.NamespacedName{Name: "modeswitch", Namespace: namespace}
		fetched := &nomadv1alpha1.NomadSnapshot{}
		Expect(k8sClient.Get(ctx, key, fetched)).To(Succeed())
		fetched.Status.Operation = nomadv1alpha1.SnapshotOperationJob
		fetched.Status.Phase = nomadv1alpha1.SnapshotPhaseRunning
		Expect(k8sClient.Status().Update(ctx, fetched)).To(Succeed())

		Expect(k8sClient.Get(ctx, key, fetched)).To(Succeed())
		fetched.Spec.Schedule = &nomadv1alpha1.SnapshotSchedule{Interval: "1h", Retain: 24}
		err := k8sClient.Update(ctx, fetched)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("mode switch"))

		// Completion unblocks the switch.
		Expect(k8sClient.Get(ctx, key, fetched)).To(Succeed())
		fetched.Status.Phase = nomadv1alpha1.SnapshotPhaseSucceeded
		Expect(k8sClient.Status().Update(ctx, fetched)).To(Succeed())

		Expect(k8sClient.Get(ctx, key, fetched)).To(Succeed())
		fetched.Spec.Schedule = &nomadv1alpha1.SnapshotSchedule{Interval: "1h", Retain: 24}
		Expect(k8sClient.Update(ctx, fetched)).To(Succeed())
	})
})

// Token mint via the injected factory: policy upsert + token create,
// both management-token-authenticated, accessor persisted to status.
func TestEnsureSnapshotTokenWithMock(t *testing.T) {
	snap := newOneShotSnapshot("tok")
	cluster := newTestCluster("snap-ns", "test-cluster")
	tlsSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-tls", Namespace: "snap-ns"},
		Data:       map[string][]byte{"ca.crt": []byte("dummy-ca")},
	}
	r, _ := newSnapshotReconciler(snap, cluster, tlsSecret)

	mockNomad := mocks.NewMockNomadAPI(t)
	r.NomadClientFactory = func(_ nomad.ClientConfig) (nomad.NomadAPI, error) {
		return mockNomad, nil
	}

	policyName := "snapshot-agent-snap-ns-tok"
	mockNomad.EXPECT().
		CreateACLPolicy("mgmt-token", policyName, "Snapshot agent policy for tok", snapshotAgentPolicyRules).
		Return(nil).Once()
	mockNomad.EXPECT().
		CreateACLTokenWithPolicies("mgmt-token", policyName, []string{policyName}).
		Return(&nomad.ACLTokenResult{AccessorID: "snap-acc", SecretID: "snap-secret"}, nil).Once()

	token, err := r.ensureSnapshotToken(context.Background(), snap, cluster, "mgmt-token")
	if err != nil {
		t.Fatalf("ensureSnapshotToken() error = %v", err)
	}
	if token != "snap-secret" {
		t.Errorf("token = %q, want snap-secret", token)
	}
	if snap.Status.TokenAccessorID != "snap-acc" || snap.Status.PolicyName != policyName {
		t.Errorf("status not persisted: %+v", snap.Status)
	}
}

// TestManagedByLabelConsistency pins neo-e3y: the operator stamps ONE
// managed-by identity across both controllers' resources. No migration
// path for the old value — this is a pre-release operator with no users
// (see bd memory no-migration-code-brand-new-operator).
func TestManagedByLabelConsistency(t *testing.T) {
	snap := newOneShotSnapshot("labels")
	cluster := newTestCluster("snap-ns", "test-cluster")

	clusterVal := phases.GetLabels(cluster)["app.kubernetes.io/managed-by"]
	agentVal := snapshotAgentLabels(snap)["app.kubernetes.io/managed-by"]
	if clusterVal != agentVal {
		t.Fatalf("managed-by mismatch: cluster resources %q vs snapshot agent %q", clusterVal, agentVal)
	}

}

// TestSnapshotTargetPodWiring covers neo-tih: each storage backend's
// pod-spec requirements — credentials env vars / volume mounts and the
// local PVC mount — asserted per target, including the no-credentials
// (IAM/workload-identity) variants which must leave the pod untouched.
func TestSnapshotTargetPodWiring(t *testing.T) {
	credRef := &corev1.LocalObjectReference{Name: "backend-creds"}

	envNames := func(spec corev1.PodSpec) map[string]bool {
		out := map[string]bool{}
		for _, e := range spec.Containers[0].Env {
			out[e.Name] = true
		}
		return out
	}
	mountPaths := func(spec corev1.PodSpec) map[string]bool {
		out := map[string]bool{}
		for _, m := range spec.Containers[0].VolumeMounts {
			out[m.MountPath] = true
		}
		return out
	}

	cases := []struct {
		name       string
		target     nomadv1alpha1.SnapshotTarget
		wantEnv    []string
		wantNoEnv  []string
		wantMounts []string
	}{
		{
			name: "S3 with credentials gets AWS env pair",
			target: nomadv1alpha1.SnapshotTarget{S3: &nomadv1alpha1.SnapshotS3Config{
				Bucket: "b", Region: "eu-west-1", CredentialsSecretRef: credRef,
			}},
			wantEnv: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"},
		},
		{
			name: "S3 without credentials (IRSA) adds no AWS env",
			target: nomadv1alpha1.SnapshotTarget{S3: &nomadv1alpha1.SnapshotS3Config{
				Bucket: "b", Region: "eu-west-1",
			}},
			wantNoEnv: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"},
		},
		{
			name: "GCS with credentials mounts key file and sets GOOGLE_APPLICATION_CREDENTIALS",
			target: nomadv1alpha1.SnapshotTarget{GCS: &nomadv1alpha1.SnapshotGCSConfig{
				Bucket: "b", CredentialsSecretRef: credRef,
			}},
			wantEnv:    []string{"GOOGLE_APPLICATION_CREDENTIALS"},
			wantMounts: []string{"/gcp"},
		},
		{
			name: "GCS without credentials (workload identity) adds nothing",
			target: nomadv1alpha1.SnapshotTarget{GCS: &nomadv1alpha1.SnapshotGCSConfig{
				Bucket: "b",
			}},
			wantNoEnv: []string{"GOOGLE_APPLICATION_CREDENTIALS"},
		},
		{
			name: "Azure with credentials gets account key env",
			target: nomadv1alpha1.SnapshotTarget{Azure: &nomadv1alpha1.SnapshotAzureConfig{
				Container: "c", AccountName: "acct", CredentialsSecretRef: credRef,
			}},
			wantEnv: []string{"AZURE_BLOB_ACCOUNT_KEY"},
		},
		{
			name: "local target mounts the snapshot PVC at the configured path",
			target: nomadv1alpha1.SnapshotTarget{Local: &nomadv1alpha1.SnapshotLocalConfig{
				Path: "/backups", Size: "1Gi",
			}},
			wantMounts: []string{"/backups"},
		},
		{
			name: "local target defaults the mount path",
			target: nomadv1alpha1.SnapshotTarget{Local: &nomadv1alpha1.SnapshotLocalConfig{
				Size: "1Gi",
			}},
			wantMounts: []string{"/snapshots"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := newOneShotSnapshot("wiring")
			snap.Spec.Target = tc.target
			cluster := newTestCluster("snap-ns", "test-cluster")
			r, _ := newSnapshotReconciler(snap, cluster)

			template := r.buildAgentPodTemplate(snap, cluster, "https://addr:4646", "c", "s")

			env := envNames(template.Spec)
			for _, want := range tc.wantEnv {
				if !env[want] {
					t.Errorf("env %s missing; have %v", want, env)
				}
			}
			for _, absent := range tc.wantNoEnv {
				if env[absent] {
					t.Errorf("env %s present but no credentials were configured", absent)
				}
			}
			mounts := mountPaths(template.Spec)
			for _, want := range tc.wantMounts {
				if !mounts[want] {
					t.Errorf("mount %s missing; have %v", want, mounts)
				}
			}
		})
	}
}

// TestSnapshotPVCReconcile covers neo-tih: local-target PVC sizing,
// storageClassName passthrough, and the immutability guard (spec is set
// only on create — a subsequent reconcile with a different size must
// not attempt to mutate the immutable PVC spec).
func TestSnapshotPVCReconcile(t *testing.T) {
	sc := "fast-ssd"
	snap := newOneShotSnapshot("pvc")
	snap.Spec.Target = nomadv1alpha1.SnapshotTarget{Local: &nomadv1alpha1.SnapshotLocalConfig{
		Size: "2Gi", StorageClassName: &sc,
	}}
	cluster := newTestCluster("snap-ns", "test-cluster")
	r, _ := newSnapshotReconciler(snap, cluster)

	if err := r.reconcilePVC(context.Background(), snap); err != nil {
		t.Fatalf("reconcilePVC() error = %v", err)
	}

	pvc := &corev1.PersistentVolumeClaim{}
	key := types.NamespacedName{Name: "pvc-snapshots", Namespace: "snap-ns"}
	if err := r.Get(context.Background(), key, pvc); err != nil {
		t.Fatalf("PVC not created: %v", err)
	}
	if got := pvc.Spec.Resources.Requests.Storage().String(); got != "2Gi" {
		t.Errorf("PVC size = %s, want 2Gi", got)
	}
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != "fast-ssd" {
		t.Errorf("storageClassName = %v, want fast-ssd", pvc.Spec.StorageClassName)
	}

	// Size change on the CR must not rewrite the immutable PVC spec.
	snap.Spec.Target.Local.Size = "10Gi"
	if err := r.reconcilePVC(context.Background(), snap); err != nil {
		t.Fatalf("reconcilePVC() second pass error = %v", err)
	}
	if err := r.Get(context.Background(), key, pvc); err != nil {
		t.Fatal(err)
	}
	if got := pvc.Spec.Resources.Requests.Storage().String(); got != "2Gi" {
		t.Errorf("PVC size mutated to %s — immutability guard broken", got)
	}

	// Invalid size surfaces as an error, not a panic.
	snap2 := newOneShotSnapshot("pvc-bad")
	snap2.Spec.Target = nomadv1alpha1.SnapshotTarget{Local: &nomadv1alpha1.SnapshotLocalConfig{Size: "not-a-size"}}
	if err := r.reconcilePVC(context.Background(), snap2); err == nil {
		t.Error("reconcilePVC() accepted an unparseable size")
	}
}

// neo-6rw: cross-namespace clusterRef is rejected at admission (the
// agent pod cannot mount the cluster's TLS Secret across namespaces),
// so the controller assumes same-namespace; the CEL rejection itself
// is covered in admission_invariants_test.go. The former neo-tih
// cross-namespace lookup spec was removed with the contract.

// neo-87a: a token re-mint rewrites the Secret in place, so only the
// pod-template secrets checksum carries the change into the recurring
// Deployment and rolls the agent onto the new token.
func TestSnapshotTokenRemintRollsDeployment(t *testing.T) {
	snap := newOneShotSnapshot("remint")
	snap.Spec.Schedule = &nomadv1alpha1.SnapshotSchedule{Interval: "1h", Retain: 24}
	snap.Finalizers = []string{snapshotFinalizer}
	cluster := newTestCluster("snap-ns", "test-cluster")
	cluster.Status.ACLBootstrapped = true
	tlsSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-tls", Namespace: "snap-ns"},
		Data:       map[string][]byte{"ca.crt": []byte("dummy-ca")},
	}
	mgmt := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-operator-management", Namespace: "snap-ns"},
		Data:       map[string][]byte{"secret-id": []byte("mgmt-token")},
	}
	r, _ := newSnapshotReconciler(snap, cluster, tlsSecret, mgmt)

	mockNomad := mocks.NewMockNomadAPI(t)
	r.NomadClientFactory = func(_ nomad.ClientConfig) (nomad.NomadAPI, error) {
		return mockNomad, nil
	}
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "remint", Namespace: "snap-ns"}}
	policyName := "snapshot-agent-snap-ns-remint"

	mockNomad.EXPECT().
		CreateACLPolicy("mgmt-token", policyName, "Snapshot agent policy for remint", snapshotAgentPolicyRules).
		Return(nil).Twice() // initial mint + re-mint below
	mockNomad.EXPECT().
		CreateACLTokenWithPolicies("mgmt-token", policyName, []string{policyName}).
		Return(&nomad.ACLTokenResult{AccessorID: "acc-1", SecretID: "secret-1"}, nil).Once()

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	deploy := &appsv1.Deployment{}
	deployKey := types.NamespacedName{Name: "remint-snapshot-agent", Namespace: "snap-ns"}
	if err := r.Get(context.Background(), deployKey, deploy); err != nil {
		t.Fatal(err)
	}
	first := deploy.Spec.Template.Annotations["checksum/secrets"]
	if first == "" {
		t.Fatal("pod template missing checksum/secrets annotation")
	}

	// Steady pass: recorded token still resolves — no roll.
	mockNomad.EXPECT().
		GetACLToken("mgmt-token", "acc-1").
		Return(&nomad.ACLTokenResult{AccessorID: "acc-1", SecretID: "secret-1"}, nil).Once()
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile() steady pass error = %v", err)
	}
	if err := r.Get(context.Background(), deployKey, deploy); err != nil {
		t.Fatal(err)
	}
	if got := deploy.Spec.Template.Annotations["checksum/secrets"]; got != first {
		t.Errorf("secrets checksum moved without a token change: %q -> %q", first, got)
	}

	// Re-mint: recorded token gone from Nomad — the template must move.
	mockNomad.EXPECT().GetACLToken("mgmt-token", "acc-1").Return(nil, nil).Once()
	mockNomad.EXPECT().
		CreateACLTokenWithPolicies("mgmt-token", policyName, []string{policyName}).
		Return(&nomad.ACLTokenResult{AccessorID: "acc-2", SecretID: "secret-2"}, nil).Once()
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile() re-mint pass error = %v", err)
	}
	if err := r.Get(context.Background(), deployKey, deploy); err != nil {
		t.Fatal(err)
	}
	if got := deploy.Spec.Template.Annotations["checksum/secrets"]; got == first {
		t.Error("token re-mint did not perturb the pod template — running agents keep the revoked token")
	}
	tokenSecret := &corev1.Secret{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "remint-snapshot-token", Namespace: "snap-ns"}, tokenSecret); err != nil {
		t.Fatal(err)
	}
	if got := string(tokenSecret.Data["secret-id"]); got != "secret-2" {
		t.Errorf("token secret = %q, want rotated secret-2", got)
	}
}

// neo-87a: the mint is not idempotent — a network error after a
// possibly-committed create must NOT reach the in-helper LB retry and
// mint a second, orphaned token. Mockery's .Once() fails the test on
// any second mint attempt.
func TestSnapshotMintSingleAttemptOnNetworkError(t *testing.T) {
	snap := newOneShotSnapshot("mintonce")
	cluster := newTestCluster("snap-ns", "test-cluster")
	// An LB address makes the old retry leg reachable: this proves the
	// mint no longer takes it.
	cluster.Status.AdvertiseAddress = "10.0.0.100"
	tlsSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-tls", Namespace: "snap-ns"},
		Data:       map[string][]byte{"ca.crt": []byte("dummy-ca")},
	}
	r, _ := newSnapshotReconciler(snap, cluster, tlsSecret)

	mockNomad := mocks.NewMockNomadAPI(t)
	r.NomadClientFactory = func(_ nomad.ClientConfig) (nomad.NomadAPI, error) {
		return mockNomad, nil
	}
	policyName := "snapshot-agent-snap-ns-mintonce"
	mockNomad.EXPECT().
		CreateACLPolicy("mgmt-token", policyName, "Snapshot agent policy for mintonce", snapshotAgentPolicyRules).
		Return(nil).Once()
	mockNomad.EXPECT().
		CreateACLTokenWithPolicies("mgmt-token", policyName, []string{policyName}).
		Return(nil, &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("connection refused")}).Once()

	if _, err := r.ensureSnapshotToken(context.Background(), snap, cluster, "mgmt-token"); err == nil {
		t.Fatal("ensureSnapshotToken() must surface the mint network error")
	}
}

// neo-87a: the status patch is the only durable record of a minted
// accessor — on patch failure the mint must be unwound or every retry
// leaks a fresh orphan.
func TestSnapshotMintUnwoundOnStatusPatchFailure(t *testing.T) {
	snap := newOneShotSnapshot("unwind")
	cluster := newTestCluster("snap-ns", "test-cluster")
	tlsSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-tls", Namespace: "snap-ns"},
		Data:       map[string][]byte{"ca.crt": []byte("dummy-ca")},
	}
	_ = nomadv1alpha1.AddToScheme(scheme.Scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme.Scheme).
		WithObjects(snap, cluster, tlsSecret).
		WithStatusSubresource(snap).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
				return fmt.Errorf("simulated status patch failure")
			},
		}).Build()
	r := &NomadSnapshotReconciler{Client: fakeClient, Scheme: scheme.Scheme}

	mockNomad := mocks.NewMockNomadAPI(t)
	r.NomadClientFactory = func(_ nomad.ClientConfig) (nomad.NomadAPI, error) {
		return mockNomad, nil
	}
	policyName := "snapshot-agent-snap-ns-unwind"
	mockNomad.EXPECT().
		CreateACLPolicy("mgmt-token", policyName, "Snapshot agent policy for unwind", snapshotAgentPolicyRules).
		Return(nil).Once()
	mockNomad.EXPECT().
		CreateACLTokenWithPolicies("mgmt-token", policyName, []string{policyName}).
		Return(&nomad.ACLTokenResult{AccessorID: "acc-1", SecretID: "secret-1"}, nil).Once()
	mockNomad.EXPECT().DeleteACLToken("mgmt-token", "acc-1").Return(nil).Once()

	_, err := r.ensureSnapshotToken(context.Background(), snap, cluster, "mgmt-token")
	if err == nil || !strings.Contains(err.Error(), "failed to patch status") {
		t.Fatalf("ensureSnapshotToken() error = %v, want status patch failure", err)
	}
}

// neo-87a: a cluster with ACLs disabled is a terminal misconfiguration
// — distinct Ready reason plus one Warning, not an infinite
// WaitingForACLBootstrap.
func TestSnapshotACLsDisabledTerminal(t *testing.T) {
	snap := newOneShotSnapshot("acloff")
	snap.Finalizers = []string{snapshotFinalizer}
	cluster := newTestCluster("snap-ns", "test-cluster")
	cluster.Spec.Server.ACL.Enabled = ptr.To(false)
	r, recorder := newSnapshotReconciler(snap, cluster)
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "acloff", Namespace: "snap-ns"}}

	// Two passes: the Warning must not repeat per retry.
	for i := 0; i < 2; i++ {
		if _, err := r.Reconcile(context.Background(), req); err != nil {
			t.Fatalf("Reconcile() pass %d error = %v", i, err)
		}
	}

	got := &nomadv1alpha1.NomadSnapshot{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "acloff", Namespace: "snap-ns"}, got); err != nil {
		t.Fatal(err)
	}
	var ready *metav1.Condition
	for i := range got.Status.Conditions {
		if got.Status.Conditions[i].Type == "Ready" {
			ready = &got.Status.Conditions[i]
		}
	}
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != "ACLsDisabled" {
		t.Fatalf("Ready condition = %+v, want False/ACLsDisabled", ready)
	}
	events := drainEvents(recorder)
	if len(events) != 1 || !strings.Contains(events[0], "ACLsDisabled") {
		t.Errorf("events = %v, want exactly one ACLsDisabled Warning", events)
	}
}

// neo-87a parity with neo-2um.18: an empty management secret-id is the
// only wait branch that previously patched no condition.
func TestSnapshotEmptyManagementSecretID(t *testing.T) {
	snap := newOneShotSnapshot("emptymgmt")
	snap.Finalizers = []string{snapshotFinalizer}
	cluster := newTestCluster("snap-ns", "test-cluster")
	cluster.Status.ACLBootstrapped = true
	mgmt := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster-operator-management", Namespace: "snap-ns"},
		Data:       map[string][]byte{"secret-id": nil},
	}
	r, _ := newSnapshotReconciler(snap, cluster, mgmt)
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "emptymgmt", Namespace: "snap-ns"}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	got := &nomadv1alpha1.NomadSnapshot{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "emptymgmt", Namespace: "snap-ns"}, got); err != nil {
		t.Fatal(err)
	}
	for _, c := range got.Status.Conditions {
		if c.Type == "Ready" {
			if c.Status != metav1.ConditionFalse || c.Reason != "WaitingForManagementToken" || !strings.Contains(c.Message, "empty secret-id") {
				t.Fatalf("Ready condition = %+v, want False/WaitingForManagementToken (empty secret-id)", c)
			}
			return
		}
	}
	t.Fatal("Ready condition not set on the empty secret-id branch")
}

// TestNextScheduledProjection covers neo-c2f / AC-2.7.9: recurring mode
// projects status.nextScheduled forward one interval when unset or
// lapsed, does NOT advance it while still in the future (the
// once-per-interval churn bound), leaves it unset on an unparseable
// interval, and one-shot mode clears it.
// TestRecurringVersionMirror: the recurring path mirrors the cluster's
// Nomad version into status — the same-version restore check for
// agent-taken snapshots the operator cannot individually observe.
func TestRecurringVersionMirror(t *testing.T) {
	snap := newOneShotSnapshot("vmirror")
	snap.Spec.Schedule = &nomadv1alpha1.SnapshotSchedule{Interval: "1h", Retain: 24}
	cluster := newTestCluster("snap-ns", "test-cluster")
	cluster.Status.NomadVersion = "2.0.4-ent"
	r, _ := newSnapshotReconciler(snap, cluster)

	if _, err := r.reconcileRecurring(context.Background(), snap, cluster, "https://addr:4646", "c", "s"); err != nil {
		t.Fatalf("reconcileRecurring() error = %v", err)
	}
	if snap.Status.NomadVersion != "2.0.4-ent" {
		t.Errorf("status.nomadVersion = %q, want mirror of cluster", snap.Status.NomadVersion)
	}

	// Upgrade: the mirror follows the cluster.
	cluster.Status.NomadVersion = "2.1.0-ent"
	if _, err := r.reconcileRecurring(context.Background(), snap, cluster, "https://addr:4646", "c", "s"); err != nil {
		t.Fatalf("reconcileRecurring() second pass error = %v", err)
	}
	if snap.Status.NomadVersion != "2.1.0-ent" {
		t.Errorf("status.nomadVersion = %q, want upgraded mirror", snap.Status.NomadVersion)
	}
}

func TestNextScheduledProjection(t *testing.T) {
	newRecurring := func(name, interval string) (*NomadSnapshotReconciler, *nomadv1alpha1.NomadSnapshot, *nomadv1alpha1.NomadCluster) {
		snap := newOneShotSnapshot(name)
		snap.Spec.Schedule = &nomadv1alpha1.SnapshotSchedule{Interval: interval, Retain: 24}
		cluster := newTestCluster("snap-ns", "test-cluster")
		// A ready Deployment so the projection branch (agent Ready) runs.
		deploy := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: name + "-snapshot-agent", Namespace: "snap-ns"},
			Status:     appsv1.DeploymentStatus{ReadyReplicas: 1},
		}
		r, _ := newSnapshotReconciler(snap, cluster, deploy)
		return r, snap, cluster
	}

	t.Run("set on first ready reconcile, not advanced while in the future", func(t *testing.T) {
		r, snap, cluster := newRecurring("proj", "1h")
		if _, err := r.reconcileRecurring(context.Background(), snap, cluster, "https://addr:4646", "c", "s"); err != nil {
			t.Fatalf("reconcileRecurring() error = %v", err)
		}
		if snap.Status.NextScheduled == nil {
			t.Fatal("nextScheduled not set on first ready reconcile")
		}
		first := snap.Status.NextScheduled.Time
		if until := time.Until(first); until < 55*time.Minute || until > 65*time.Minute {
			t.Errorf("nextScheduled projected %v out, want ~1h", until)
		}

		// Second reconcile within the interval: unchanged (churn bound).
		if _, err := r.reconcileRecurring(context.Background(), snap, cluster, "https://addr:4646", "c", "s"); err != nil {
			t.Fatalf("second reconcileRecurring() error = %v", err)
		}
		if !snap.Status.NextScheduled.Time.Equal(first) {
			t.Errorf("nextScheduled advanced within the interval: %v -> %v", first, snap.Status.NextScheduled.Time)
		}
	})

	t.Run("re-projected after the deadline lapses", func(t *testing.T) {
		r, snap, cluster := newRecurring("lapsed", "1h")
		past := metav1.NewTime(time.Now().Add(-time.Minute))
		snap.Status.NextScheduled = &past
		if _, err := r.reconcileRecurring(context.Background(), snap, cluster, "https://addr:4646", "c", "s"); err != nil {
			t.Fatalf("reconcileRecurring() error = %v", err)
		}
		if !snap.Status.NextScheduled.After(time.Now()) {
			t.Errorf("lapsed nextScheduled not re-projected: %v", snap.Status.NextScheduled.Time)
		}
	})

	t.Run("unparseable interval leaves it unset without error", func(t *testing.T) {
		// Admission now rejects bad intervals (neo-f7j), but the
		// controller must stay robust to pre-validation objects.
		r, snap, cluster := newRecurring("badint", "not-a-duration")
		if _, err := r.reconcileRecurring(context.Background(), snap, cluster, "https://addr:4646", "c", "s"); err != nil {
			t.Fatalf("reconcileRecurring() error = %v", err)
		}
		if snap.Status.NextScheduled != nil {
			t.Errorf("nextScheduled set despite unparseable interval: %v", snap.Status.NextScheduled)
		}
	})

	t.Run("switching to one-shot clears it", func(t *testing.T) {
		snap := newOneShotSnapshot("clear") // no schedule = one-shot
		future := metav1.NewTime(time.Now().Add(time.Hour))
		snap.Status.NextScheduled = &future
		cluster := newTestCluster("snap-ns", "test-cluster")
		r, _ := newSnapshotReconciler(snap, cluster)
		if _, err := r.reconcileOneShot(context.Background(), snap, cluster, "https://addr:4646", "c", "s"); err != nil {
			t.Fatalf("reconcileOneShot() error = %v", err)
		}
		if snap.Status.NextScheduled != nil {
			t.Errorf("nextScheduled not cleared on mode switch: %v", snap.Status.NextScheduled)
		}
	})
}

// TestSnapshotAgentSecurityContext covers neo-8xu for the snapshot
// agent: the same PSS-restricted profile as the server pods, with the
// /tmp staging mount required by the read-only root filesystem.
func TestSnapshotAgentSecurityContext(t *testing.T) {
	snap := newOneShotSnapshot("sec")
	cluster := newTestCluster("snap-ns", "test-cluster")
	r, _ := newSnapshotReconciler(snap, cluster)

	template := r.buildAgentPodTemplate(snap, cluster, "https://addr:4646", "c", "s")

	sc := template.Spec.SecurityContext
	if sc == nil || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot ||
		sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("agent pod security context not PSS-restricted: %+v", sc)
	}
	c := template.Spec.Containers[0].SecurityContext
	if c == nil || c.AllowPrivilegeEscalation == nil || *c.AllowPrivilegeEscalation ||
		c.ReadOnlyRootFilesystem == nil || !*c.ReadOnlyRootFilesystem ||
		c.Capabilities == nil || len(c.Capabilities.Drop) != 1 || c.Capabilities.Drop[0] != "ALL" {
		t.Fatalf("agent container security context not PSS-restricted: %+v", c)
	}
	var tmpMounted bool
	for _, m := range template.Spec.Containers[0].VolumeMounts {
		if m.MountPath == "/tmp" {
			tmpMounted = true
		}
	}
	if !tmpMounted {
		t.Error("agent read-only root requires the /tmp staging mount")
	}
}
