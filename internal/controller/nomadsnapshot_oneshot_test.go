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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/internal/controller/phases"
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

	if _, err := r.reconcileOneShot(context.Background(), snap, cluster, "https://addr:4646", "cafe1234"); err != nil {
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
		job := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: "done-snapshot", Namespace: "snap-ns"},
			Status:     batchv1.JobStatus{Succeeded: 1, CompletionTime: &now},
		}
		r, recorder := newSnapshotReconciler(snap, cluster, job)

		if _, err := r.reconcileOneShot(context.Background(), snap, cluster, "https://addr:4646", "c"); err != nil {
			t.Fatalf("reconcileOneShot() error = %v", err)
		}
		if snap.Status.Phase != nomadv1alpha1.SnapshotPhaseSucceeded {
			t.Errorf("phase = %q, want Succeeded", snap.Status.Phase)
		}
		if snap.Status.LastSnapshot == nil || snap.Status.LastSnapshot.Status != "Success" {
			t.Errorf("lastSnapshot = %+v, want Success", snap.Status.LastSnapshot)
		}
		if len(recorder.Events) != 0 {
			t.Error("unexpected event on success")
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
			if _, err := r.reconcileOneShot(context.Background(), snap, cluster, "https://addr:4646", "c"); err != nil {
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

		if _, err := r.reconcileOneShot(context.Background(), snap, cluster, "https://addr:4646", "c"); err != nil {
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

		if _, err := r.reconcileRecurring(context.Background(), snap, cluster, "https://addr:4646", "c"); err != nil {
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
