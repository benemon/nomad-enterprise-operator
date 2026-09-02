//go:build operandcontract

package controller

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Operand-contract gate (neo-ce6): every snapshot.hcl shape the
// operator can render must load in the pinned operand image's snapshot
// agent, proven by the startup banner naming the storage backend. The
// banner is the load marker: an unrecognized storage stanza either
// hard-fails the HCL parse or leaves the agent on its Local default,
// and both miss the expected banner. Requires docker and OPERAND_IMAGE;
// runs in the operand-contract CI job, not the unit lane.

func snapshotFixture(target nomadv1alpha1.SnapshotTarget, schedule *nomadv1alpha1.SnapshotSchedule) *nomadv1alpha1.NomadSnapshot {
	return &nomadv1alpha1.NomadSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: "contract", Namespace: "contract-ns"},
		Spec: nomadv1alpha1.NomadSnapshotSpec{
			Target:   target,
			Schedule: schedule,
		},
	}
}

// agentBanner starts the snapshot agent on the rendered config and
// returns its early output. The agent never exits on its own (it
// retries the license fetch), so it is force-removed after capture.
func agentBanner(t *testing.T, img, config string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "snapshot.hcl"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("operand-contract-%d", time.Now().UnixNano())
	defer exec.Command("docker", "rm", "-f", name).Run()
	if out, err := exec.Command("docker", "run", "-d", "--name", name,
		"-v", dir+":/cfg:ro", img, "operator", "snapshot", "agent", "/cfg/snapshot.hcl").CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		out, _ := exec.Command("docker", "logs", name).CombinedOutput()
		if strings.Contains(string(out), "Snapshot Storage:") ||
			strings.Contains(string(out), "Error") || time.Now().After(deadline) {
			return string(out)
		}
		time.Sleep(time.Second)
	}
}

func TestOperandContract_SnapshotHCL(t *testing.T) {
	img := os.Getenv("OPERAND_IMAGE")
	if img == "" {
		t.Fatal("OPERAND_IMAGE not set (e.g. hashicorp/nomad:2.0.5-ent)")
	}

	r := &NomadSnapshotReconciler{}
	schedule := &nomadv1alpha1.SnapshotSchedule{Interval: "1h", Retain: 12, Stale: true}
	credentials := map[string]string{
		"AWS_ACCESS_KEY_ID":      "stub-key",
		"AWS_SECRET_ACCESS_KEY":  "stub-secret",
		"AZURE_BLOB_ACCOUNT_KEY": "stub-account-key",
	}

	cases := []struct {
		name     string
		target   nomadv1alpha1.SnapshotTarget
		schedule *nomadv1alpha1.SnapshotSchedule
		marker   string
	}{
		{
			name: "s3-oneshot",
			target: nomadv1alpha1.SnapshotTarget{S3: &nomadv1alpha1.SnapshotS3Config{
				Bucket: "stub-bucket", Region: "eu-west-2",
			}},
			marker: "Snapshot Storage: Amazon S3",
		},
		{
			name: "s3-compatible-scheduled",
			target: nomadv1alpha1.SnapshotTarget{S3: &nomadv1alpha1.SnapshotS3Config{
				Bucket: "stub-bucket", Region: "eu-west-2",
				Endpoint: "https://minio.example:9000", ForcePathStyle: true,
			}},
			schedule: schedule,
			marker:   "Snapshot Storage: Amazon S3",
		},
		{
			name:   "gcs",
			target: nomadv1alpha1.SnapshotTarget{GCS: &nomadv1alpha1.SnapshotGCSConfig{Bucket: "stub-bucket"}},
			marker: "Snapshot Storage: Google Cloud Storage",
		},
		{
			name: "azure",
			target: nomadv1alpha1.SnapshotTarget{Azure: &nomadv1alpha1.SnapshotAzureConfig{
				Container: "stub-container", AccountName: "stubaccount",
			}},
			marker: "Snapshot Storage: Azure Blob Storage",
		},
		{
			name:   "local",
			target: nomadv1alpha1.SnapshotTarget{Local: &nomadv1alpha1.SnapshotLocalConfig{Path: "/snapshots"}},
			marker: "Snapshot Storage: Local",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := r.generateSnapshotConfig(snapshotFixture(tc.target, tc.schedule), credentials)
			out := agentBanner(t, img, config)
			if !strings.Contains(out, tc.marker) {
				t.Errorf("banner missing %q — the operand did not load the rendered backend:\n%s\n--- config:\n%s",
					tc.marker, out, config)
			}
		})
	}

	// Canary: a renamed storage stanza must not produce a cloud-backend
	// banner, proving the oracle still detects unrecognized blocks.
	t.Run("oracle-canary", func(t *testing.T) {
		config := r.generateSnapshotConfig(snapshotFixture(
			nomadv1alpha1.SnapshotTarget{S3: &nomadv1alpha1.SnapshotS3Config{Bucket: "b", Region: "r"}}, nil),
			credentials)
		config = strings.Replace(config, "aws_storage", "aws_s3", 1)
		out := agentBanner(t, img, config)
		if strings.Contains(out, "Snapshot Storage: Amazon S3") {
			t.Errorf("oracle loaded a config with an unknown storage stanza:\n%s", out)
		}
	})
}
