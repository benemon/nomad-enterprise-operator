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

package hcl

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
)

func TestGenerator_Generate_BasicConfiguration(t *testing.T) {
	cluster := &nomadv1alpha1.NomadCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "nomad",
		},
		Spec: nomadv1alpha1.NomadClusterSpec{
			Replicas: 3,
			Topology: nomadv1alpha1.TopologySpec{
				Region:     "us-west-1",
				Datacenter: "dc1",
			},
		},
	}

	gen := NewGenerator(cluster, "10.0.0.100", "test-gossip-key")
	hcl, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify basic configuration
	assertions := []struct {
		name     string
		contains string
	}{
		{"region", `region     = "us-west-1"`},
		{"datacenter", `datacenter = "dc1"`},
		{"advertise http", `http = "10.0.0.100:4646"`},
		{"advertise rpc", `rpc  = "10.0.0.100:4647"`},
		{"bootstrap_expect", "bootstrap_expect = 3"},
		{"gossip key", `encrypt = "test-gossip-key"`},
		{"server join 0", "test-cluster-0.test-cluster-headless.nomad.svc.cluster.local"},
		{"server join 1", "test-cluster-1.test-cluster-headless.nomad.svc.cluster.local"},
		{"server join 2", "test-cluster-2.test-cluster-headless.nomad.svc.cluster.local"},
		{"telemetry", "prometheus_metrics         = true"},
	}

	for _, a := range assertions {
		if !strings.Contains(hcl, a.contains) {
			t.Errorf("Generate() missing %s: expected to contain %q", a.name, a.contains)
		}
	}

	// Verify optional blocks are NOT present
	optionalBlocks := []string{"acl {", "tls {", "audit {", "snapshot_agent {"}
	for _, block := range optionalBlocks {
		if strings.Contains(hcl, block) {
			t.Errorf("Generate() should not contain %q when not enabled", block)
		}
	}
}

func TestGenerator_Generate_DefaultValues(t *testing.T) {
	// Test that defaults are applied when values are not set
	cluster := &nomadv1alpha1.NomadCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-ns",
		},
		Spec: nomadv1alpha1.NomadClusterSpec{
			// Leave most fields empty to test defaults
		},
	}

	gen := NewGenerator(cluster, "192.168.1.1", "key")
	hcl, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify defaults
	assertions := []struct {
		name     string
		contains string
	}{
		{"default region", `region     = "global"`},
		{"default datacenter from namespace", `datacenter = "test-ns"`},
		{"default replicas", "bootstrap_expect = 3"},
		{"default autopilot last_contact", `last_contact_threshold    = "200ms"`},
		{"default autopilot max_trailing", "max_trailing_logs         = 250"},
		{"default autopilot stabilization", `server_stabilization_time = "10s"`},
	}

	for _, a := range assertions {
		if !strings.Contains(hcl, a.contains) {
			t.Errorf("Generate() missing default %s: expected to contain %q", a.name, a.contains)
		}
	}
}

func TestGenerator_Generate_ACLEnabled(t *testing.T) {
	cluster := &nomadv1alpha1.NomadCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "nomad",
		},
		Spec: nomadv1alpha1.NomadClusterSpec{
			Replicas: 3,
			Server: nomadv1alpha1.ServerSpec{
				ACL: nomadv1alpha1.ACLSpec{
					Enabled: true,
				},
			},
		},
	}

	gen := NewGenerator(cluster, "10.0.0.100", "key")
	hcl, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify ACL block is present
	if !strings.Contains(hcl, "# ACL configuration") {
		t.Error("Generate() should contain ACL configuration comment")
	}
	if !strings.Contains(hcl, "acl {") {
		t.Error("Generate() should contain acl block")
	}
	if !strings.Contains(hcl, "enabled = true") {
		t.Error("Generate() should contain enabled = true in acl block")
	}
}

func TestGenerator_Generate_TLSEnabled(t *testing.T) {
	cluster := &nomadv1alpha1.NomadCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "nomad",
		},
		Spec: nomadv1alpha1.NomadClusterSpec{
			Replicas: 3,
			Server: nomadv1alpha1.ServerSpec{
				TLS: nomadv1alpha1.TLSSpec{
					Enabled: true,
				},
			},
		},
	}

	gen := NewGenerator(cluster, "10.0.0.100", "key")
	hcl, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify TLS block is present
	assertions := []struct {
		name     string
		contains string
	}{
		{"TLS comment", "# TLS configuration"},
		{"TLS block", "tls {"},
		{"http enabled", "http = true"},
		{"rpc enabled", "rpc  = true"},
		{"ca_file", `ca_file   = "/nomad/tls/ca.crt"`},
		{"cert_file", `cert_file = "/nomad/tls/server.crt"`},
		{"key_file", `key_file  = "/nomad/tls/server.key"`},
		{"verify_server_hostname", "verify_server_hostname = true"},
		{"verify_https_client", "verify_https_client    = true"},
	}

	for _, a := range assertions {
		if !strings.Contains(hcl, a.contains) {
			t.Errorf("Generate() missing TLS %s: expected to contain %q", a.name, a.contains)
		}
	}
}

func TestGenerator_Generate_AuditEnabled(t *testing.T) {
	cluster := &nomadv1alpha1.NomadCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "nomad",
		},
		Spec: nomadv1alpha1.NomadClusterSpec{
			Replicas: 3,
			Server: nomadv1alpha1.ServerSpec{
				Audit: nomadv1alpha1.AuditSpec{
					Enabled:        true,
					Format:         "json",
					RotateDuration: "12h",
					RotateMaxFiles: 10,
				},
			},
		},
	}

	gen := NewGenerator(cluster, "10.0.0.100", "key")
	hcl, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify audit block is present
	assertions := []struct {
		name     string
		contains string
	}{
		{"audit comment", "# Audit logging configuration"},
		{"audit block", "audit {"},
		{"enabled", "enabled = true"},
		{"sink block", `sink "file" {`},
		{"format", `format             = "json"`},
		{"path", `path               = "/nomad/audit/audit.log"`},
		{"rotate_duration", `rotate_duration    = "12h"`},
		{"rotate_max_files", "rotate_max_files   = 10"},
	}

	for _, a := range assertions {
		if !strings.Contains(hcl, a.contains) {
			t.Errorf("Generate() missing audit %s: expected to contain %q", a.name, a.contains)
		}
	}
}

func TestGenerator_Generate_AuditDefaults(t *testing.T) {
	cluster := &nomadv1alpha1.NomadCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "nomad",
		},
		Spec: nomadv1alpha1.NomadClusterSpec{
			Replicas: 3,
			Server: nomadv1alpha1.ServerSpec{
				Audit: nomadv1alpha1.AuditSpec{
					Enabled: true,
					// Leave format, rotation empty to test defaults
				},
			},
		},
	}

	gen := NewGenerator(cluster, "10.0.0.100", "key")
	hcl, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify default audit values
	assertions := []struct {
		name     string
		contains string
	}{
		{"default format", `format             = "json"`},
		{"default rotate_duration", `rotate_duration    = "24h"`},
		{"default rotate_max_files", "rotate_max_files   = 15"},
	}

	for _, a := range assertions {
		if !strings.Contains(hcl, a.contains) {
			t.Errorf("Generate() missing default audit %s: expected to contain %q", a.name, a.contains)
		}
	}
}

func TestGenerator_Generate_SnapshotEnabled(t *testing.T) {
	cluster := &nomadv1alpha1.NomadCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "nomad",
		},
		Spec: nomadv1alpha1.NomadClusterSpec{
			Replicas: 3,
			Server: nomadv1alpha1.ServerSpec{
				Snapshot: nomadv1alpha1.SnapshotSpec{
					Enabled:  true,
					Interval: "30m",
					Retain:   48,
					S3: nomadv1alpha1.S3Spec{
						Endpoint:       "https://minio.example.com",
						Bucket:         "nomad-snapshots",
						Region:         "us-east-1",
						ForcePathStyle: true,
					},
				},
			},
		},
	}

	gen := NewGenerator(cluster, "10.0.0.100", "key")
	hcl, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify snapshot block is present
	assertions := []struct {
		name     string
		contains string
	}{
		{"snapshot comment", "# Snapshot agent configuration"},
		{"snapshot_agent block", "snapshot_agent {"},
		{"snapshot block", "snapshot {"},
		{"interval", `interval         = "30m"`},
		{"retain", "retain           = 48"},
		{"aws_s3 block", "aws_s3 {"},
		{"endpoint", `endpoint                       = "https://minio.example.com"`},
		{"bucket", `bucket                         = "nomad-snapshots"`},
		{"region", `region                         = "us-east-1"`},
		{"force_path_style", "s3_force_path_style            = true"},
	}

	for _, a := range assertions {
		if !strings.Contains(hcl, a.contains) {
			t.Errorf("Generate() missing snapshot %s: expected to contain %q", a.name, a.contains)
		}
	}
}

func TestGenerator_Generate_SnapshotDefaults(t *testing.T) {
	cluster := &nomadv1alpha1.NomadCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "nomad",
		},
		Spec: nomadv1alpha1.NomadClusterSpec{
			Replicas: 3,
			Server: nomadv1alpha1.ServerSpec{
				Snapshot: nomadv1alpha1.SnapshotSpec{
					Enabled: true,
					// Leave interval, retain, region empty to test defaults
					S3: nomadv1alpha1.S3Spec{
						Endpoint: "https://s3.amazonaws.com",
						Bucket:   "my-bucket",
					},
				},
			},
		},
	}

	gen := NewGenerator(cluster, "10.0.0.100", "key")
	hcl, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify default snapshot values
	assertions := []struct {
		name     string
		contains string
	}{
		{"default interval", `interval         = "1h"`},
		{"default retain", "retain           = 24"},
		{"default region", `region                         = "us-east-1"`},
	}

	for _, a := range assertions {
		if !strings.Contains(hcl, a.contains) {
			t.Errorf("Generate() missing default snapshot %s: expected to contain %q", a.name, a.contains)
		}
	}
}

func TestGenerator_Generate_AllFeaturesEnabled(t *testing.T) {
	cluster := &nomadv1alpha1.NomadCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "full-cluster",
			Namespace: "production",
		},
		Spec: nomadv1alpha1.NomadClusterSpec{
			Replicas: 5,
			Topology: nomadv1alpha1.TopologySpec{
				Region:     "eu-west-1",
				Datacenter: "prod-dc",
			},
			Server: nomadv1alpha1.ServerSpec{
				ACL: nomadv1alpha1.ACLSpec{
					Enabled: true,
				},
				TLS: nomadv1alpha1.TLSSpec{
					Enabled: true,
				},
				Audit: nomadv1alpha1.AuditSpec{
					Enabled: true,
				},
				Snapshot: nomadv1alpha1.SnapshotSpec{
					Enabled: true,
					S3: nomadv1alpha1.S3Spec{
						Endpoint: "https://s3.eu-west-1.amazonaws.com",
						Bucket:   "prod-snapshots",
					},
				},
				Autopilot: nomadv1alpha1.AutopilotSpec{
					CleanupDeadServers:      true,
					LastContactThreshold:    "500ms",
					MaxTrailingLogs:         500,
					ServerStabilizationTime: "30s",
				},
			},
		},
	}

	gen := NewGenerator(cluster, "lb.example.com", "production-gossip-key")
	hcl, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify all blocks are present
	requiredBlocks := []string{
		"acl {",
		"tls {",
		"audit {",
		"snapshot_agent {",
		"autopilot {",
	}

	for _, block := range requiredBlocks {
		if !strings.Contains(hcl, block) {
			t.Errorf("Generate() should contain %q when all features enabled", block)
		}
	}

	// Verify 5 server join entries
	for i := 0; i < 5; i++ {
		expected := "full-cluster-" + string(rune('0'+i)) + ".full-cluster-headless.production.svc.cluster.local"
		if !strings.Contains(hcl, expected) {
			t.Errorf("Generate() should contain server join entry %q", expected)
		}
	}

	// Verify custom autopilot settings
	if !strings.Contains(hcl, `last_contact_threshold    = "500ms"`) {
		t.Error("Generate() should contain custom last_contact_threshold")
	}
	if !strings.Contains(hcl, "max_trailing_logs         = 500") {
		t.Error("Generate() should contain custom max_trailing_logs")
	}
}

func TestGenerator_Generate_SingleReplica(t *testing.T) {
	cluster := &nomadv1alpha1.NomadCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dev-cluster",
			Namespace: "dev",
		},
		Spec: nomadv1alpha1.NomadClusterSpec{
			Replicas: 1,
		},
	}

	gen := NewGenerator(cluster, "10.0.0.1", "key")
	hcl, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Verify single replica configuration
	if !strings.Contains(hcl, "bootstrap_expect = 1") {
		t.Error("Generate() should have bootstrap_expect = 1")
	}

	// Should only have one server join entry
	if !strings.Contains(hcl, "dev-cluster-0.dev-cluster-headless.dev.svc.cluster.local") {
		t.Error("Generate() should contain server join entry for pod 0")
	}
	if strings.Contains(hcl, "dev-cluster-1.") {
		t.Error("Generate() should NOT contain server join entry for pod 1")
	}
}
