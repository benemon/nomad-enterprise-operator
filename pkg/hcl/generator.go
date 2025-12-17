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
	"bytes"
	"fmt"
	"text/template"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
)

// Generator creates Nomad HCL configuration
type Generator struct {
	cluster          *nomadv1alpha1.NomadCluster
	advertiseAddress string
	gossipKey        string
}

// NewGenerator creates a new HCL generator
func NewGenerator(cluster *nomadv1alpha1.NomadCluster, advertiseAddress, gossipKey string) *Generator {
	return &Generator{
		cluster:          cluster,
		advertiseAddress: advertiseAddress,
		gossipKey:        gossipKey,
	}
}

// Generate produces the server.hcl configuration
func (g *Generator) Generate() (string, error) {
	funcMap := template.FuncMap{
		"intRange": func(n int32) []int {
			result := make([]int, n)
			for i := range result {
				result[i] = i
			}
			return result
		},
	}

	tmpl, err := template.New("server.hcl").Funcs(funcMap).Parse(serverHCLTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse HCL template: %w", err)
	}

	data := g.buildTemplateData()

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute HCL template: %w", err)
	}

	return buf.String(), nil
}

type templateData struct {
	Region                 string
	Datacenter             string
	AdvertiseAddress       string
	Replicas               int32
	ClusterName            string
	Namespace              string
	HeadlessService        string
	GossipKey              string
	ACLEnabled             bool
	TLSEnabled             bool
	AuditEnabled           bool
	AuditDeliveryGuarantee string
	AuditFormat            string
	AuditRotateDur         string
	AuditRotateMax         int
	SnapshotEnabled        bool
	SnapshotInterval       string
	SnapshotRetain         int
	S3Endpoint             string
	S3Bucket               string
	S3Region               string
	S3ForcePathStyle       bool
	Autopilot              autopilotData
}

type autopilotData struct {
	CleanupDeadServers      bool
	LastContactThreshold    string
	MaxTrailingLogs         int
	ServerStabilizationTime string
}

func (g *Generator) buildTemplateData() templateData {
	cluster := g.cluster

	// Defaults
	region := cluster.Spec.Topology.Region
	if region == "" {
		region = "global"
	}

	datacenter := cluster.Spec.Topology.Datacenter
	if datacenter == "" {
		datacenter = cluster.Namespace
	}

	replicas := cluster.Spec.Replicas
	if replicas == 0 {
		replicas = 3
	}

	// Autopilot defaults
	lastContactThreshold := cluster.Spec.Server.Autopilot.LastContactThreshold
	if lastContactThreshold == "" {
		lastContactThreshold = "200ms"
	}

	maxTrailingLogs := cluster.Spec.Server.Autopilot.MaxTrailingLogs
	if maxTrailingLogs == 0 {
		maxTrailingLogs = 250
	}

	serverStabilizationTime := cluster.Spec.Server.Autopilot.ServerStabilizationTime
	if serverStabilizationTime == "" {
		serverStabilizationTime = "10s"
	}

	// Audit defaults
	auditDeliveryGuarantee := cluster.Spec.Server.Audit.DeliveryGuarantee
	if auditDeliveryGuarantee == "" {
		auditDeliveryGuarantee = "enforced"
	}

	auditFormat := cluster.Spec.Server.Audit.Format
	if auditFormat == "" {
		auditFormat = "json"
	}

	auditRotateDur := cluster.Spec.Server.Audit.RotateDuration
	if auditRotateDur == "" {
		auditRotateDur = "24h"
	}

	auditRotateMax := cluster.Spec.Server.Audit.RotateMaxFiles
	if auditRotateMax == 0 {
		auditRotateMax = 15
	}

	// Snapshot defaults
	snapshotInterval := cluster.Spec.Server.Snapshot.Interval
	if snapshotInterval == "" {
		snapshotInterval = "1h"
	}

	snapshotRetain := cluster.Spec.Server.Snapshot.Retain
	if snapshotRetain == 0 {
		snapshotRetain = 24
	}

	s3Region := cluster.Spec.Server.Snapshot.S3.Region
	if s3Region == "" {
		s3Region = "us-east-1"
	}

	return templateData{
		Region:                 region,
		Datacenter:             datacenter,
		AdvertiseAddress:       g.advertiseAddress,
		Replicas:               replicas,
		ClusterName:            cluster.Name,
		Namespace:              cluster.Namespace,
		HeadlessService:        cluster.Name + "-headless",
		GossipKey:              g.gossipKey,
		ACLEnabled:             cluster.Spec.Server.ACL.Enabled,
		TLSEnabled:             cluster.Spec.Server.TLS.Enabled,
		AuditEnabled:           cluster.Spec.Server.Audit.Enabled,
		AuditDeliveryGuarantee: auditDeliveryGuarantee,
		AuditFormat:            auditFormat,
		AuditRotateDur:         auditRotateDur,
		AuditRotateMax:         auditRotateMax,
		SnapshotEnabled:        cluster.Spec.Server.Snapshot.Enabled,
		SnapshotInterval:       snapshotInterval,
		SnapshotRetain:         snapshotRetain,
		S3Endpoint:             cluster.Spec.Server.Snapshot.S3.Endpoint,
		S3Bucket:               cluster.Spec.Server.Snapshot.S3.Bucket,
		S3Region:               s3Region,
		S3ForcePathStyle:       cluster.Spec.Server.Snapshot.S3.ForcePathStyle,
		Autopilot: autopilotData{
			CleanupDeadServers:      cluster.Spec.Server.Autopilot.CleanupDeadServers,
			LastContactThreshold:    lastContactThreshold,
			MaxTrailingLogs:         maxTrailingLogs,
			ServerStabilizationTime: serverStabilizationTime,
		},
	}
}

const serverHCLTemplate = `# Nomad Server Configuration
# Generated by nomad-enterprise-operator

# Data directory
data_dir = "/nomad/data"

# Topology
region     = "{{ .Region }}"
datacenter = "{{ .Datacenter }}"

# Bind address
bind_addr = "0.0.0.0"

# Advertise addresses
advertise {
  http = "{{ .AdvertiseAddress }}:4646"
  rpc  = "{{ .AdvertiseAddress }}:4647"
  serf = "{{ "{{ GetPrivateIP }}" }}:4648"
}

# Ports
ports {
  http = 4646
  rpc  = 4647
  serf = 4648
}

# Server configuration
server {
  enabled = true
  bootstrap_expect = {{ .Replicas }}

  # Server join configuration
  server_join {
    retry_join = [
{{- range $i := intRange .Replicas }}
      "{{ $.ClusterName }}-{{ $i }}.{{ $.HeadlessService }}.{{ $.Namespace }}.svc.cluster.local",
{{- end }}
    ]
    retry_interval = "15s"
    retry_max = 0
  }

  # Gossip encryption
  encrypt = "{{ .GossipKey }}"
}

{{ if .ACLEnabled -}}
# ACL configuration
acl {
  enabled = true
}
{{ end }}

# Autopilot configuration
autopilot {
  cleanup_dead_servers      = {{ .Autopilot.CleanupDeadServers }}
  last_contact_threshold    = "{{ .Autopilot.LastContactThreshold }}"
  max_trailing_logs         = {{ .Autopilot.MaxTrailingLogs }}
  server_stabilization_time = "{{ .Autopilot.ServerStabilizationTime }}"
}

{{ if .TLSEnabled -}}
# TLS configuration
tls {
  http = true
  rpc  = true

  ca_file   = "/nomad/tls/ca.crt"
  cert_file = "/nomad/tls/server.crt"
  key_file  = "/nomad/tls/server.key"

  verify_server_hostname = true
  verify_https_client    = true
}
{{ end }}

{{ if .AuditEnabled -}}
# Audit logging configuration
audit {
  enabled = true
  sink "file" {
    type               = "file"
    format             = "{{ .AuditFormat }}"
    path               = "/nomad/audit/audit.log"
    delivery_guarantee = "{{ .AuditDeliveryGuarantee }}"
    rotate_duration    = "{{ .AuditRotateDur }}"
    rotate_max_files   = {{ .AuditRotateMax }}
  }
}
{{ end }}

{{ if .SnapshotEnabled -}}
# Snapshot agent configuration
snapshot_agent {
  snapshot {
    interval         = "{{ .SnapshotInterval }}"
    retain           = {{ .SnapshotRetain }}
    stale_reads      = false
    deregister_after = "8h"
  }

  aws_s3 {
    endpoint                       = "{{ .S3Endpoint }}"
    bucket                         = "{{ .S3Bucket }}"
    region                         = "{{ .S3Region }}"
    s3_force_path_style            = {{ .S3ForcePathStyle }}
    disable_ssl                    = false
    skip_head_object_before_upload = true
  }
}
{{ end }}

# Telemetry
telemetry {
  publish_allocation_metrics = true
  publish_node_metrics       = true
  prometheus_metrics         = true
}

# Leave on interrupt/term
leave_on_interrupt = true
leave_on_terminate = true

# Disable update check
disable_update_check = true

# Log level
log_level = "INFO"
`
