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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NomadClusterSpec defines the desired state of NomadCluster.
// +kubebuilder:validation:XValidation:rule="!has(self.server) || !has(self.server.snapshot) || !self.server.snapshot.enabled || size(self.server.snapshot.s3.bucket) > 0",message="server.snapshot.s3.bucket is required when server.snapshot.enabled is true"
type NomadClusterSpec struct {
	// Replicas is the number of Nomad server replicas (should be 1, 3, or 5)
	// +kubebuilder:validation:Enum=1;3;5
	// +kubebuilder:default=3
	Replicas int32 `json:"replicas,omitempty"`

	// Image configuration for the Nomad container
	Image ImageSpec `json:"image,omitempty"`

	// License is a reference to a secret containing the Nomad Enterprise license
	License LicenseSpec `json:"license"`

	// Topology defines region and datacenter settings
	// +optional
	Topology TopologySpec `json:"topology,omitempty"`

	// Gossip encryption configuration
	// +optional
	Gossip GossipSpec `json:"gossip,omitempty"`

	// Services configuration for Nomad endpoints
	// +optional
	Services ServicesSpec `json:"services,omitempty"`

	// OpenShift-specific configuration
	// +optional
	OpenShift OpenShiftSpec `json:"openshift,omitempty"`

	// Server configuration options
	// +optional
	Server ServerSpec `json:"server,omitempty"`

	// Persistence configuration for data volumes
	// +optional
	Persistence PersistenceSpec `json:"persistence,omitempty"`

	// Resources defines CPU and memory requests/limits
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// Affinity configuration for pod scheduling
	// +optional
	Affinity *AffinitySpec `json:"affinity,omitempty"`

	// TopologySpreadConstraints for distributing pods
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// NodeSelector for pod scheduling
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations for pod scheduling
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// ImagePullSecrets for private registries
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
}

// ImageSpec defines container image configuration
type ImageSpec struct {
	// Repository is the container image repository
	// +kubebuilder:default="hashicorp/nomad"
	Repository string `json:"repository,omitempty"`

	// Tag is the container image tag
	// +kubebuilder:default="1.11-ent"
	Tag string `json:"tag,omitempty"`

	// PullPolicy defines when to pull the image
	// +kubebuilder:validation:Enum=Always;IfNotPresent;Never
	// +kubebuilder:default="IfNotPresent"
	PullPolicy corev1.PullPolicy `json:"pullPolicy,omitempty"`
}

// LicenseSpec defines the Nomad Enterprise license configuration.
// Exactly one of SecretName or Value must be specified.
// +kubebuilder:validation:XValidation:rule="(has(self.secretName) && size(self.secretName) > 0) || (has(self.value) && size(self.value) > 0)",message="either secretName or value must be specified"
// +kubebuilder:validation:XValidation:rule="!((has(self.secretName) && size(self.secretName) > 0) && (has(self.value) && size(self.value) > 0))",message="secretName and value are mutually exclusive"
type LicenseSpec struct {
	// SecretName is the name of an existing secret containing the license.
	// Mutually exclusive with Value.
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// SecretKey is the key within the secret (default: "license")
	// Only used when SecretName is specified.
	// +kubebuilder:default="license"
	SecretKey string `json:"secretKey,omitempty"`

	// Value is the license content provided directly.
	// The operator will create and manage a secret from this value.
	// Mutually exclusive with SecretName.
	// +optional
	Value string `json:"value,omitempty"`
}

// TopologySpec defines Nomad topology configuration
type TopologySpec struct {
	// Region name for this Nomad cluster
	// +kubebuilder:default="global"
	Region string `json:"region,omitempty"`

	// Datacenter name (defaults to namespace if empty)
	// +optional
	Datacenter string `json:"datacenter,omitempty"`
}

// GossipSpec defines gossip encryption configuration
type GossipSpec struct {
	// SecretName is the name of secret containing gossip key (auto-created if empty)
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// SecretKey is the key within the secret
	// +kubebuilder:default="gossip-key"
	SecretKey string `json:"secretKey,omitempty"`
}

// ServicesSpec defines Kubernetes Service configuration
type ServicesSpec struct {
	// External LoadBalancer service configuration
	// +optional
	External ExternalServiceSpec `json:"external,omitempty"`
}

// ExternalServiceSpec defines the external LoadBalancer service
type ExternalServiceSpec struct {
	// Type of external service (LoadBalancer or NodePort)
	// +kubebuilder:validation:Enum=LoadBalancer;NodePort
	// +kubebuilder:default="LoadBalancer"
	Type corev1.ServiceType `json:"type,omitempty"`

	// LoadBalancerIP is the requested IP for LoadBalancer type
	// +optional
	LoadBalancerIP string `json:"loadBalancerIP,omitempty"`

	// Annotations for the external service
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// OpenShiftSpec defines OpenShift-specific configuration
type OpenShiftSpec struct {
	// Enabled determines if OpenShift-specific resources are created.
	// Set to true to create Routes and ServiceMonitors.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Route configuration for OpenShift Route
	// +optional
	Route RouteSpec `json:"route,omitempty"`

	// Monitoring configuration for ServiceMonitor and PrometheusRule
	// +optional
	Monitoring MonitoringSpec `json:"monitoring,omitempty"`
}

// RouteSpec defines OpenShift Route configuration
type RouteSpec struct {
	// Enabled determines if Route is created.
	// Only applies when OpenShift.Enabled is true.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Host is the custom hostname (auto-generated if empty)
	// +optional
	Host string `json:"host,omitempty"`

	// TLS configuration
	// +optional
	TLS RouteTLSSpec `json:"tls,omitempty"`
}

// RouteTLSSpec defines TLS configuration for Route
type RouteTLSSpec struct {
	// Termination type: edge, passthrough, or reencrypt
	// +kubebuilder:validation:Enum=edge;passthrough;reencrypt
	// +kubebuilder:default="edge"
	Termination string `json:"termination,omitempty"`

	// InsecureEdgeTerminationPolicy: Redirect, Allow, or None
	// +kubebuilder:validation:Enum=Redirect;Allow;None
	// +kubebuilder:default="Redirect"
	InsecureEdgeTerminationPolicy string `json:"insecureEdgeTerminationPolicy,omitempty"`
}

// MonitoringSpec defines Prometheus monitoring configuration
type MonitoringSpec struct {
	// Enabled determines if monitoring resources are created
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// ScrapeInterval for metrics collection (simplified from serviceMonitor.interval)
	// +kubebuilder:default="30s"
	ScrapeInterval string `json:"scrapeInterval,omitempty"`

	// ScrapeTimeout for metric collection (simplified from serviceMonitor.scrapeTimeout)
	// +kubebuilder:default="10s"
	ScrapeTimeout string `json:"scrapeTimeout,omitempty"`

	// AdditionalLabels to add to ServiceMonitor
	// +optional
	AdditionalLabels map[string]string `json:"additionalLabels,omitempty"`

	// PrometheusRulesEnabled determines if PrometheusRule is created
	// +kubebuilder:default=false
	PrometheusRulesEnabled bool `json:"prometheusRulesEnabled,omitempty"`

	// ServiceMonitor configuration (DEPRECATED - use flattened fields above)
	// +optional
	ServiceMonitor ServiceMonitorSpec `json:"serviceMonitor,omitempty"`

	// PrometheusRule configuration (DEPRECATED - use prometheusRulesEnabled)
	// +optional
	PrometheusRule PrometheusRuleSpec `json:"prometheusRule,omitempty"`
}

// ServiceMonitorSpec defines ServiceMonitor configuration (DEPRECATED)
type ServiceMonitorSpec struct {
	// Interval for scraping metrics (DEPRECATED - use MonitoringSpec.ScrapeInterval)
	Interval string `json:"interval,omitempty"`

	// ScrapeTimeout for metric collection (DEPRECATED - use MonitoringSpec.ScrapeTimeout)
	ScrapeTimeout string `json:"scrapeTimeout,omitempty"`

	// AdditionalLabels to add to ServiceMonitor (DEPRECATED - use MonitoringSpec.AdditionalLabels)
	// +optional
	AdditionalLabels map[string]string `json:"additionalLabels,omitempty"`
}

// PrometheusRuleSpec defines PrometheusRule configuration (DEPRECATED)
type PrometheusRuleSpec struct {
	// Enabled determines if PrometheusRule is created (DEPRECATED - use MonitoringSpec.PrometheusRulesEnabled)
	Enabled bool `json:"enabled,omitempty"`
}

// ServerSpec defines Nomad server configuration
type ServerSpec struct {
	// ACL configuration
	// +optional
	ACL ACLSpec `json:"acl,omitempty"`

	// TLS configuration
	// +optional
	TLS TLSSpec `json:"tls,omitempty"`

	// Autopilot configuration
	// +optional
	Autopilot AutopilotSpec `json:"autopilot,omitempty"`

	// Audit logging configuration
	// +optional
	Audit AuditSpec `json:"audit,omitempty"`

	// Snapshot agent configuration
	// +optional
	Snapshot SnapshotSpec `json:"snapshot,omitempty"`

	// ExtraConfig is raw HCL to append to server configuration
	// +optional
	ExtraConfig string `json:"extraConfig,omitempty"`
}

// ACLSpec defines ACL configuration
type ACLSpec struct {
	// Enabled determines if ACLs are enabled (defaults to true for security)
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// BootstrapSecretName is the secret to store bootstrap token (auto-created)
	// +optional
	BootstrapSecretName string `json:"bootstrapSecretName,omitempty"`
}

// TLSSpec defines TLS configuration.
// When Enabled is true, either SecretName or inline certificates (CACert, ServerCert, ServerKey) must be provided.
// +kubebuilder:validation:XValidation:rule="!self.enabled || (has(self.secretName) && size(self.secretName) > 0) || (has(self.caCert) && size(self.caCert) > 0 && has(self.serverCert) && size(self.serverCert) > 0 && has(self.serverKey) && size(self.serverKey) > 0)",message="when TLS is enabled, either secretName or all inline certificates (caCert, serverCert, serverKey) must be specified"
// +kubebuilder:validation:XValidation:rule="!((has(self.secretName) && size(self.secretName) > 0) && (has(self.caCert) && size(self.caCert) > 0))",message="secretName and inline certificates are mutually exclusive"
type TLSSpec struct {
	// Enabled determines if TLS is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// SecretName containing TLS certificates (ca.crt, server.crt, server.key).
	// Mutually exclusive with inline certificates.
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// CACert is the CA certificate in PEM format.
	// The operator will create and manage a secret from inline certificates.
	// Must be provided together with ServerCert and ServerKey.
	// +optional
	CACert string `json:"caCert,omitempty"`

	// ServerCert is the server certificate in PEM format.
	// Must be provided together with CACert and ServerKey.
	// +optional
	ServerCert string `json:"serverCert,omitempty"`

	// ServerKey is the server private key in PEM format.
	// Must be provided together with CACert and ServerCert.
	// +optional
	ServerKey string `json:"serverKey,omitempty"`
}

// AutopilotSpec defines Autopilot configuration
type AutopilotSpec struct {
	// CleanupDeadServers enables automatic removal of dead servers
	// +kubebuilder:default=true
	CleanupDeadServers bool `json:"cleanupDeadServers,omitempty"`

	// LastContactThreshold before marking server unhealthy
	// +kubebuilder:default="200ms"
	LastContactThreshold string `json:"lastContactThreshold,omitempty"`

	// MaxTrailingLogs before server is considered unhealthy
	// +kubebuilder:default=250
	MaxTrailingLogs int `json:"maxTrailingLogs,omitempty"`

	// ServerStabilizationTime before becoming voter
	// +kubebuilder:default="10s"
	ServerStabilizationTime string `json:"serverStabilizationTime,omitempty"`
}

// AuditSpec defines audit logging configuration
type AuditSpec struct {
	// Enabled determines if audit logging is enabled.
	// When enabled, an audit volume is automatically created.
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// DeliveryGuarantee determines behavior when audit logging fails.
	// "enforced" blocks requests if audit fails (recommended for production).
	// "best-effort" allows requests even if audit fails (useful for development).
	// +kubebuilder:validation:Enum=enforced;best-effort
	// +kubebuilder:default="enforced"
	DeliveryGuarantee string `json:"deliveryGuarantee,omitempty"`

	// Format of audit logs (json or log)
	// +kubebuilder:validation:Enum=json;log
	// +kubebuilder:default="json"
	Format string `json:"format,omitempty"`

	// RotateDuration for log rotation
	// +kubebuilder:default="24h"
	RotateDuration string `json:"rotateDuration,omitempty"`

	// RotateMaxFiles to retain
	// +kubebuilder:default=15
	RotateMaxFiles int `json:"rotateMaxFiles,omitempty"`

	// Size of the audit volume (created automatically when audit is enabled)
	// +kubebuilder:default="5Gi"
	Size string `json:"size,omitempty"`

	// StorageClassName for the audit PVC (uses cluster default if empty)
	// +optional
	StorageClassName string `json:"storageClassName,omitempty"`
}

// SnapshotSpec defines snapshot agent configuration
type SnapshotSpec struct {
	// Enabled determines if snapshots are enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Interval between snapshots
	// +kubebuilder:default="1h"
	Interval string `json:"interval,omitempty"`

	// Retain number of snapshots
	// +kubebuilder:default=24
	Retain int `json:"retain,omitempty"`

	// S3 configuration for snapshot storage
	// +optional
	S3 S3Spec `json:"s3,omitempty"`
}

// S3Spec defines S3-compatible storage configuration.
// Credentials can be provided via CredentialsSecretName or inline (AccessKeyID + SecretAccessKey).
// +kubebuilder:validation:XValidation:rule="!((has(self.credentialsSecretName) && size(self.credentialsSecretName) > 0) && (has(self.accessKeyId) && size(self.accessKeyId) > 0))",message="credentialsSecretName and inline credentials are mutually exclusive"
type S3Spec struct {
	// Endpoint URL for S3-compatible storage
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// Bucket name
	// +optional
	Bucket string `json:"bucket,omitempty"`

	// Region
	// +kubebuilder:default="us-east-1"
	Region string `json:"region,omitempty"`

	// ForcePathStyle enables path-style addressing
	// +kubebuilder:default=true
	ForcePathStyle bool `json:"forcePathStyle,omitempty"`

	// CredentialsSecretName is the name of an existing secret containing access-key-id and secret-access-key.
	// Mutually exclusive with inline credentials.
	// +optional
	CredentialsSecretName string `json:"credentialsSecretName,omitempty"`

	// AccessKeyID is the S3 access key ID provided directly.
	// The operator will create and manage a secret from inline credentials.
	// Must be provided together with SecretAccessKey.
	// +optional
	AccessKeyID string `json:"accessKeyId,omitempty"`

	// SecretAccessKey is the S3 secret access key provided directly.
	// Must be provided together with AccessKeyID.
	// +optional
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
}

// PersistenceSpec defines storage configuration
type PersistenceSpec struct {
	// Enabled is DEPRECATED - persistence is now inferred from Size being non-empty.
	// If Size is set, persistence is enabled. This field is ignored.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// StorageClassName for the PVC (uses cluster default if empty)
	// +optional
	StorageClassName string `json:"storageClassName,omitempty"`

	// Size of the data volume. If set, persistence is enabled.
	// Set to empty string to disable persistence (use emptyDir).
	// +kubebuilder:default="10Gi"
	Size string `json:"size,omitempty"`

	// Audit volume configuration (DEPRECATED - use server.audit.size instead)
	// +optional
	Audit AuditPersistenceSpec `json:"audit,omitempty"`
}

// AuditPersistenceSpec defines audit log storage
type AuditPersistenceSpec struct {
	// Enabled determines if separate audit volume is used
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// StorageClassName for the audit PVC
	// +optional
	StorageClassName string `json:"storageClassName,omitempty"`

	// Size of the audit volume
	// +kubebuilder:default="5Gi"
	Size string `json:"size,omitempty"`
}

// AffinitySpec defines pod affinity configuration
type AffinitySpec struct {
	// PodAntiAffinity configuration
	// +optional
	PodAntiAffinity PodAntiAffinitySpec `json:"podAntiAffinity,omitempty"`
}

// PodAntiAffinitySpec defines pod anti-affinity
type PodAntiAffinitySpec struct {
	// Enabled determines if pod anti-affinity is configured
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Type: preferred or required
	// +kubebuilder:validation:Enum=preferred;required
	// +kubebuilder:default="preferred"
	Type string `json:"type,omitempty"`

	// Weight for preferred anti-affinity (1-100)
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=100
	Weight int32 `json:"weight,omitempty"`

	// TopologyKey for anti-affinity
	// +kubebuilder:default="kubernetes.io/hostname"
	TopologyKey string `json:"topologyKey,omitempty"`
}

// ClusterPhase represents the phase of the NomadCluster
type ClusterPhase string

const (
	ClusterPhasePending  ClusterPhase = "Pending"
	ClusterPhaseCreating ClusterPhase = "Creating"
	ClusterPhaseRunning  ClusterPhase = "Running"
	ClusterPhaseUpdating ClusterPhase = "Updating"
	ClusterPhaseFailed   ClusterPhase = "Failed"
)

// Condition types for NomadCluster
const (
	// ConditionTypeReady indicates the cluster is ready
	ConditionTypeReady = "Ready"

	// ConditionTypeGossipKeyReady indicates gossip key is configured
	ConditionTypeGossipKeyReady = "GossipKeyReady"

	// ConditionTypeServicesReady indicates all services are ready
	ConditionTypeServicesReady = "ServicesReady"

	// ConditionTypeAdvertiseResolved indicates LoadBalancer IP is resolved
	ConditionTypeAdvertiseResolved = "AdvertiseResolved"

	// ConditionTypeStatefulSetReady indicates StatefulSet is ready
	ConditionTypeStatefulSetReady = "StatefulSetReady"

	// ConditionTypeACLBootstrapped indicates ACL bootstrap is complete
	ConditionTypeACLBootstrapped = "ACLBootstrapped"

	// ConditionTypeRouteReady indicates OpenShift Route is ready
	ConditionTypeRouteReady = "RouteReady"

	// ConditionTypeMonitoringReady indicates monitoring resources are ready
	ConditionTypeMonitoringReady = "MonitoringReady"

	// ConditionTypeLicenseValid indicates the Nomad Enterprise license status
	ConditionTypeLicenseValid = "LicenseValid"

	// ConditionTypeAutopilotHealthy indicates Raft autopilot health status
	ConditionTypeAutopilotHealthy = "AutopilotHealthy"
)

// LicenseStatus represents the Nomad Enterprise license information
type LicenseStatus struct {
	// Valid indicates if the license is currently valid
	Valid bool `json:"valid"`

	// LicenseID is the unique identifier for the license
	// +optional
	LicenseID string `json:"licenseId,omitempty"`

	// ExpirationTime is when the license expires
	// +optional
	ExpirationTime string `json:"expirationTime,omitempty"`

	// TerminationTime is when the license terminates (grace period end)
	// +optional
	TerminationTime string `json:"terminationTime,omitempty"`

	// Features is the list of licensed features
	// +optional
	Features []string `json:"features,omitempty"`
}

// AutopilotStatus represents the Raft autopilot health information
type AutopilotStatus struct {
	// Healthy indicates if autopilot considers the cluster healthy
	Healthy bool `json:"healthy"`

	// FailureTolerance is the number of server failures the cluster can tolerate
	FailureTolerance int `json:"failureTolerance"`

	// Voters is the number of voting servers
	Voters int `json:"voters"`

	// Servers is the detailed status of each server
	// +optional
	Servers []ServerStatus `json:"servers,omitempty"`
}

// ServerStatus represents the status of a single Nomad server in the cluster
type ServerStatus struct {
	// Name is the server name (typically the pod name)
	Name string `json:"name"`

	// ID is the Raft server ID
	ID string `json:"id"`

	// Address is the server's RPC address
	Address string `json:"address"`

	// Healthy indicates if the server is healthy
	Healthy bool `json:"healthy"`

	// Voter indicates if the server is a voting member
	Voter bool `json:"voter"`

	// Leader indicates if this server is the current Raft leader
	Leader bool `json:"leader"`

	// StableSince is when the server became stable
	// +optional
	StableSince string `json:"stableSince,omitempty"`

	// LastContact is the time since last contact with the leader
	// +optional
	LastContact string `json:"lastContact,omitempty"`
}

// NomadClusterStatus defines the observed state of NomadCluster.
type NomadClusterStatus struct {
	// Phase represents the current phase of the cluster
	// +kubebuilder:validation:Enum=Pending;Creating;Running;Updating;Failed
	Phase ClusterPhase `json:"phase,omitempty"`

	// Conditions represent the latest observations of the cluster state
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ReadyReplicas is the number of ready Nomad server pods
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// CurrentReplicas is the current number of Nomad server pods
	CurrentReplicas int32 `json:"currentReplicas,omitempty"`

	// LeaderID is the Raft leader node ID (if known)
	// +optional
	LeaderID string `json:"leaderID,omitempty"`

	// AdvertiseAddress is the resolved LoadBalancer address
	// +optional
	AdvertiseAddress string `json:"advertiseAddress,omitempty"`

	// GossipKeySecretName is the name of secret containing gossip key
	// +optional
	GossipKeySecretName string `json:"gossipKeySecretName,omitempty"`

	// ACLBootstrapped indicates if ACL bootstrap has completed
	// +optional
	ACLBootstrapped bool `json:"aclBootstrapped,omitempty"`

	// ACLBootstrapSecretName is the secret containing bootstrap token
	// +optional
	ACLBootstrapSecretName string `json:"aclBootstrapSecretName,omitempty"`

	// RouteHost is the assigned Route hostname
	// +optional
	RouteHost string `json:"routeHost,omitempty"`

	// License contains Nomad Enterprise license information
	// +optional
	License *LicenseStatus `json:"license,omitempty"`

	// Autopilot contains Raft autopilot health information
	// +optional
	Autopilot *AutopilotStatus `json:"autopilot,omitempty"`

	// ObservedGeneration is the last observed generation
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// LastReconcileTime is the timestamp of last reconciliation
	LastReconcileTime *metav1.Time `json:"lastReconcileTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=nc
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Ready",type="integer",JSONPath=".status.readyReplicas"
// +kubebuilder:printcolumn:name="Desired",type="integer",JSONPath=".spec.replicas"
// +kubebuilder:printcolumn:name="Advertise",type="string",JSONPath=".status.advertiseAddress"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// NomadCluster is the Schema for the nomadclusters API.
type NomadCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NomadClusterSpec   `json:"spec,omitempty"`
	Status NomadClusterStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NomadClusterList contains a list of NomadCluster.
type NomadClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NomadCluster `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NomadCluster{}, &NomadClusterList{})
}
