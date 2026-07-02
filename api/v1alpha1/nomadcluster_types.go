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

	// Monitoring configures ServiceMonitor and PrometheusRule creation.
	// Resources are created when enabled AND the Prometheus Operator CRDs
	// are installed — independent of openshift.enabled, so vanilla
	// Kubernetes clusters running Prometheus Operator get monitoring too.
	// +optional
	Monitoring MonitoringSpec `json:"monitoring,omitempty"`

	// Server configuration options
	// +optional
	Server ServerSpec `json:"server,omitempty"`

	// Persistence configuration for data volumes
	// +optional
	Persistence PersistenceSpec `json:"persistence,omitempty"`

	// Resources defines CPU and memory requests/limits
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

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

	// Tag is the container image tag. The default is pinned to a concrete
	// patch version rather than a floating tag, because Nomad is a Raft
	// cluster — a registry-side retag during a rolling restart can produce
	// version-mismatched peers and silent quorum loss. The operator's
	// release process updates this default in deliberate increments per
	// Nomad Enterprise release (see docs/release-process.md).
	// +kubebuilder:default="2.0.0-ent"
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9._-]+$`
	Tag string `json:"tag,omitempty"`

	// PullPolicy defines when to pull the image. Defaults to Always as a
	// safety measure against registry-side image content changes (a tag
	// being re-pushed) even though the default tag is now pinned to a
	// concrete patch version. Users on strict-pin workflows running fully
	// air-gapped or using image digests can override to IfNotPresent.
	// +kubebuilder:validation:Enum=Always;IfNotPresent;Never
	// +kubebuilder:default="Always"
	PullPolicy corev1.PullPolicy `json:"pullPolicy,omitempty"`
}

// LicenseSpec defines the Nomad Enterprise license configuration.
// Exactly one of SecretName or Value must be specified.
// +kubebuilder:validation:XValidation:rule="(has(self.secretName) && size(self.secretName) > 0) || (has(self.value) && size(self.value) > 0)",message="either secretName or value must be specified"
// +kubebuilder:validation:XValidation:rule="!((has(self.secretName) && size(self.secretName) > 0) && (has(self.value) && size(self.value) > 0))",message="secretName and value are mutually exclusive"
type LicenseSpec struct {
	// SecretName is the name of an existing secret containing the license.
	// The license must be stored under the key "license" (the key name is
	// operator-owned per ADR 0003). Mutually exclusive with Value.
	// +optional
	SecretName string `json:"secretName,omitempty"`

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
	// SecretName is the name of secret containing gossip key (auto-created
	// if empty). The key must be stored under "gossip-key" (the key name
	// is operator-owned per ADR 0003).
	// +optional
	SecretName string `json:"secretName,omitempty"`
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
	// Set to true to create Routes.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Route configuration for OpenShift Route
	// +optional
	Route RouteSpec `json:"route,omitempty"`
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

// RouteTLSSpec defines TLS configuration for the OpenShift Route.
// The Route always uses reencrypt termination with HTTP→HTTPS redirect.
// The operator automatically populates DestinationCACertificate from the
// Nomad CA. Optionally, a custom external-facing certificate can be
// provided instead of using the platform wildcard certificate.
type RouteTLSSpec struct {
	// CertificateSecretName is the name of a Secret containing a custom
	// TLS certificate for the external-facing side of the Route.
	// If omitted, the platform wildcard certificate is used.
	// +optional
	CertificateSecretName string `json:"certificateSecretName,omitempty"`

	// SecretKeys allows overriding the key names within the certificate
	// Secret, for Secrets populated by tooling (ESO, VSO) that does not
	// follow the kubernetes.io/tls key convention. The {} default makes
	// admission materialise the nested tls.crt/tls.key defaults even when
	// secretKeys is omitted — kubebuilder nested defaults only apply
	// inside objects that are present in the stored JSON.
	// +kubebuilder:default={}
	// +optional
	SecretKeys CertificateSecretKeys `json:"secretKeys,omitempty"`
}

// CertificateSecretKeys defines the key names within a TLS certificate Secret.
type CertificateSecretKeys struct {
	// Certificate is the key name for the TLS certificate.
	// +kubebuilder:default="tls.crt"
	Certificate string `json:"certificate,omitempty"`

	// PrivateKey is the key name for the TLS private key.
	// +kubebuilder:default="tls.key"
	PrivateKey string `json:"privateKey,omitempty"`
}

// MonitoringSpec defines Prometheus monitoring configuration. Scrape
// interval (30s) and timeout (10s) are operator-owned per ADR 0003;
// advanced scrape tuning belongs in Prometheus, not this CR.
type MonitoringSpec struct {
	// Enabled determines if monitoring resources are created
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// PrometheusRulesEnabled determines if PrometheusRule is created
	// +kubebuilder:default=false
	PrometheusRulesEnabled bool `json:"prometheusRulesEnabled,omitempty"`
}

// ServerSpec defines Nomad server configuration. Autopilot tuning is
// operator-owned per ADR 0003 (cleanup_dead_servers=true, 200ms last
// contact, 250 trailing logs, 10s stabilization — Nomad's defaults).
type ServerSpec struct {
	// ACL configuration
	// +optional
	ACL ACLSpec `json:"acl,omitempty"`

	// TLS configuration
	// +optional
	TLS TLSSpec `json:"tls,omitempty"`

	// Audit logging configuration
	// +optional
	Audit AuditSpec `json:"audit,omitempty"`
}

// ACLSpec defines ACL configuration. The bootstrap token Secret name is
// operator-owned per ADR 0003: always `<cluster>-acl-bootstrap`.
type ACLSpec struct {
	// Enabled determines if ACLs are enabled (defaults to true for security)
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`
}

// TLSSpec defines TLS configuration for the Nomad cluster.
// mTLS is always enabled. The operator generates and manages all certificates
// automatically using a self-signed CA unless CA.SecretName is provided,
// in which case certificates are issued from the user-supplied CA.
type TLSSpec struct {
	// CA optionally specifies a user-provided Certificate Authority for
	// certificate issuance. If not specified, the operator generates and
	// manages a self-signed CA. Providing a CA allows certificates to chain
	// to your organisation's trusted root.
	// +optional
	CA *CASpec `json:"ca,omitempty"`
}

// CASpec references a Secret containing a CA certificate and private key
// from which the operator will issue all Nomad certificates.
type CASpec struct {
	// SecretName is the name of the Secret containing the CA certificate
	// and private key. Expected keys: tls.crt (certificate), tls.key (private key).
	SecretName string `json:"secretName"`

	// SecretKeys allows overriding the key names within the CA secret,
	// for Secrets populated by tooling (ESO, VSO) that does not follow
	// the kubernetes.io/tls key convention. The {} default makes
	// admission materialise the nested tls.crt/tls.key defaults even when
	// secretKeys is omitted — kubebuilder nested defaults only apply
	// inside objects that are present in the stored JSON.
	// +kubebuilder:default={}
	// +optional
	SecretKeys CASecretKeys `json:"secretKeys,omitempty"`
}

// CASecretKeys defines the key names within a CA Secret.
type CASecretKeys struct {
	// Certificate is the key name for the CA certificate.
	// +kubebuilder:default="tls.crt"
	Certificate string `json:"certificate,omitempty"`

	// PrivateKey is the key name for the CA private key.
	// +kubebuilder:default="tls.key"
	PrivateKey string `json:"privateKey,omitempty"`
}

// AuditSpec defines audit logging configuration. Delivery guarantee
// (enforced), format (json), and rotation (24h × 15 files) are
// operator-owned per ADR 0003 — users needing different log shipping
// should ship via sidecar, not rotation tuning.
type AuditSpec struct {
	// Enabled determines if audit logging is enabled.
	// When enabled, an audit volume is automatically created.
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Size of the audit volume (created automatically when audit is enabled)
	// +kubebuilder:default="5Gi"
	Size string `json:"size,omitempty"`

	// StorageClassName for the audit PVC (uses cluster default if empty)
	// +optional
	StorageClassName string `json:"storageClassName,omitempty"`
}

// PersistenceSpec defines storage configuration
type PersistenceSpec struct {
	// StorageClassName for the PVC (uses cluster default if empty)
	// +optional
	StorageClassName string `json:"storageClassName,omitempty"`

	// Size of the data volume. If set, persistence is enabled.
	// Set to empty string to disable persistence (use emptyDir).
	// +kubebuilder:default="10Gi"
	Size string `json:"size,omitempty"`

	// ReclaimPolicy controls what happens to the data PVCs when the
	// NomadCluster is deleted. Retain (the default) leaves the PVCs in
	// place so Raft state survives accidental CR deletion and can be
	// re-adopted by a recreated cluster of the same name; Delete removes
	// them with the cluster. The value in effect at deletion time wins —
	// earlier values are not remembered.
	// +kubebuilder:validation:Enum=Retain;Delete
	// +kubebuilder:default=Retain
	// +optional
	ReclaimPolicy string `json:"reclaimPolicy,omitempty"`
}

// Valid spec.persistence.reclaimPolicy values.
const (
	ReclaimPolicyRetain = "Retain"
	ReclaimPolicyDelete = "Delete"
)

// ClusterPhase represents the phase of the NomadCluster
type ClusterPhase string

const (
	ClusterPhasePending  ClusterPhase = "Pending"
	ClusterPhaseCreating ClusterPhase = "Creating"
	ClusterPhaseRunning  ClusterPhase = "Running"
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

// CertificateAuthorityStatus contains information about the CA used for
// issuing Nomad certificates.
type CertificateAuthorityStatus struct {
	// Source indicates how the CA was provisioned.
	// Valid values: "operator-generated", "user-provided"
	Source string `json:"source"`

	// ExpiryTime is when the CA certificate expires.
	// +optional
	ExpiryTime string `json:"expiryTime,omitempty"`

	// Subject is the CA certificate's subject distinguished name.
	// +optional
	Subject string `json:"subject,omitempty"`

	// RenewalRequiredBy is the deadline by which the CA should be
	// renewed (expiry minus the renewal warning window). Crossing it
	// surfaces a one-shot Warning Event with reason CARenewalRequired;
	// Ready stays True (C5 / AC-2.4.10 — informational, not failure).
	// +optional
	RenewalRequiredBy string `json:"renewalRequiredBy,omitempty"`

	// RenewalWarningEmitted debounces the CARenewalRequired Event: set
	// when the Event fires, carried forward while the same CA remains in
	// place, reset when the CA rotates. Same per-cluster status-field
	// debounce pattern as InitialReconcileEventEmitted.
	// +optional
	RenewalWarningEmitted bool `json:"renewalWarningEmitted,omitempty"`
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
	// +kubebuilder:validation:Enum=Pending;Creating;Running;Failed
	Phase ClusterPhase `json:"phase,omitempty"`

	// Conditions represent the latest observations of the cluster state
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ReadyReplicas is the number of ready Nomad server pods
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// CurrentReplicas is the current number of Nomad server pods
	CurrentReplicas int32 `json:"currentReplicas,omitempty"`

	// LeaderAddress is the host:port of the current Raft leader as
	// reported by Nomad (if known). This is NOT the Raft server ID;
	// it is the leader's RPC address. Consumers that need the actual
	// Raft server ID should read it from
	// `status.autopilot.servers[?(@.leader==true)].id`.
	// +optional
	LeaderAddress string `json:"leaderAddress,omitempty"`

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

	// OperatorStatusSecretName is the name of the Secret containing the
	// narrow-scope ACL token used by the operator for day-2 status API calls.
	// This token has operator:read only. The bootstrap token is not used after
	// initial ACL bootstrap completes.
	// +optional
	OperatorStatusSecretName string `json:"operatorStatusSecretName,omitempty"`

	// OperatorManagementSecretName is the name of the Secret containing
	// the least-privilege management ACL token (acl:write,
	// operator:write) used for all day-2 management writes (C4). Cache
	// only: cleanup on deletion uses the deterministic name
	// `<cluster>-operator-management`, not this field (AC-2.4.7).
	// +optional
	OperatorManagementSecretName string `json:"operatorManagementSecretName,omitempty"`

	// OperatorStatusPolicyName is the Nomad ACL policy name created for the
	// operator status token. Stored for cleanup if the cluster is deleted.
	// +optional
	OperatorStatusPolicyName string `json:"operatorStatusPolicyName,omitempty"`

	// RouteHost is the assigned Route hostname
	// +optional
	RouteHost string `json:"routeHost,omitempty"`

	// NomadVersion is the agent version reported by /v1/agent/self
	// (e.g. "1.11.0+ent"). Probed each reconcile while at least one
	// pod is Ready; empty if the probe failed or has not yet run.
	// The version probe is non-fatal — failure does not gate other
	// status enrichment (C7 / AC-4.7.2).
	// +optional
	NomadVersion string `json:"nomadVersion,omitempty"`

	// License contains Nomad Enterprise license information
	// +optional
	License *LicenseStatus `json:"license,omitempty"`

	// Autopilot contains Raft autopilot health information
	// +optional
	Autopilot *AutopilotStatus `json:"autopilot,omitempty"`

	// CertificateAuthority contains information about the CA in use.
	// +optional
	CertificateAuthority *CertificateAuthorityStatus `json:"certificateAuthority,omitempty"`

	// ObservedGeneration is the last observed generation
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// LastReconcileTime is the timestamp of the most recent reconciliation
	// that produced a status mutation or that crossed the heartbeat
	// threshold of (defaultRequeueInterval / 2). It is NOT updated on
	// every reconcile loop — that would produce per-loop status writes
	// even when nothing observable changed (etcd write amplification and
	// false GitOps drift). Consumers treating this as "is the operator
	// alive?" should expect updates roughly every 2m30s at the operator's
	// 5-minute steady-state requeue cadence, plus immediate updates on
	// any real status transition.
	LastReconcileTime *metav1.Time `json:"lastReconcileTime,omitempty"`

	// InitialReconcileEventEmitted records whether the operator has
	// emitted the one-shot "InitialReconcileComplete" Event for this
	// cluster. Used as a per-cluster debounce so the Event fires
	// exactly once across the cluster's lifetime, even across
	// operator restarts. Downstream issues (B6 audit migration, etc.)
	// use the same status-field pattern for their per-cluster
	// one-shot Events.
	// +optional
	InitialReconcileEventEmitted bool `json:"initialReconcileEventEmitted,omitempty"`

	// AuditPVCMigrated records whether the operator has observed the
	// audit PVC Bound and emitted the one-shot "AuditPVCCreated" Event
	// for this cluster (B6 / AC-4.5.4). Same per-cluster debounce
	// pattern as InitialReconcileEventEmitted: the flag survives
	// operator restarts so the Event fires exactly once across the
	// cluster's lifetime.
	// +optional
	AuditPVCMigrated bool `json:"auditPVCMigrated,omitempty"`

	// ScaleDown tracks an in-flight Raft scale-down operation
	// (D2 / neo-1ve). Non-nil while peers are being removed from
	// the Raft quorum; cleared to nil when the operation completes
	// (i.e., the StatefulSet's replica count matches spec.replicas).
	// Used by the resume path so a crashed operator never re-removes
	// a peer (AC-2.3.7), by the admission gate that blocks concurrent
	// spec.replicas edits during scale-down (AC-2.3.5a), and by the
	// scale-down-in-progress metric (D2e).
	// +optional
	ScaleDown *ScaleDownStatus `json:"scaleDown,omitempty"`
}

// ScaleDownStatus tracks the in-flight Raft scale-down operation.
// Owned by D2 (neo-1ve); the status field is established here in D2a
// so D2b's reconcile loop and D2c's admission rule can both depend
// on a stable shape.
type ScaleDownStatus struct {
	// RemovedPeers is the list of Raft server IDs (as returned by
	// the autopilot API) the operator has already removed during the
	// current operation. The reconcile loop appends one ID per
	// successful RaftRemovePeer call and never re-removes an entry
	// in this list across operator restarts.
	// +optional
	RemovedPeers []string `json:"removedPeers,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=nc
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Ready",type="integer",JSONPath=".status.readyReplicas"
// +kubebuilder:printcolumn:name="Desired",type="integer",JSONPath=".spec.replicas"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Advertise",type="string",JSONPath=".status.advertiseAddress"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// AC-2.3.5a (D2c / neo-1ve.3): spec.replicas cannot be modified while
// a scale-down operation is in flight. Once the operator clears
// status.scaleDown at completion, edits are accepted again. Defends
// the resume contract (AC-2.3.7) — without this, a user who changes
// spec.replicas mid-operation can desynchronise the gap calculation
// from the recorded removed-peers list.
//
// Note on AC-2.3.5 / 2.3.6 (degraded-quorum opt-in): the design doc
// expected CRD CEL to gate scale-down below 3 replicas on an
// annotation. CRD validation rules on K8s 1.36 do NOT expose
// metadata.annotations or metadata.labels to CEL — only structural
// schema fields. AC-2.3.5 / 2.3.6 are therefore enforced by the
// operator's ScaleDownPhase (see internal/controller/phases/scaledown.go)
// via a ScaleDownBlocked-style Ready condition. The annotation
// remains the public contract.
// +kubebuilder:validation:XValidation:rule="self.spec.replicas == oldSelf.spec.replicas || !has(self.status) || !has(self.status.scaleDown) || !has(self.status.scaleDown.removedPeers) || size(self.status.scaleDown.removedPeers) == 0",message="spec.replicas cannot be modified while a scale-down operation is in progress; wait for status.scaleDown to clear"

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
