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

	// OIDC configures OIDC authentication via Keycloak.
	// +optional
	OIDC *OIDCSpec `json:"oidc,omitempty"`
}

// ImageSpec defines container image configuration
type ImageSpec struct {
	// Repository is the container image repository
	// +kubebuilder:default="hashicorp/nomad"
	Repository string `json:"repository,omitempty"`

	// Tag is the container image tag
	// +kubebuilder:default="1.11-ent"
	Tag string `json:"tag,omitempty"`

	// PullPolicy defines when to pull the image. Defaults to Always because
	// the default tag (1.11-ent) is a floating tag that resolves to the latest
	// patch release. Set to IfNotPresent when pinning to a specific version
	// (e.g. 1.11.3-ent).
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

	// SecretKeys allows overriding the key names within the certificate Secret.
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

	// SecretKeys allows overriding the key names within the CA secret.
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

// PersistenceSpec defines storage configuration
type PersistenceSpec struct {
	// StorageClassName for the PVC (uses cluster default if empty)
	// +optional
	StorageClassName string `json:"storageClassName,omitempty"`

	// Size of the data volume. If set, persistence is enabled.
	// Set to empty string to disable persistence (use emptyDir).
	// +kubebuilder:default="10Gi"
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

// OIDCSpec configures OIDC authentication for the Nomad cluster via Keycloak.
// Requires the Keycloak operator to be installed in the same namespace and a
// healthy Keycloak CR referenced by KeycloakRef.
type OIDCSpec struct {
	// Enabled controls whether OIDC authentication is configured.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// KeycloakRef references the Keycloak CR that the realm import targets.
	// Must be in the same namespace as the NomadCluster.
	KeycloakRef corev1.LocalObjectReference `json:"keycloakRef"`

	// Realm is the name of the Keycloak realm to create. Defaults to the NomadCluster name.
	// +optional
	Realm string `json:"realm,omitempty"`

	// DiscoveryCA references a Secret containing the CA certificate used to
	// verify the Keycloak OIDC discovery endpoint. Required when the Keycloak
	// hostname is served behind a TLS certificate not in the system trust store
	// (e.g. OpenShift ingress with a private CA).
	// +optional
	DiscoveryCA *OIDCDiscoveryCASpec `json:"discoveryCA,omitempty"`

	// BindingRules defines how Keycloak groups map to Nomad ACL roles.
	// If empty, a default rule mapping the "nomad-admins" group to a
	// management-equivalent role is created.
	// +optional
	BindingRules []OIDCBindingRule `json:"bindingRules,omitempty"`
}

// OIDCDiscoveryCASpec references a Secret containing the CA certificate for
// OIDC discovery endpoint verification.
type OIDCDiscoveryCASpec struct {
	// SecretName is the name of the Secret containing the CA certificate.
	SecretName string `json:"secretName"`

	// SecretKey is the key within the Secret that holds the PEM-encoded CA certificate.
	// +kubebuilder:default="tls.crt"
	SecretKey string `json:"secretKey,omitempty"`
}

// RealmName returns the configured realm name, defaulting to the cluster name.
func (o *OIDCSpec) RealmName(clusterName string) string {
	if o.Realm != "" {
		return o.Realm
	}
	return clusterName
}

// OIDCBindingRule maps a Keycloak group to a Nomad ACL role.
type OIDCBindingRule struct {
	// KeycloakGroup is the Keycloak group path, including leading slash (e.g. "/nomad-admins").
	KeycloakGroup string `json:"keycloakGroup"`

	// NomadRole is the name of the Nomad ACL role to bind to this group.
	NomadRole string `json:"nomadRole"`

	// PolicyRules is the HCL policy document granted to this role.
	PolicyRules string `json:"policyRules"`
}

// OIDCStatus tracks the state of the OIDC integration.
type OIDCStatus struct {
	// RealmImportName is the name of the managed KeycloakRealmImport CR.
	// +optional
	RealmImportName string `json:"realmImportName,omitempty"`

	// ClientSecretName is the name of the Secret containing the OIDC client secret.
	// +optional
	ClientSecretName string `json:"clientSecretName,omitempty"`

	// AuthMethodName is the name of the Nomad ACL auth method created.
	// +optional
	AuthMethodName string `json:"authMethodName,omitempty"`

	// Ready indicates that the realm import is complete and Nomad has been
	// configured with the auth method, policies, roles, and binding rules.
	// +optional
	Ready bool `json:"ready,omitempty"`
}

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

	// OperatorStatusSecretName is the name of the Secret containing the
	// narrow-scope ACL token used by the operator for day-2 status API calls.
	// This token has operator:read only. The bootstrap token is not used after
	// initial ACL bootstrap completes.
	// +optional
	OperatorStatusSecretName string `json:"operatorStatusSecretName,omitempty"`

	// OperatorStatusPolicyName is the Nomad ACL policy name created for the
	// operator status token. Stored for cleanup if the cluster is deleted.
	// +optional
	OperatorStatusPolicyName string `json:"operatorStatusPolicyName,omitempty"`

	// RouteHost is the assigned Route hostname
	// +optional
	RouteHost string `json:"routeHost,omitempty"`

	// License contains Nomad Enterprise license information
	// +optional
	License *LicenseStatus `json:"license,omitempty"`

	// Autopilot contains Raft autopilot health information
	// +optional
	Autopilot *AutopilotStatus `json:"autopilot,omitempty"`

	// CertificateAuthority contains information about the CA in use.
	// +optional
	CertificateAuthority *CertificateAuthorityStatus `json:"certificateAuthority,omitempty"`

	// OIDC contains the observed state of the OIDC integration.
	// +optional
	OIDC OIDCStatus `json:"oidc,omitempty"`

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
