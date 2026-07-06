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
	// Resources are created when enabled AND the Prometheus Operator
	// CRDs are installed; independent of openshift.enabled.
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

	// Tag is the container image tag, default-pinned to a concrete
	// patch version: a registry-side retag mid-roll can produce
	// version-mismatched Raft peers and silent quorum loss.
	// +kubebuilder:default="2.0.3-ent"
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9._-]+$`
	Tag string `json:"tag,omitempty"`

	// Digest optionally pins the image by content digest. When set, the
	// reference is `repository@digest` and Tag is ignored (defaulting
	// materialises Tag before validation, so CEL exclusion is
	// impossible).
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	// +optional
	Digest string `json:"digest,omitempty"`

	// PullPolicy defaults to Always as a defence against registry-side
	// retags; digest-pinned or air-gapped workflows can use
	// IfNotPresent.
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
	// operator-owned). Mutually exclusive with Value.
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
	// is operator-owned).
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

	// SecretKeys overrides the Secret key names for tooling (ESO, VSO)
	// that does not follow the kubernetes.io/tls convention. The {}
	// default materialises the nested defaults when omitted.
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
// interval (30s) and timeout (10s) are operator-owned;
// advanced scrape tuning belongs in Prometheus, not this CR.
type MonitoringSpec struct {
	// Enabled determines if monitoring resources are created
	// +kubebuilder:default=true
	// Pointer + omitempty is load-bearing: a plain bool either drops
	// explicit false (omitempty: apiserver re-defaults it true on the
	// operator's next write) or writes false into fields the user
	// never set (no omitempty: the zero value overwrites the default).
	// nil means "user said nothing" and reads as the default via
	// IsEnabled().
	Enabled *bool `json:"enabled,omitempty"`

	// PrometheusRulesEnabled determines if PrometheusRule is created
	// +kubebuilder:default=false
	PrometheusRulesEnabled bool `json:"prometheusRulesEnabled,omitempty"`
}

// IsEnabled resolves the tri-state pointer: nil (unset) follows the
// default (true).
func (m MonitoringSpec) IsEnabled() bool { return m.Enabled == nil || *m.Enabled }

// ServerSpec defines Nomad server configuration. Autopilot tuning is
// operator-owned (cleanup_dead_servers=true, 200ms last
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

	// Keyrings configures external KMS protection for Nomad's root
	// encryption keys (Variables encryption, workload-identity signing).
	// Every listed keyring is active: new keys are wrapped by all
	// entries, so any one surviving KMS can unwrap (HA). Omitted = the
	// default aead keyring, whose KEK rides Raft IN CLEARTEXT — meaning
	// snapshots (including NomadSnapshot uploads) contain key material.
	// The operator manages migration between keyring sets, including
	// enable, disable, and provider changes, with no quorum impact.
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Keyrings []KeyringEntry `json:"keyrings,omitempty"`
}

// KeyringEntry names one KMS keyring. Exactly one provider block must
// be set per entry (CEL-enforced).
// +kubebuilder:validation:XValidation:rule="(has(self.awskms) ? 1 : 0) + (has(self.azurekeyvault) ? 1 : 0) + (has(self.gcpckms) ? 1 : 0) + (has(self.transit) ? 1 : 0) == 1",message="exactly one of awskms, azurekeyvault, gcpckms, or transit must be set per keyring entry"
type KeyringEntry struct {
	// Name identifies this keyring; rendered as the Nomad keyring block
	// name. Unique within the list.
	// +kubebuilder:validation:Pattern=`^[a-zA-Z][a-zA-Z0-9_-]*$`
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`

	// +optional
	AWSKMS *AWSKMSKeyring `json:"awskms,omitempty"`
	// +optional
	AzureKeyVault *AzureKeyVaultKeyring `json:"azurekeyvault,omitempty"`
	// +optional
	GCPCKMS *GCPCKMSKeyring `json:"gcpckms,omitempty"`
	// +kubebuilder:validation:XValidation:rule="(self.auth.method == 'token') == has(self.auth.token) && (self.auth.method == 'kubernetes') == has(self.auth.kubernetes) && (self.auth.method == 'jwt') == has(self.auth.jwt)",message="auth requires exactly the per-method block matching method"
	// +kubebuilder:validation:XValidation:rule="self.auth.method == 'token' || has(self.auth.mount)",message="auth.mount is required for the kubernetes and jwt methods"
	// +optional
	Transit *TransitKeyring `json:"transit,omitempty"`
}

// AWSKMSKeyring wraps root keys with AWS KMS.
type AWSKMSKeyring struct {
	// KMSKeyID is the KMS key: an ID, ARN, or alias/<name>.
	// +kubebuilder:validation:MinLength=1
	KMSKeyID string `json:"kmsKeyID"`

	// Region of the KMS key. Omitted = SDK default chain.
	// +optional
	Region string `json:"region,omitempty"`

	// Endpoint overrides the KMS endpoint (FIPS or KMS-compatible).
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// CredentialsSecretRef names a Secret with AWS_ACCESS_KEY_ID,
	// AWS_SECRET_ACCESS_KEY, and optionally AWS_SESSION_TOKEN. Omitted =
	// ambient identity (IRSA / instance profile).
	// +optional
	CredentialsSecretRef *corev1.LocalObjectReference `json:"credentialsSecretRef,omitempty"`
}

// AzureKeyVaultKeyring wraps root keys with Azure Key Vault.
// resource "managedhsm.azure.net" selects a Managed HSM vault.
type AzureKeyVaultKeyring struct {
	// +kubebuilder:validation:MinLength=1
	VaultName string `json:"vaultName"`
	// +kubebuilder:validation:MinLength=1
	KeyName string `json:"keyName"`
	// +kubebuilder:validation:MinLength=1
	TenantID string `json:"tenantID"`

	// Environment, e.g. AZUREPUBLICCLOUD (the default).
	// +optional
	Environment string `json:"environment,omitempty"`

	// Resource is the key vault resource domain; set
	// "managedhsm.azure.net" for Managed HSM.
	// +optional
	Resource string `json:"resource,omitempty"`

	// CredentialsSecretRef names a Secret with AZURE_CLIENT_ID and
	// AZURE_CLIENT_SECRET. Omitted = MSI / workload identity.
	// +optional
	CredentialsSecretRef *corev1.LocalObjectReference `json:"credentialsSecretRef,omitempty"`
}

// GCPCKMSKeyring wraps root keys with GCP Cloud KMS.
type GCPCKMSKeyring struct {
	// +kubebuilder:validation:MinLength=1
	Project string `json:"project"`
	// +kubebuilder:validation:MinLength=1
	Region string `json:"region"`
	// +kubebuilder:validation:MinLength=1
	KeyRing string `json:"keyRing"`
	// +kubebuilder:validation:MinLength=1
	CryptoKey string `json:"cryptoKey"`

	// CredentialsSecretRef names a Secret whose single key holds a
	// service-account JSON, mounted and exposed as
	// GOOGLE_APPLICATION_CREDENTIALS. Omitted = workload identity.
	// +optional
	CredentialsSecretRef *corev1.LocalObjectReference `json:"credentialsSecretRef,omitempty"`
}

// TransitKeyring wraps root keys with Vault's transit engine.
type TransitKeyring struct {
	// Address is the Vault cluster URL.
	// +kubebuilder:validation:Pattern=`^https?://`
	Address string `json:"address"`
	// +kubebuilder:validation:MinLength=1
	KeyName string `json:"keyName"`
	// +kubebuilder:validation:MinLength=1
	MountPath string `json:"mountPath"`

	// Namespace is the Vault namespace of the transit engine.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// KeyIDPrefix disambiguates wrapped key IDs when multiple transit
	// keyrings are listed.
	// +optional
	KeyIDPrefix string `json:"keyIDPrefix,omitempty"`

	// TLSServerName is the SNI hostname for the Vault connection.
	// +optional
	TLSServerName string `json:"tlsServerName,omitempty"`

	// CASecretRef names a Secret whose ca.crt verifies the Vault
	// connection, for CAs outside the system trust store.
	// +optional
	CASecretRef *corev1.LocalObjectReference `json:"caSecretRef,omitempty"`

	// ClientCertSecretRef names a kubernetes.io/tls-shaped Secret
	// (tls.crt, tls.key) for mTLS to Vault.
	// +optional
	ClientCertSecretRef *corev1.LocalObjectReference `json:"clientCertSecretRef,omitempty"`

	// Auth selects one of four credential vectors for the transit
	// connection, mirroring the Vault Secrets Operator's VaultAuth
	// structure (method + mount/namespace, per-method blocks).
	Auth *TransitAuth `json:"auth"`
}

// TransitAuth is the transit keyring's Vault credential configuration.
// Exactly one per-method block is set, agreeing with method:
//
//	token:      a long-lived user-minted Vault token (no login call;
//	            user-owned lifecycle). Our extension beyond VSO.
//	kubernetes: TokenReview-validated login — either a user-minted
//	            long-lived ServiceAccount token (secretRef) or the
//	            DEFAULT ephemeral operator-minted TokenRequest token
//	            (single-use, never stored; the VSO pattern).
//	jwt:        JWKS/OIDC-validated login with the same two
//	            ServiceAccount token sources.
type TransitAuth struct {
	// Method declares the credential vector explicitly.
	// +kubebuilder:validation:Enum=token;kubernetes;jwt
	Method string `json:"method"`

	// Mount is the Vault auth mount path (e.g. "kubernetes", "jwt").
	// Not used by method=token.
	// +kubebuilder:validation:MaxLength=128
	// +optional
	Mount string `json:"mount,omitempty"`

	// Namespace is the Vault namespace for the login call. Defaults to
	// the transit entry's namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Token configures method=token.
	// +optional
	Token *TransitAuthToken `json:"token,omitempty"`

	// Kubernetes configures method=kubernetes.
	// +optional
	Kubernetes *TransitAuthKubernetes `json:"kubernetes,omitempty"`

	// JWT configures method=jwt.
	// +optional
	JWT *TransitAuthKubernetes `json:"jwt,omitempty"`
}

// TransitAuthToken is the long-lived user-minted Vault token vector.
type TransitAuthToken struct {
	// SecretRef names a Secret whose VAULT_TOKEN key holds the token.
	// The operator wires it to the server pods and manages nothing
	// else: renewal and rotation are user-owned (rotation is delivered
	// by the Secret watch and rolls pods).
	SecretRef corev1.LocalObjectReference `json:"secretRef"`
}

// TransitAuthKubernetes configures a ServiceAccount-JWT login (shared
// by the kubernetes and jwt methods — their login payloads are
// identical; only Vault-side validation differs).
type TransitAuthKubernetes struct {
	// Role is the Vault role to log in as.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	Role string `json:"role"`

	// ServiceAccountTokenSecretRef names a Secret whose token key
	// holds a user-managed long-lived ServiceAccount JWT, replacing
	// the default ephemeral TokenRequest source.
	// +optional
	ServiceAccountTokenSecretRef *corev1.LocalObjectReference `json:"serviceAccountTokenSecretRef,omitempty"`

	// Audiences for the ephemeral ServiceAccount token. Ignored when
	// serviceAccountTokenSecretRef is set.
	// +kubebuilder:default={"vault"}
	// +optional
	Audiences []string `json:"audiences,omitempty"`

	// TokenExpirationSeconds bounds the ephemeral ServiceAccount token
	// lifetime. It is used once, immediately, and never stored.
	// Ignored when serviceAccountTokenSecretRef is set.
	// +kubebuilder:default=600
	// +kubebuilder:validation:Minimum=600
	// +kubebuilder:validation:Maximum=86400
	// +optional
	TokenExpirationSeconds int64 `json:"tokenExpirationSeconds,omitempty"`
}

// ACLSpec defines ACL configuration. The bootstrap token Secret name is
// operator-owned: always `<cluster>-acl-bootstrap`.
type ACLSpec struct {
	// Enabled determines if ACLs are enabled (defaults to true for security)
	// +kubebuilder:default=true
	// Pointer + omitempty is load-bearing: a plain bool either drops
	// explicit false (omitempty: apiserver re-defaults it true on the
	// operator's next write) or writes false into fields the user
	// never set (no omitempty: the zero value overwrites the default).
	// nil means "user said nothing" and reads as the default via
	// IsEnabled().
	Enabled *bool `json:"enabled,omitempty"`
}

// IsEnabled resolves the tri-state pointer: nil (unset) follows the
// default (true).
func (a ACLSpec) IsEnabled() bool { return a.Enabled == nil || *a.Enabled }

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

	// SecretKeys overrides the Secret key names for tooling (ESO, VSO)
	// that does not follow the kubernetes.io/tls convention. The {}
	// default materialises the nested defaults when omitted.
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
// operator-owned — users needing different log shipping
// should ship via sidecar, not rotation tuning.
type AuditSpec struct {
	// Enabled determines if audit logging is enabled.
	// When enabled, an audit volume is automatically created.
	// +kubebuilder:default=true
	// Pointer + omitempty is load-bearing: a plain bool either drops
	// explicit false (omitempty: apiserver re-defaults it true on the
	// operator's next write) or writes false into fields the user
	// never set (no omitempty: the zero value overwrites the default).
	// nil means "user said nothing" and reads as the default via
	// IsEnabled().
	Enabled *bool `json:"enabled,omitempty"`

	// Size of the audit volume (created automatically when audit is enabled)
	// +kubebuilder:default="5Gi"
	Size string `json:"size,omitempty"`

	// StorageClassName for the audit PVC (uses cluster default if empty)
	// +optional
	StorageClassName string `json:"storageClassName,omitempty"`
}

// IsEnabled resolves the tri-state pointer: nil (unset) follows the
// default (true).
func (a AuditSpec) IsEnabled() bool { return a.Enabled == nil || *a.Enabled }

// PersistenceSpec defines storage configuration
type PersistenceSpec struct {
	// StorageClassName for the PVC (uses cluster default if empty)
	// +optional
	StorageClassName string `json:"storageClassName,omitempty"`

	// Size of the data volume. If set, persistence is enabled.
	// Set to empty string to disable persistence (use emptyDir).
	// +kubebuilder:default="10Gi"
	Size string `json:"size,omitempty"`

	// ReclaimPolicy controls data-PVC fate on cluster deletion. Delete
	// (default) removes the data PVCs with the cluster. Retain keeps
	// them, but re-adoption by a recreated cluster does NOT recover
	// automatically: Raft stores peer addresses as pod IPs, which
	// change on recreation, so a fully recreated cluster needs manual
	// outage recovery. Prefer NomadSnapshot restore for recovery.
	// Deletion-time value wins.
	// +kubebuilder:validation:Enum=Retain;Delete
	// +kubebuilder:default=Delete
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

// Condition contract: exactly ONE condition, type "Ready"; sub-state
// lives in dedicated status fields. Unknown probe state does not fail
// Ready. Ready=False reasons:
//
//	WaitingForReplicas        — StatefulSet below desired ready count
//	LicenseExpired            — Nomad Enterprise license invalid
//	AutopilotUnhealthy        — Raft autopilot reports unhealthy
//	LicenseSecretNotFound     — referenced license Secret absent
//	LicenseSecretInvalid      — license Secret present, key missing
//	CAExpired                 — CA past expiry (checked before
//	                            WaitingForReplicas: name the cause,
//	                            not the symptom)
//	PhaseFailed               — a reconcile phase returned an error
//	Reconciling               — generic requeue
//	ScaleDownBlocked          — scale-down waiting on a Raft leader
//	DegradedQuorumNotAccepted — scale-down below 3 lacks the opt-in
//
// Condition types stay string literals; deliberately no ConditionType
// constants.

// KeyringStatus reports keyring reconciliation state.
type KeyringStatus struct {
	// Active lists the keyring entries currently wrapping new keys
	// ("aead" when the default file keyring is in use).
	// +optional
	Active []string `json:"active,omitempty"`

	// Retiring lists entries kept only until their wrapped keys are
	// removed; cleared when migration completes.
	// +optional
	Retiring []string `json:"retiring,omitempty"`

	// TokenExpiry is when the operator-managed Vault token expires;
	// only set when a transit entry uses auth.
	// +optional
	TokenExpiry *metav1.Time `json:"tokenExpiry,omitempty"`

	// Phase is Ready, Introducing, Rotating, Retiring, or Degraded
	// (Ready state machine, but Nomad reports the keyring inoperable).
	// +kubebuilder:validation:Enum=Ready;Introducing;Rotating;Retiring;Degraded
	// +optional
	Phase string `json:"phase,omitempty"`
}

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

	// RenewalRequiredBy is CA expiry minus the 30-day window. For
	// operator CAs: when automatic rotation starts. For user CAs: when
	// a human must renew (CARenewalRequired Events).
	// +optional
	RenewalRequiredBy string `json:"renewalRequiredBy,omitempty"`

	// RenewalWarningThreshold records the last emitted warning bucket
	// ("30d", "14d", or "7d:<date>" daily), debouncing the escalating
	// user-CA Events across operator restarts.
	// +optional
	RenewalWarningThreshold string `json:"renewalWarningThreshold,omitempty"`
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

	// LeaderAddress is the leader's RPC host:port (not its Raft server
	// ID — that lives in status.autopilot.servers).
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

	// OperatorManagementSecretName names the Secret holding the
	// management-type token for day-2 ACL writes. Cache only — cleanup
	// uses the deterministic name, not this field.
	// +optional
	OperatorManagementSecretName string `json:"operatorManagementSecretName,omitempty"`

	// OperatorStatusPolicyName is the Nomad ACL policy name created for the
	// operator status token. Stored for cleanup if the cluster is deleted.
	// +optional
	OperatorStatusPolicyName string `json:"operatorStatusPolicyName,omitempty"`

	// RouteHost is the assigned Route hostname
	// +optional
	RouteHost string `json:"routeHost,omitempty"`

	// NomadVersion is the agent version from /v1/agent/self; empty on
	// probe miss. Non-fatal — never gates other enrichment.
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

	// LastReconcileTime advances on status mutations and on the
	// heartbeat threshold — NOT every loop, which would amplify etcd
	// writes and fake GitOps drift. Liveness watchers see updates
	// roughly every 2m30s when idle.
	LastReconcileTime *metav1.Time `json:"lastReconcileTime,omitempty"`

	// InitialReconcileEventEmitted debounces the one-shot
	// InitialReconcileComplete Event across operator restarts.
	// +optional
	InitialReconcileEventEmitted bool `json:"initialReconcileEventEmitted,omitempty"`

	// Keyring reports the keyring set the operator has reconciled.
	// +optional
	Keyring *KeyringStatus `json:"keyring,omitempty"`

	// ScaleDown tracks an in-flight Raft scale-down; nil when none.
	// Drives crash-safe resume, the replicas-edit admission freeze,
	// and the in-progress metric.
	// +optional
	ScaleDown *ScaleDownStatus `json:"scaleDown,omitempty"`
}

// ScaleDownStatus tracks the in-flight Raft scale-down operation; the
// reconcile loop and the replicas-freeze admission rule both depend on
// its shape.
type ScaleDownStatus struct {
	// RemovedPeers lists Raft server IDs already removed this
	// operation; never re-removed, even across operator restarts.
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
// spec.replicas is frozen while a scale-down is in flight — an edit
// mid-operation would desynchronise the gap calculation from the
// removed-peers list. The degraded-quorum opt-in is enforced by
// ScaleDownPhase instead: CRD CEL cannot read metadata.annotations.
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
