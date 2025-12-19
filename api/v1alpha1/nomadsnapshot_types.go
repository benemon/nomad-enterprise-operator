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

// NomadSnapshotSpec defines the desired state of NomadSnapshot.
// +kubebuilder:validation:XValidation:rule="has(self.target.s3) || has(self.target.gcs) || has(self.target.azure) || has(self.target.local)",message="one of target.s3, target.gcs, target.azure, or target.local must be specified"
type NomadSnapshotSpec struct {
	// ClusterRef references the NomadCluster to snapshot
	ClusterRef ClusterReference `json:"clusterRef"`

	// Schedule defines snapshot timing
	Schedule SnapshotSchedule `json:"schedule"`

	// Target defines where to store snapshots
	Target SnapshotTarget `json:"target"`

	// Resources defines CPU and memory for the snapshot agent
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// NodeSelector for snapshot agent pod scheduling
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations for snapshot agent pod scheduling
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// ClusterReference identifies the NomadCluster to snapshot.
type ClusterReference struct {
	// Name of the NomadCluster
	Name string `json:"name"`

	// Namespace of the NomadCluster (defaults to same namespace as NomadSnapshot)
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// SnapshotSchedule defines when and how often to take snapshots.
type SnapshotSchedule struct {
	// Interval between snapshots (e.g., "1h", "24h")
	// +kubebuilder:default="1h"
	Interval string `json:"interval,omitempty"`

	// Retain is the number of snapshots to keep
	// +kubebuilder:default=24
	// +kubebuilder:validation:Minimum=1
	Retain int `json:"retain,omitempty"`

	// Stale allows reading from non-leader for snapshots
	// +kubebuilder:default=false
	Stale bool `json:"stale,omitempty"`
}

// SnapshotTarget defines storage backend configuration.
type SnapshotTarget struct {
	// S3 configuration for AWS S3 or S3-compatible storage
	// +optional
	S3 *SnapshotS3Config `json:"s3,omitempty"`

	// GCS configuration for Google Cloud Storage
	// +optional
	GCS *SnapshotGCSConfig `json:"gcs,omitempty"`

	// Azure configuration for Azure Blob Storage
	// +optional
	Azure *SnapshotAzureConfig `json:"azure,omitempty"`

	// Local configuration for local/PVC storage
	// +optional
	Local *SnapshotLocalConfig `json:"local,omitempty"`
}

// SnapshotS3Config defines S3 storage configuration.
type SnapshotS3Config struct {
	// Bucket name
	Bucket string `json:"bucket"`

	// Region (e.g., "us-east-1")
	Region string `json:"region"`

	// Endpoint URL for S3-compatible storage (optional)
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// ForcePathStyle forces path-style URLs (required for some S3-compatible storage)
	// +kubebuilder:default=false
	ForcePathStyle bool `json:"forcePathStyle,omitempty"`

	// CredentialsSecretRef references a secret containing AWS credentials
	// Expected keys: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
	// If not specified, uses IAM role/IRSA
	// +optional
	CredentialsSecretRef *corev1.LocalObjectReference `json:"credentialsSecretRef,omitempty"`
}

// SnapshotGCSConfig defines Google Cloud Storage configuration.
type SnapshotGCSConfig struct {
	// Bucket name
	Bucket string `json:"bucket"`

	// CredentialsSecretRef references a secret containing GCP credentials
	// Expected key: GOOGLE_APPLICATION_CREDENTIALS (JSON service account key)
	// If not specified, uses workload identity
	// +optional
	CredentialsSecretRef *corev1.LocalObjectReference `json:"credentialsSecretRef,omitempty"`
}

// SnapshotAzureConfig defines Azure Blob Storage configuration.
type SnapshotAzureConfig struct {
	// Container name
	Container string `json:"container"`

	// AccountName is the Azure storage account name
	AccountName string `json:"accountName"`

	// CredentialsSecretRef references a secret containing Azure credentials
	// Expected key: AZURE_BLOB_ACCOUNT_KEY
	// +optional
	CredentialsSecretRef *corev1.LocalObjectReference `json:"credentialsSecretRef,omitempty"`
}

// SnapshotLocalConfig defines local/PVC storage configuration.
type SnapshotLocalConfig struct {
	// Path within the PVC to store snapshots
	// +kubebuilder:default="/snapshots"
	Path string `json:"path,omitempty"`

	// Size of the PVC to create (e.g., "10Gi")
	// +kubebuilder:default="10Gi"
	Size string `json:"size,omitempty"`

	// StorageClassName for the PVC (optional, uses cluster default if not specified)
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`
}

// NomadSnapshotStatus defines the observed state of NomadSnapshot.
type NomadSnapshotStatus struct {
	// Conditions represent the latest observations of the snapshot agent state
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// TokenAccessorID is the Nomad ACL token accessor ID for cleanup
	// +optional
	TokenAccessorID string `json:"tokenAccessorID,omitempty"`

	// LastSnapshot contains information about the most recent snapshot
	// +optional
	LastSnapshot *SnapshotInfo `json:"lastSnapshot,omitempty"`

	// NextScheduled is when the next snapshot is expected
	// +optional
	NextScheduled *metav1.Time `json:"nextScheduled,omitempty"`

	// SnapshotCount is the total number of snapshots stored
	// +optional
	SnapshotCount int `json:"snapshotCount,omitempty"`

	// ObservedGeneration is the last observed generation
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// DeploymentName is the name of the snapshot agent deployment
	// +optional
	DeploymentName string `json:"deploymentName,omitempty"`

	// ConfigMapName is the name of the snapshot agent configuration ConfigMap
	// +optional
	ConfigMapName string `json:"configMapName,omitempty"`

	// NomadAddress is the internal Nomad cluster address used by the snapshot agent
	// +optional
	NomadAddress string `json:"nomadAddress,omitempty"`

	// ReadyReplicas is the number of ready snapshot agent replicas
	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// DesiredReplicas is the desired number of snapshot agent replicas
	// +optional
	DesiredReplicas int32 `json:"desiredReplicas,omitempty"`
}

// SnapshotInfo contains details about a snapshot.
type SnapshotInfo struct {
	// Time when the snapshot was taken
	Time *metav1.Time `json:"time,omitempty"`

	// Status of the snapshot (Success, Failed)
	Status string `json:"status,omitempty"`

	// Size of the snapshot
	// +optional
	Size string `json:"size,omitempty"`

	// Location is the storage path/URL of the snapshot
	// +optional
	Location string `json:"location,omitempty"`

	// Error message if snapshot failed
	// +optional
	Error string `json:"error,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ns;snapshot
// +kubebuilder:printcolumn:name="Cluster",type="string",JSONPath=".spec.clusterRef.name"
// +kubebuilder:printcolumn:name="Interval",type="string",JSONPath=".spec.schedule.interval"
// +kubebuilder:printcolumn:name="Retain",type="integer",JSONPath=".spec.schedule.retain"
// +kubebuilder:printcolumn:name="Last Snapshot",type="date",JSONPath=".status.lastSnapshot.time"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// NomadSnapshot is the Schema for the nomadsnapshots API.
type NomadSnapshot struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NomadSnapshotSpec   `json:"spec,omitempty"`
	Status NomadSnapshotStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NomadSnapshotList contains a list of NomadSnapshot.
type NomadSnapshotList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NomadSnapshot `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NomadSnapshot{}, &NomadSnapshotList{})
}
