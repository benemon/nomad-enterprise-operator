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

// NomadAutoscalerSpec defines the desired state of NomadAutoscaler.
// The operator derives all Nomad connection material (address, CA,
// ACL token) from ClusterRef; scaling policies are not authored here —
// horizontal application scaling and Dynamic Application Sizing
// policies live in job specifications and flow through the agent's
// Nomad policy source.
// +kubebuilder:validation:XValidation:rule="!('*' in self.namespaces) || size(self.namespaces) == 1",message="namespaces: \"*\" must be the only entry when present"
type NomadAutoscalerSpec struct {
	// ClusterRef references the NomadCluster the autoscaler acts on
	ClusterRef ClusterReference `json:"clusterRef"`

	// Replicas is the number of agent pods. Values above 1 enable the
	// agent's high-availability mode: replicas form a leader-election
	// group over a Nomad Variables lock and only the leader evaluates
	// policies. The lock path is operator-owned and unique per
	// NomadAutoscaler, so distinct instances never share an election.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=3
	Replicas int32 `json:"replicas,omitempty"`

	// Image for the autoscaler agent. Dynamic Application Sizing
	// requires the enterprise image (the default).
	// +optional
	Image AutoscalerImageSpec `json:"image,omitempty"`

	// Namespaces are the Nomad namespaces the agent may observe and
	// scale. Drives both the agent configuration and the scope of the
	// ACL policy the operator mints. "*" grants all namespaces and
	// must be the only entry when present.
	// +kubebuilder:default={"default"}
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:Pattern=`^(\*|[A-Za-z0-9][A-Za-z0-9_-]*)$`
	Namespaces []string `json:"namespaces,omitempty"`

	// DynamicApplicationSizing configuration (Nomad Enterprise).
	// +optional
	DynamicApplicationSizing DynamicApplicationSizingSpec `json:"dynamicApplicationSizing,omitempty"`

	// Monitoring configuration for the agent's metrics endpoint
	// +optional
	Monitoring AutoscalerMonitoringSpec `json:"monitoring,omitempty"`

	// LogLevel for the agent
	// +kubebuilder:validation:Enum=DEBUG;INFO;WARN
	// +kubebuilder:default="INFO"
	LogLevel string `json:"logLevel,omitempty"`

	// EnableDebug exposes the agent's pprof endpoints
	// +kubebuilder:default=false
	EnableDebug bool `json:"enableDebug,omitempty"`

	// Resources defines CPU and memory for the agent
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// NodeSelector for agent pod scheduling
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations for agent pod scheduling
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// AutoscalerImageSpec defines the agent container image. A separate
// type from ImageSpec because the defaults differ and defaults are
// baked into the shared struct's markers.
type AutoscalerImageSpec struct {
	// Repository is the container image repository
	// +kubebuilder:default="hashicorp/nomad-autoscaler-enterprise"
	Repository string `json:"repository,omitempty"`

	// Tag is the container image tag, default-pinned to a concrete
	// version so a registry-side retag cannot change the running agent
	// mid-roll.
	// +kubebuilder:default="0.5.0-ent"
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9._-]+$`
	Tag string `json:"tag,omitempty"`

	// Digest optionally pins the image by content digest. When set, the
	// reference is `repository@digest` and Tag is ignored.
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	// +optional
	Digest string `json:"digest,omitempty"`

	// PullPolicy defaults to Always as a defence against registry-side
	// retags.
	// +kubebuilder:validation:Enum=Always;IfNotPresent;Never
	// +kubebuilder:default="Always"
	PullPolicy corev1.PullPolicy `json:"pullPolicy,omitempty"`
}

// DynamicApplicationSizingSpec opts the agent into Dynamic Application
// Sizing (Nomad Enterprise). Sizing policies live in job
// specifications, not here; enabling this extends the minted ACL
// policy with the recommendations capability.
type DynamicApplicationSizingSpec struct {
	// Enabled turns on Dynamic Application Sizing support
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`
}

// AutoscalerMonitoringSpec gates creation of monitoring resources for
// the agent metrics endpoint.
type AutoscalerMonitoringSpec struct {
	// Enabled determines if monitoring resources are created
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
func (m AutoscalerMonitoringSpec) IsEnabled() bool { return m.Enabled == nil || *m.Enabled }

// NomadAutoscalerStatus defines the observed state of NomadAutoscaler.
type NomadAutoscalerStatus struct {
	// Conditions represent the latest observations of the agent state
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the last observed generation
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// TokenAccessorID is the Nomad ACL token accessor ID for cleanup
	// +optional
	TokenAccessorID string `json:"tokenAccessorID,omitempty"`

	// PolicyName is the Nomad ACL policy created for the agent.
	// Stored here so it can be cleaned up when the NomadAutoscaler is
	// deleted.
	// +optional
	PolicyName string `json:"policyName,omitempty"`

	// DeploymentName is the name of the agent Deployment
	// +optional
	DeploymentName string `json:"deploymentName,omitempty"`

	// ConfigMapName is the name of the agent configuration ConfigMap
	// +optional
	ConfigMapName string `json:"configMapName,omitempty"`

	// NomadAddress is the internal Nomad cluster address used by the agent
	// +optional
	NomadAddress string `json:"nomadAddress,omitempty"`

	// ReadyReplicas is the number of ready agent replicas
	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// DesiredReplicas is the desired number of agent replicas
	// +optional
	DesiredReplicas int32 `json:"desiredReplicas,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=nas;autoscaler
// +kubebuilder:printcolumn:name="Cluster",type="string",JSONPath=".spec.clusterRef.name"
// +kubebuilder:printcolumn:name="Ready",type="integer",JSONPath=".status.readyReplicas"
// +kubebuilder:printcolumn:name="Desired",type="integer",JSONPath=".status.desiredReplicas"
// +kubebuilder:printcolumn:name="DAS",type="boolean",JSONPath=".spec.dynamicApplicationSizing.enabled"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// NomadAutoscaler is the Schema for the nomadautoscalers API.
type NomadAutoscaler struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NomadAutoscalerSpec   `json:"spec,omitempty"`
	Status NomadAutoscalerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NomadAutoscalerList contains a list of NomadAutoscaler.
type NomadAutoscalerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NomadAutoscaler `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NomadAutoscaler{}, &NomadAutoscalerList{})
}
