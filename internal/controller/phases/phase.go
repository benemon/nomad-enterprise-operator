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

// Package phases provides the reconciliation phase framework for the NomadCluster controller.
package phases

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Operator-owned Secret key names and naming conventions per ADR 0003
// ("Fields dropped in v1"). These were previously user-configurable spec
// fields; one convention is supported forever instead.
const (
	// licenseSecretKey is the key holding the Nomad Enterprise license
	// in the license Secret.
	licenseSecretKey = "license"

	// gossipSecretKey is the key holding the gossip encryption key in
	// the gossip Secret.
	gossipSecretKey = "gossip-key"
)

// BootstrapSecretName returns the operator-owned name of the ACL
// bootstrap token Secret for a cluster: `<cluster>-acl-bootstrap`
// (ADR 0003 — previously spec.server.acl.bootstrapSecretName).
func BootstrapSecretName(clusterName string) string {
	return clusterName + "-acl-bootstrap"
}

// PhaseResult represents the outcome of a phase execution.
type PhaseResult struct {
	// Requeue indicates if reconciliation should be requeued.
	Requeue bool

	// RequeueAfter specifies delay before requeue.
	RequeueAfter time.Duration

	// Error holds the error if phase failed.
	Error error

	// Message is the message for status update.
	Message string

	// Reason overrides the default "Reconciling" reason on the Ready
	// condition the controller sets when this phase requests requeue.
	// Used by phases that need a specific reason surfaced on the CR
	// (e.g. ScaleDownPhase's AC-2.3.8 "ScaleDownBlocked"). Empty
	// preserves the default.
	Reason string
}

// OK returns a successful result.
func OK() PhaseResult {
	return PhaseResult{}
}

// Requeue returns a result that triggers requeue after specified duration.
func Requeue(after time.Duration, message string) PhaseResult {
	return PhaseResult{
		Requeue:      true,
		RequeueAfter: after,
		Message:      message,
	}
}

// RequeueWithReason returns a requeue result carrying a specific
// Ready-condition reason. Used by phases that need the user-facing
// condition to name the deferral cause (D2d / AC-2.3.8).
func RequeueWithReason(after time.Duration, reason, message string) PhaseResult {
	return PhaseResult{
		Requeue:      true,
		RequeueAfter: after,
		Reason:       reason,
		Message:      message,
	}
}

// Error returns a failed result.
func Error(err error, message string) PhaseResult {
	return PhaseResult{
		Error:   err,
		Message: message,
	}
}

// Phase represents a reconciliation phase.
type Phase interface {
	// Name returns the phase name for logging/status.
	Name() string

	// Execute performs the phase reconciliation.
	Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult
}

// PhaseContext provides shared context for phases.
type PhaseContext struct {
	Client     client.Client
	Scheme     *runtime.Scheme
	Log        logr.Logger
	RESTConfig *rest.Config

	// Recorder emits Kubernetes Events on the NomadCluster from phases
	// (e.g. RouteCRDMissing). May be nil in tests; guard before use.
	Recorder record.EventRecorder

	// NomadClientFactory builds Nomad API clients used by phases that call the
	// Nomad API. Defaults to nomad.NewClient when nil. Tests inject a factory
	// that returns a mock NomadAPI to avoid real HTTP calls.
	NomadClientFactory func(cfg nomad.ClientConfig) (nomad.NomadAPI, error)

	// AdvertiseAddress is the cached advertise address resolved during reconciliation.
	AdvertiseAddress string
	// GossipKey is the cached gossip key resolved during reconciliation.
	GossipKey string

	// LeaderAddress is the cluster leader address from Nomad API (populated by ClusterStatusPhase).
	LeaderAddress string
	// ClusterHealthy indicates cluster health from Nomad API (populated by ClusterStatusPhase).
	ClusterHealthy bool
	// PeerCount is the number of peers from Nomad API (populated by ClusterStatusPhase).
	PeerCount int

	// License contains license information from Nomad API (populated by ClusterStatusPhase).
	License *nomadv1alpha1.LicenseStatus
	// LicenseError contains any error from fetching license info.
	LicenseError error

	// Autopilot contains autopilot health from Nomad API (populated by ClusterStatusPhase).
	Autopilot *nomadv1alpha1.AutopilotStatus
	// AutopilotError contains any error from fetching autopilot info.
	AutopilotError error

	// NomadVersion is the agent-reported version from /v1/agent/self
	// (populated by ClusterStatusPhase via C7 probe). Empty when the
	// probe failed or has not yet run.
	NomadVersion string

	// CACert is the PEM-encoded CA certificate, populated by CertificatePhase.
	// Used by RoutePhase for destinationCACertificate and by BuildClientConfig.
	CACert []byte
}

// NewPhaseContext creates a new phase context.
func NewPhaseContext(k8sClient client.Client, scheme *runtime.Scheme, log logr.Logger, restConfig *rest.Config) *PhaseContext {
	return &PhaseContext{
		Client:     k8sClient,
		Scheme:     scheme,
		Log:        log,
		RESTConfig: restConfig,
	}
}

// GetLabels returns common labels for all resources.
func GetLabels(cluster *nomadv1alpha1.NomadCluster) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "nomad",
		"app.kubernetes.io/instance":   cluster.Name,
		"app.kubernetes.io/managed-by": "nomad-operator",
		"app.kubernetes.io/component":  "server",
	}
}

// GetSelectorLabels returns labels used for pod selection.
func GetSelectorLabels(cluster *nomadv1alpha1.NomadCluster) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "nomad",
		"app.kubernetes.io/instance": cluster.Name,
		"app":                        "nomad",
		"component":                  "server",
	}
}

// BuildClientConfig assembles a nomad.ClientConfig for the given cluster.
// Since verify_https_client is off, only the CA cert is needed for TLS verification.
func (pc *PhaseContext) BuildClientConfig(cluster *nomadv1alpha1.NomadCluster, timeout time.Duration, token string) nomad.ClientConfig {
	return nomad.ClientConfig{
		Token:      token,
		TLSEnabled: true,
		Timeout:    timeout,
		CACert:     pc.CACert,
	}
}

// NewNomadClient constructs a Nomad API client using PhaseContext.NomadClientFactory
// if set, falling back to nomad.NewClient. The return type is the NomadAPI
// interface so phases depend on the interface rather than the concrete *Client.
func (pc *PhaseContext) NewNomadClient(cfg nomad.ClientConfig) (nomad.NomadAPI, error) {
	if pc.NomadClientFactory != nil {
		return pc.NomadClientFactory(cfg)
	}
	return nomad.NewClient(cfg)
}

// CheckPodsReady returns true if at least one pod matching the cluster's selector labels is ready.
func (pc *PhaseContext) CheckPodsReady(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (bool, error) {
	podList := &corev1.PodList{}
	if err := pc.Client.List(ctx, podList,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(GetSelectorLabels(cluster)),
	); err != nil {
		return false, err
	}

	for _, pod := range podList.Items {
		if pod.Status.Phase == corev1.PodRunning {
			for _, cond := range pod.Status.Conditions {
				if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
					return true, nil
				}
			}
		}
	}

	return false, nil
}
