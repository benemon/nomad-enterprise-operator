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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

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
