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
	"fmt"
	"time"

	"github.com/go-logr/logr"
	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/internal/metrics"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
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

// TLSSecretName returns the operator-owned name of the server TLS
// Secret for a cluster: `<cluster>-tls`. Single definition (neo-08p) —
// the name is consumed by the certificate phase (writer), the
// StatefulSet mount, checksum inputs, and both controllers' Nomad
// client construction, which must all agree.
func TLSSecretName(clusterName string) string {
	return clusterName + "-tls"
}

// OperatorStatusName returns the shared deterministic name of the
// operator-status credential: the Nomad ACL policy, the token, and the
// Kubernetes Secret all use `<cluster>-operator-status` (ADR 0003).
func OperatorStatusName(clusterName string) string {
	return clusterName + "-operator-status"
}

// GossipSecretName returns the effective gossip key Secret name: the
// user-provided spec.gossip.secretName, else the operator-owned
// `<cluster>-gossip` default.
func GossipSecretName(cluster *nomadv1alpha1.NomadCluster) string {
	if cluster.Spec.Gossip.SecretName != "" {
		return cluster.Spec.Gossip.SecretName
	}
	return cluster.Name + "-gossip"
}

// SecretKeySecretID is the data key under which a Nomad ACL token's
// secret ID is stored in Kubernetes Secrets owned by this operator —
// the pair of SecretKeyAccessorID.
const SecretKeySecretID = "secret-id"

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
// ErrorWithReason returns an error result carrying a specific Ready
// reason (e.g. "LicenseSecretNotFound") instead of the generic
// PhaseFailed — for failures with a user-actionable cause (neo-0zq).
func ErrorWithReason(err error, reason, message string) PhaseResult {
	r := Error(err, message)
	r.Reason = reason
	return r
}

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

// Pod security (neo-8xu): both workload families (Nomad servers,
// snapshot agents) target the PSS "restricted" profile. The identity
// fields are conditional on platform: on OpenShift the SCC injects
// runAsUser/fsGroup from the namespace's allocated range and setting
// them explicitly would fight it; on vanilla Kubernetes the Nomad image
// has no USER directive, so runAsNonRoot needs an explicit non-root
// UID, and fsGroup makes the PVCs writable by it.
const nonRootUserID = int64(65532)

// ImageRef returns the Nomad container image reference for the
// cluster: `repository@digest` when a digest is pinned (neo-4xj,
// digest takes precedence), else `repository:tag`. Single definition —
// the StatefulSet and the snapshot-agent workloads must agree.
func ImageRef(cluster *nomadv1alpha1.NomadCluster) string {
	if cluster.Spec.Image.Digest != "" {
		return cluster.Spec.Image.Repository + "@" + cluster.Spec.Image.Digest
	}
	return cluster.Spec.Image.Repository + ":" + cluster.Spec.Image.Tag
}

// PodSecurityContext returns the PSS-restricted pod-level context.
func PodSecurityContext(openshift bool) *corev1.PodSecurityContext {
	sc := &corev1.PodSecurityContext{
		RunAsNonRoot: ptr.To(true),
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
	if !openshift {
		sc.RunAsUser = ptr.To(nonRootUserID)
		sc.RunAsGroup = ptr.To(nonRootUserID)
		sc.FSGroup = ptr.To(nonRootUserID)
	}
	return sc
}

// ContainerSecurityContext returns the PSS-restricted container-level
// context. Root filesystem stays read-only — writable paths are
// explicit mounts (data/audit PVCs, /tmp emptyDir).
func ContainerSecurityContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr.To(false),
		ReadOnlyRootFilesystem:   ptr.To(true),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
	}
}

// TimedExecute runs the phase and observes its wall-clock duration on
// the nomad_operator_phase_duration_seconds histogram (D4a / AC-8.1.1).
// The controller's phase loop calls this instead of Execute directly so
// every phase is measured, including failing ones.
func TimedExecute(ctx context.Context, phase Phase, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	start := time.Now()
	result := phase.Execute(ctx, cluster)
	metrics.PhaseDuration.WithLabelValues(cluster.Name, cluster.Namespace, phase.Name()).
		Observe(time.Since(start).Seconds())
	return result
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

	// License contains license information from Nomad API (populated by
	// ClusterStatusPhase). nil on probe miss — the controller preserves
	// the last-known status sub-field rather than clobbering it.
	License *nomadv1alpha1.LicenseStatus

	// Autopilot contains autopilot health from Nomad API (populated by
	// ClusterStatusPhase). nil on probe miss, same semantics as License.
	Autopilot *nomadv1alpha1.AutopilotStatus

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

// BuildClientConfig assembles a nomad.ClientConfig from the phase
// context. Since verify_https_client is off, only the CA cert is needed
// for TLS verification; callers set cfg.Address themselves.
func (pc *PhaseContext) BuildClientConfig(timeout time.Duration, token string) nomad.ClientConfig {
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
// The production path is instrumented with the D4b request counter;
// factory-injected clients (tests) are returned as-is.
func (pc *PhaseContext) NewNomadClient(cfg nomad.ClientConfig) (nomad.NomadAPI, error) {
	if pc.NomadClientFactory != nil {
		return pc.NomadClientFactory(cfg)
	}
	c, err := nomad.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return metrics.InstrumentNomadAPI(c), nil
}

// runNomadWithFallback builds a Nomad API client for the cluster's
// internal Service address and runs fn against it. If fn fails with a
// network error and a LoadBalancer address is known, the client is
// rebuilt for the LB address and fn re-run ONCE (neo-6al — the shared
// core of the previously hand-rolled per-site fallbacks). fn must be
// idempotent against the Nomad API; every caller is (policy upserts,
// reads, and token creation retried only when the first attempt never
// reached the server). Not used by executeBootstrap (bespoke per-address
// error guidance for the one-shot critical path), ClusterStatusPhase's
// createNomadClient (probe-and-keep shape), or the snapshot controller's
// best-effort cleanup (per-op log-and-continue semantics).
func (pc *PhaseContext) runNomadWithFallback(cluster *nomadv1alpha1.NomadCluster, timeout time.Duration, token string, fn func(nomad.NomadAPI) error) error {
	cfg := pc.BuildClientConfig(timeout, token)
	cfg.Address = nomad.InternalServiceAddress(cluster.Name, cluster.Namespace, true)
	nomadClient, err := pc.NewNomadClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Nomad client: %w", err)
	}

	err = fn(nomadClient)
	if err == nil || !nomad.IsNetworkError(err) {
		return err
	}

	loadBalancerAddress := nomad.LoadBalancerAddress(pc.AdvertiseAddress, true)
	if loadBalancerAddress == "" {
		return err
	}
	cfg.Address = loadBalancerAddress
	pc.Log.V(1).Info("Internal service not reachable, retrying via LoadBalancer", "address", loadBalancerAddress)
	nomadClient, cerr := pc.NewNomadClient(cfg)
	if cerr != nil {
		return fmt.Errorf("failed to create Nomad client for LoadBalancer: %w", cerr)
	}
	return fn(nomadClient)
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
