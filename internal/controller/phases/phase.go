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

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/go-logr/logr"
	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/internal/metrics"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/hcl"
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

// TLSSecretName returns the server TLS Secret name, `<cluster>-tls`.
// Single definition: writer, mounts, checksums, and both controllers
// must agree.
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

	// Reason overrides the default Ready-condition reason
	// ("Reconciling" on requeue, "PhaseFailed" on error) when a phase
	// has a specific user-facing cause. Empty preserves the default.
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

// Both workload families target PSS "restricted". Identity fields are
// platform-conditional: OpenShift's SCC injects runAsUser/fsGroup and
// explicit values would fight it; vanilla needs them because the Nomad
// image has no USER directive.
const nonRootUserID = int64(65532)

// getManagementToken loads the operator management token, empty with
// no error when ACLs are disabled; a missing Secret defers the caller.
func getManagementToken(ctx context.Context, c client.Client, cluster *nomadv1alpha1.NomadCluster) (string, error) {
	if !cluster.Spec.Server.ACL.Enabled {
		return "", nil
	}
	secretName := OperatorManagementSecretName(cluster.Name)
	secret := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, secret); err != nil {
		return "", err
	}
	token := string(secret.Data[SecretKeySecretID])
	if token == "" {
		return "", fmt.Errorf("management token secret %q has no secret-id", secretName)
	}
	return token, nil
}

// statefulSetFullyRolled reports whether every pod runs the current
// pod template — the gate between config-changing lifecycle steps.
func statefulSetFullyRolled(ctx context.Context, c client.Client, cluster *nomadv1alpha1.NomadCluster) bool {
	sts := &appsv1.StatefulSet{}
	if err := c.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, sts); err != nil {
		return false
	}
	if sts.Generation != sts.Status.ObservedGeneration || sts.Spec.Replicas == nil {
		return false
	}
	replicas := *sts.Spec.Replicas
	return sts.Status.UpdatedReplicas == replicas &&
		sts.Status.ReadyReplicas == replicas &&
		sts.Status.CurrentRevision == sts.Status.UpdateRevision
}

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

	// Keyrings is the keyring render set, populated by KeyringPhase and
	// consumed by the ConfigMap and StatefulSet phases.
	Keyrings []hcl.KeyringBlock

	// KeyringEntries is the active+retiring entry union, populated by
	// KeyringPhase. Pod wiring (env, volumes, secrets checksum) derives
	// from this, NOT the spec: a retiring wrapper still needs its
	// credentials until its keys are removed.
	KeyringEntries []nomadv1alpha1.KeyringEntry

	// VaultLogin/VaultRenew override the Vault auth calls in tests.
	VaultLogin VaultLoginFunc
	VaultRenew VaultRenewFunc

	// RevisitAfter asks the controller to reconcile again after this
	// interval WITHOUT degrading status — a healthy-steady-state timer
	// (e.g. Vault token renewal), not a requeue. Zero means the
	// default heartbeat; the controller takes the minimum.
	RevisitAfter time.Duration

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
// context. Since verify_https_client is off, only the CA cert is needed to
// verify TLS; callers set cfg.Address themselves.
func (pc *PhaseContext) BuildClientConfig(timeout time.Duration, token string) nomad.ClientConfig {
	return nomad.ClientConfig{
		Token:      token,
		TLSEnabled: true,
		Timeout:    timeout,
		CACert:     pc.CACert,
	}
}

// NewNomadClient returns a NomadAPI from the factory when set (tests),
// else an instrumented production client.
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

// runNomadWithFallback runs fn against the internal Service address,
// retrying once via the LoadBalancer address on a network error.
// fn must be idempotent. Deliberately unused by executeBootstrap,
// createNomadClient, and best-effort cleanup, whose shapes differ.
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
