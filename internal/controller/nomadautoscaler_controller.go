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

package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/internal/controller/phases"
	"github.com/hashicorp/nomad-enterprise-operator/internal/discovery"
	"github.com/hashicorp/nomad-enterprise-operator/internal/metrics"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
)

const (
	autoscalerFinalizer      = "nomad.hashicorp.com/autoscaler-cleanup"
	autoscalerRequeueDefault = 30 * time.Second

	// autoscalerDegradedGrace is how long the agent Deployment may sit
	// below its desired replica count before Degraded=True: long enough
	// for an image pull and start, short enough to page before a whole
	// HA window is lost.
	autoscalerDegradedGrace = 2 * time.Minute

	// autoscalerLockNamespace is the Nomad namespace holding the HA
	// lock variable. Constant so every replica of an instance lands in
	// the same election group.
	autoscalerLockNamespace = "default"
)

// autoscalerServiceMonitorGVK gates ServiceMonitor creation on CRD
// presence, mirroring the cluster monitoring phase.
var autoscalerServiceMonitorGVK = schema.GroupVersionKind{
	Group:   "monitoring.coreos.com",
	Version: "v1",
	Kind:    "ServiceMonitor",
}

// NomadAutoscalerReconciler reconciles a NomadAutoscaler object.
// Ensure idiom: controllerutil.CreateOrUpdate, matching the snapshot
// controller.
type NomadAutoscalerReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// NomadClientFactory overrides Nomad API client construction for
	// tests (same shape as the other reconcilers). nil in production.
	NomadClientFactory func(cfg nomad.ClientConfig) (nomad.NomadAPI, error)
}

// Deterministic names of the resources a NomadAutoscaler owns: each is
// built in one place so construction sites and status-write sites
// cannot disagree.
func autoscalerAgentName(a *nomadv1alpha1.NomadAutoscaler) string {
	return a.Name + "-autoscaler-agent"
}
func autoscalerConfigMapName(a *nomadv1alpha1.NomadAutoscaler) string {
	return a.Name + "-autoscaler-config"
}
func autoscalerTokenName(a *nomadv1alpha1.NomadAutoscaler) string {
	return a.Name + "-autoscaler-token"
}
func autoscalerServiceName(a *nomadv1alpha1.NomadAutoscaler) string {
	return a.Name + "-autoscaler-metrics"
}
func autoscalerPDBName(a *nomadv1alpha1.NomadAutoscaler) string { return a.Name + "-autoscaler" }

// autoscalerLockPath is the per-instance Nomad Variables path for HA
// leader election. Unique per CR so two instances against the same
// cluster never share an election (the agent default is a fixed global
// path — inheriting it would silently merge elections).
func autoscalerLockPath(a *nomadv1alpha1.NomadAutoscaler) string {
	return fmt.Sprintf("nomad-autoscaler/%s/%s/lock", a.Namespace, a.Name)
}

// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadautoscalers,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadautoscalers/status,verbs=patch
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadautoscalers/finalizers,verbs=update
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;delete

// Reconcile handles NomadAutoscaler reconciliation.
//
// Status-write contract: every helper mutating autoscaler.Status issues
// its own Status().Patch with a patchBase snapshotted just before the
// mutation — the final patch is NOT a catch-all for earlier writes.
func (r *NomadAutoscalerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	autoscaler := &nomadv1alpha1.NomadAutoscaler{}
	if err := r.Get(ctx, req.NamespacedName, autoscaler); err != nil {
		if k8serrors.IsNotFound(err) {
			log.Info("NomadAutoscaler resource not found, ignoring")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get NomadAutoscaler")
		return ctrl.Result{}, err
	}

	if !autoscaler.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, autoscaler)
	}

	if !controllerutil.ContainsFinalizer(autoscaler, autoscalerFinalizer) {
		controllerutil.AddFinalizer(autoscaler, autoscalerFinalizer)
		if err := r.Update(ctx, autoscaler); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	// clusterRef is same-namespace by admission contract (CEL rejects
	// clusterRef.namespace).
	cluster := &nomadv1alpha1.NomadCluster{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      autoscaler.Spec.ClusterRef.Name,
		Namespace: autoscaler.Namespace,
	}, cluster); err != nil {
		if k8serrors.IsNotFound(err) {
			log.Error(err, "Referenced NomadCluster not found", "cluster", autoscaler.Spec.ClusterRef.Name)
			patchBase := autoscaler.DeepCopy()
			r.setCondition(autoscaler, metav1.Condition{
				Type:    "Ready",
				Status:  metav1.ConditionFalse,
				Reason:  "ClusterNotFound",
				Message: fmt.Sprintf("Referenced NomadCluster %s not found", autoscaler.Spec.ClusterRef.Name),
			})
			if err := r.Status().Patch(ctx, autoscaler, client.MergeFrom(patchBase)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: autoscalerRequeueDefault}, nil
		}
		return ctrl.Result{}, err
	}

	// The autoscaler requires ACLs (management token, minted policy and
	// token): a cluster with ACLs disabled is a terminal
	// misconfiguration, not a transient wait — without this gate the CR
	// would sit at WaitingForACLBootstrap forever, since ACL-disabled
	// clusters never set ACLBootstrapped.
	if !cluster.Spec.Server.ACL.IsEnabled() {
		log.Info("Referenced NomadCluster has ACLs disabled", "cluster", cluster.Name)
		patchBase := autoscaler.DeepCopy()
		prevReady := meta.FindStatusCondition(autoscaler.Status.Conditions, "Ready")
		alreadyReported := prevReady != nil && prevReady.Reason == "ACLsDisabled"
		r.setCondition(autoscaler, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "ACLsDisabled",
			Message: fmt.Sprintf("NomadCluster %s has ACLs disabled; the autoscaler requires an ACL-enabled cluster", cluster.Name),
		})
		if !alreadyReported && r.Recorder != nil {
			r.Recorder.Event(autoscaler, corev1.EventTypeWarning, "ACLsDisabled",
				fmt.Sprintf("NomadCluster %s has ACLs disabled; the autoscaler requires an ACL-enabled cluster", cluster.Name))
		}
		if err := r.Status().Patch(ctx, autoscaler, client.MergeFrom(patchBase)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: autoscalerRequeueDefault}, nil
	}

	if !cluster.Status.ACLBootstrapped {
		log.Info("Waiting for NomadCluster ACL bootstrap", "cluster", cluster.Name)
		patchBase := autoscaler.DeepCopy()
		r.setCondition(autoscaler, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "WaitingForACLBootstrap",
			Message: "Waiting for NomadCluster ACL bootstrap to complete",
		})
		if err := r.Status().Patch(ctx, autoscaler, client.MergeFrom(patchBase)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: autoscalerRequeueDefault}, nil
	}

	managementSecretName := phases.OperatorManagementSecretName(cluster.Name)
	managementSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      managementSecretName,
		Namespace: cluster.Namespace,
	}, managementSecret); err != nil {
		log.Info("Waiting for cluster management token secret", "secret", managementSecretName)
		patchBase := autoscaler.DeepCopy()
		r.setCondition(autoscaler, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "WaitingForManagementToken",
			Message: fmt.Sprintf("Waiting for cluster management token secret %s", managementSecretName),
		})
		if err := r.Status().Patch(ctx, autoscaler, client.MergeFrom(patchBase)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: autoscalerRequeueDefault}, nil
	}

	managementToken := string(managementSecret.Data[phases.SecretKeySecretID])
	if managementToken == "" {
		log.Info("Management token secret has no secret-id", "secret", managementSecretName)
		patchBase := autoscaler.DeepCopy()
		r.setCondition(autoscaler, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "WaitingForManagementToken",
			Message: fmt.Sprintf("Management token secret %s has an empty secret-id", managementSecretName),
		})
		if err := r.Status().Patch(ctx, autoscaler, client.MergeFrom(patchBase)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: autoscalerRequeueDefault}, nil
	}

	internalAddr := nomad.InternalServiceAddress(cluster.Name, cluster.Namespace, true)

	agentToken, err := r.ensureAutoscalerToken(ctx, autoscaler, cluster, managementToken)
	if err != nil {
		log.Error(err, "Failed to ensure autoscaler agent token")
		patchBase := autoscaler.DeepCopy()
		// Warning Event once per transition into the failed state, not
		// per retry — the 30s requeue would flood the Event stream.
		prevReady := meta.FindStatusCondition(autoscaler.Status.Conditions, "Ready")
		alreadyFailed := prevReady != nil && prevReady.Reason == "TokenCreationFailed"
		r.setCondition(autoscaler, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "TokenCreationFailed",
			Message: fmt.Sprintf("Failed to create autoscaler agent token: %v", err),
		})
		if !alreadyFailed && r.Recorder != nil {
			r.Recorder.Event(autoscaler, corev1.EventTypeWarning, "TokenCreationFailed",
				fmt.Sprintf("Failed to create autoscaler agent token: %v", err))
		}
		if err := r.Status().Patch(ctx, autoscaler, client.MergeFrom(patchBase)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: autoscalerRequeueDefault}, nil
	}

	if err := r.reconcileTokenSecret(ctx, autoscaler, agentToken); err != nil {
		log.Error(err, "Failed to reconcile token secret")
		return ctrl.Result{}, err
	}

	agentConfig := generateAutoscalerConfig(autoscaler, internalAddr)
	configChecksum := phases.ConfigChecksum(map[string]string{"autoscaler.hcl": agentConfig})
	// A token re-mint rewrites the Secret in place while the pod spec
	// stays byte-identical, and env-injected Secrets are never re-read
	// by running pods: hash the token into the template so a re-mint
	// rolls the agents (the cluster StatefulSet's checksum/secrets
	// pattern).
	secretsChecksum := phases.ConfigChecksum(map[string]string{phases.SecretKeySecretID: agentToken})

	if err := r.reconcileConfigMap(ctx, autoscaler, agentConfig); err != nil {
		log.Error(err, "Failed to reconcile ConfigMap")
		return ctrl.Result{}, err
	}

	if err := r.reconcileDeployment(ctx, autoscaler, cluster, configChecksum, secretsChecksum); err != nil {
		log.Error(err, "Failed to reconcile Deployment")
		return ctrl.Result{}, err
	}

	if err := r.reconcilePDB(ctx, autoscaler); err != nil {
		log.Error(err, "Failed to reconcile PodDisruptionBudget")
		return ctrl.Result{}, err
	}

	if err := r.reconcileMonitoring(ctx, autoscaler); err != nil {
		log.Error(err, "Failed to reconcile monitoring resources")
		return ctrl.Result{}, err
	}

	return r.updateAgentStatus(ctx, autoscaler, internalAddr)
}

// updateAgentStatus observes the agent Deployment and writes the
// status block: resource names, replica counts, the Ready condition,
// and the Degraded condition with its once-per-transition Warning.
func (r *NomadAutoscalerReconciler) updateAgentStatus(
	ctx context.Context, autoscaler *nomadv1alpha1.NomadAutoscaler, internalAddr string,
) (ctrl.Result, error) {
	deploymentName := autoscalerAgentName(autoscaler)

	patchBase := autoscaler.DeepCopy()
	autoscaler.Status.ObservedGeneration = autoscaler.Generation
	autoscaler.Status.DeploymentName = deploymentName
	autoscaler.Status.ConfigMapName = autoscalerConfigMapName(autoscaler)
	autoscaler.Status.NomadAddress = internalAddr

	deploy := &appsv1.Deployment{}
	deployFound := r.Get(ctx, types.NamespacedName{Name: deploymentName, Namespace: autoscaler.Namespace}, deploy) == nil
	if deployFound {
		autoscaler.Status.DesiredReplicas = ptr.Deref(deploy.Spec.Replicas, 1)
		autoscaler.Status.ReadyReplicas = deploy.Status.ReadyReplicas
	}

	if autoscaler.Status.ReadyReplicas > 0 {
		r.setCondition(autoscaler, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionTrue,
			Reason:  "Deployed",
			Message: "Autoscaler agent deployment is running",
		})
	} else {
		r.setCondition(autoscaler, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "DeploymentNotReady",
			Message: "Autoscaler agent deployment is not yet ready",
		})
	}

	// Degraded tracks agent health beyond the Ready snapshot: replica
	// loss that outlasts the grace window, or a rollout the Deployment
	// controller has given up on (surge keeps the old ReplicaSet — and
	// Ready=True — while the new template never becomes available).
	// Warning Event once per transition, same as the snapshot controller.
	requeueAfter := 5 * time.Minute
	wasDegraded := meta.IsStatusConditionTrue(autoscaler.Status.Conditions, "Degraded")
	degradedReason, degradedMessage := "", ""
	// A stuck rollout is evaluated first: it degrades regardless of the
	// replica-count grace window. Were the order reversed, a replica
	// loss during a stuck rollout would reset Available's transition
	// time, land in the grace window, and CLEAR Degraded while the
	// incident worsened — then re-fire a duplicate Warning.
	switch {
	case deployFound && deploymentRolloutStuck(deploy):
		degradedReason = "RolloutStuck"
		degradedMessage = "Agent Deployment rollout exceeded its progress deadline; new pods are not becoming ready"
	case deployFound && autoscaler.Status.ReadyReplicas < autoscaler.Status.DesiredReplicas:
		if since, ok := deploymentUnavailableSince(deploy); ok {
			if elapsed := time.Since(since.Time); elapsed >= autoscalerDegradedGrace {
				degradedReason = "AgentUnavailable"
				degradedMessage = fmt.Sprintf("%d/%d agent replicas ready for over %s",
					autoscaler.Status.ReadyReplicas, autoscaler.Status.DesiredReplicas, autoscalerDegradedGrace)
			} else if remaining := autoscalerDegradedGrace - elapsed + time.Second; remaining < requeueAfter {
				// A stalled Deployment emits no watch events; requeue
				// to fire the transition when the grace window lapses.
				requeueAfter = remaining
			}
		}
	}
	if degradedReason != "" {
		r.setDegraded(autoscaler, true, degradedReason, degradedMessage)
		if !wasDegraded && r.Recorder != nil {
			r.Recorder.Event(autoscaler, corev1.EventTypeWarning, "AutoscalerDegraded", degradedMessage)
		}
	} else {
		r.setDegraded(autoscaler, false, "AgentHealthy", "")
	}

	if err := r.Status().Patch(ctx, autoscaler, client.MergeFrom(patchBase)); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// deploymentUnavailableSince returns when the Deployment lost minimum
// availability. With maxUnavailable=0 that is exactly "readyReplicas
// dropped below desired", so it anchors the Degraded grace window.
func deploymentUnavailableSince(deploy *appsv1.Deployment) (metav1.Time, bool) {
	for _, c := range deploy.Status.Conditions {
		if c.Type == appsv1.DeploymentAvailable && c.Status == corev1.ConditionFalse {
			return c.LastTransitionTime, true
		}
	}
	return metav1.Time{}, false
}

// deploymentRolloutStuck reports whether the Deployment controller has
// declared the current rollout failed (progress deadline exceeded).
func deploymentRolloutStuck(deploy *appsv1.Deployment) bool {
	for _, c := range deploy.Status.Conditions {
		if c.Type == appsv1.DeploymentProgressing && c.Status == corev1.ConditionFalse {
			return true
		}
	}
	return false
}

// setDegraded maintains the Degraded condition, mirroring the snapshot
// controller's pattern.
func (r *NomadAutoscalerReconciler) setDegraded(autoscaler *nomadv1alpha1.NomadAutoscaler, degraded bool, reason, message string) {
	status := metav1.ConditionFalse
	if degraded {
		status = metav1.ConditionTrue
	}
	if message == "" {
		message = "Autoscaler agent is healthy"
	}
	r.setCondition(autoscaler, metav1.Condition{
		Type:    "Degraded",
		Status:  status,
		Reason:  reason,
		Message: message,
	})
}

func (r *NomadAutoscalerReconciler) handleDeletion(ctx context.Context, autoscaler *nomadv1alpha1.NomadAutoscaler) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if controllerutil.ContainsFinalizer(autoscaler, autoscalerFinalizer) {
		if autoscaler.Status.TokenAccessorID != "" || autoscaler.Status.PolicyName != "" {
			if err := r.cleanupNomadResources(ctx, autoscaler); err != nil {
				log.Error(err, "Failed to clean up Nomad ACL resources, continuing with deletion")
			}
		}

		controllerutil.RemoveFinalizer(autoscaler, autoscalerFinalizer)
		if err := r.Update(ctx, autoscaler); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// runNomadWithFallback mirrors the snapshot controller's helper:
// internal Service first, one LB retry on network error. fn must be
// idempotent.
func (r *NomadAutoscalerReconciler) runNomadWithFallback(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, fn func(nomad.NomadAPI) error) error {
	nomadClient, err := r.autoscalerNomadClient(ctx, cluster,
		nomad.InternalServiceAddress(cluster.Name, cluster.Namespace, true))
	if err != nil {
		return err
	}

	err = fn(nomadClient)
	if err == nil || !nomad.IsNetworkError(err) {
		return err
	}

	loadBalancerAddr := nomad.LoadBalancerAddress(cluster.Status.AdvertiseAddress, true)
	if loadBalancerAddr == "" {
		return err
	}
	nomadClient, cerr := r.autoscalerNomadClient(ctx, cluster, loadBalancerAddr)
	if cerr != nil {
		return cerr
	}
	return fn(nomadClient)
}

// autoscalerNomadClient creates a Nomad client for controller-side ACL
// operations. verify_https_client is off, so only the CA is needed.
func (r *NomadAutoscalerReconciler) autoscalerNomadClient(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, address string) (nomad.NomadAPI, error) {
	cfg := nomad.ClientConfig{
		Address:    address,
		TLSEnabled: true,
	}

	tlsSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      phases.TLSSecretName(cluster.Name),
		Namespace: cluster.Namespace,
	}, tlsSecret); err != nil {
		return nil, fmt.Errorf("failed to get TLS secret: %w", err)
	}
	cfg.CACert = tlsSecret.Data["ca.crt"]

	if r.NomadClientFactory != nil {
		return r.NomadClientFactory(cfg)
	}
	c, err := nomad.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return metrics.InstrumentNomadAPI(c), nil
}

// buildAutoscalerPolicyRules renders the agent's ACL policy from the
// spec: scale on each granted namespace, node read (per the documented
// autoscaler policy), the recommendations capability when Dynamic
// Application Sizing is enabled, and write on the per-instance HA lock
// variable when replicas > 1.
func buildAutoscalerPolicyRules(a *nomadv1alpha1.NomadAutoscaler) string {
	var b strings.Builder

	dasCaps := ""
	if a.Spec.DynamicApplicationSizing.Enabled {
		dasCaps = `
  capabilities = ["submit-recommendation"]`
	}

	lockInGrantedNamespace := false
	for _, ns := range a.Spec.Namespaces {
		fmt.Fprintf(&b, `namespace %q {
  policy = "scale"%s
`, ns, dasCaps)
		if a.Spec.Replicas > 1 && ns == autoscalerLockNamespace {
			lockInGrantedNamespace = true
			fmt.Fprintf(&b, `  variables {
    path %q {
      capabilities = ["write", "read", "list"]
    }
  }
`, autoscalerLockPath(a))
		}
		b.WriteString("}\n\n")
	}

	// HA lock lives in a fixed namespace; grant it separately when that
	// namespace is not already in the list. Nomad resolves an exact
	// namespace block over a glob WITHOUT merging, so when the list is
	// the wildcard this exact block must repeat the full scale grant —
	// a bare variables block would strip scale from the lock namespace.
	if a.Spec.Replicas > 1 && !lockInGrantedNamespace {
		scaleGrant := ""
		if len(a.Spec.Namespaces) == 1 && a.Spec.Namespaces[0] == "*" {
			scaleGrant = `  policy = "scale"` + dasCaps + "\n"
		}
		fmt.Fprintf(&b, `namespace %q {
%s  variables {
    path %q {
      capabilities = ["write", "read", "list"]
    }
  }
}

`, autoscalerLockNamespace, scaleGrant, autoscalerLockPath(a))
	}

	b.WriteString(`node {
  policy = "read"
}
`)

	// The enterprise agent (the default image) validates enterprise
	// features against the cluster license at startup even when DAS is
	// disabled; without operator read the check gets a 403 and
	// enterprise initialization — including HA mode — fails (observed
	// on the lab cluster with DAS on, neo-csu, and in e2e with DAS
	// off, neo-2um.2).
	b.WriteString(`
operator {
  policy = "read"
}
`)

	return b.String()
}

// ensureAutoscalerToken creates or retrieves the agent's dedicated ACL
// token: reuse the recorded accessor if it still resolves, else upsert
// the policy and mint a fresh token.
func (r *NomadAutoscalerReconciler) ensureAutoscalerToken(
	ctx context.Context, autoscaler *nomadv1alpha1.NomadAutoscaler,
	cluster *nomadv1alpha1.NomadCluster, authToken string,
) (string, error) {
	log := logf.FromContext(ctx)

	policyName := fmt.Sprintf("autoscaler-agent-%s-%s", autoscaler.Namespace, autoscaler.Name)
	policyRules := buildAutoscalerPolicyRules(autoscaler)

	// The policy rules derive from spec (namespaces, DAS, replicas), and
	// the upsert is a Nomad raft write: run it only when the spec
	// changed or a token is about to be minted, not on every pass.
	// Tradeoff: an out-of-band policy edit in Nomad persists until the
	// next spec change or re-mint instead of self-healing on requeue.
	specChanged := autoscaler.Generation != autoscaler.Status.ObservedGeneration
	upsertPolicy := func(nomadClient nomad.NomadAPI) error {
		if perr := nomadClient.CreateACLPolicy(authToken, policyName, "Autoscaler agent policy for "+autoscaler.Name, policyRules); perr != nil {
			return fmt.Errorf("failed to create autoscaler agent policy: %w", perr)
		}
		return nil
	}

	var existingSecretID string
	needMint := false
	err := r.runNomadWithFallback(ctx, cluster, func(nomadClient nomad.NomadAPI) error {
		if specChanged {
			if perr := upsertPolicy(nomadClient); perr != nil {
				return perr
			}
		}

		if autoscaler.Status.TokenAccessorID != "" {
			token, terr := nomadClient.GetACLToken(authToken, autoscaler.Status.TokenAccessorID)
			if terr != nil {
				return terr
			}
			if token != nil {
				existingSecretID = token.SecretID
				return nil
			}
			log.Info("Existing token not found, creating new one", "accessor", autoscaler.Status.TokenAccessorID)
		}

		// About to mint at steady state (out-of-band token deletion):
		// the policy may have drifted or vanished too, so upsert it
		// before the token references it.
		if !specChanged {
			if perr := upsertPolicy(nomadClient); perr != nil {
				return perr
			}
		}
		needMint = true
		return nil
	})
	if err != nil {
		return "", err
	}
	if !needMint {
		log.V(1).Info("Using existing autoscaler agent token", "accessor", autoscaler.Status.TokenAccessorID)
		return existingSecretID, nil
	}

	// The mint runs OUTSIDE the retried helper, one attempt against one
	// address: token creation is not idempotent, and a retry after a
	// lost response would mint a second, permanently orphaned token.
	nomadClient, err := r.autoscalerNomadClient(ctx, cluster,
		nomad.InternalServiceAddress(cluster.Name, cluster.Namespace, true))
	if err != nil {
		return "", err
	}
	newToken, err := nomadClient.CreateACLTokenWithPolicies(authToken, policyName, []string{policyName})
	if err != nil {
		return "", fmt.Errorf("failed to create autoscaler agent token: %w", err)
	}

	log.Info("Created autoscaler agent token", "accessor", newToken.AccessorID, "policy", policyName)

	patchBase := autoscaler.DeepCopy()
	autoscaler.Status.TokenAccessorID = newToken.AccessorID
	autoscaler.Status.PolicyName = policyName
	if err := r.Status().Patch(ctx, autoscaler, client.MergeFrom(patchBase)); err != nil {
		// An unrecorded live token would leak a fresh orphan on every
		// retry of this failure: best-effort delete before surfacing.
		if derr := nomadClient.DeleteACLToken(authToken, newToken.AccessorID); derr != nil {
			log.Error(derr, "Failed to delete unrecorded autoscaler token after status patch failure",
				"accessor", newToken.AccessorID)
		}
		return "", fmt.Errorf("failed to patch status with token accessor: %w", err)
	}

	return newToken.SecretID, nil
}

// cleanupNomadResources deletes the agent's ACL token and policy from
// Nomad. Mirrors the snapshot controller's deletion-time auth fallback.
func (r *NomadAutoscalerReconciler) cleanupNomadResources(ctx context.Context, autoscaler *nomadv1alpha1.NomadAutoscaler) error {
	log := logf.FromContext(ctx)

	cluster := &nomadv1alpha1.NomadCluster{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      autoscaler.Spec.ClusterRef.Name,
		Namespace: autoscaler.Namespace,
	}, cluster); err != nil {
		return fmt.Errorf("failed to get cluster: %w", err)
	}

	// Prefer the management token; fall back to the bootstrap token —
	// during cluster teardown the management token may already be
	// revoked while the bootstrap Secret survives until the cluster
	// finalizer's last step.
	authToken := ""
	managementSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      phases.OperatorManagementSecretName(cluster.Name),
		Namespace: cluster.Namespace,
	}, managementSecret); err == nil {
		authToken = string(managementSecret.Data[phases.SecretKeySecretID])
	}
	if authToken == "" {
		bootstrapSecretName := cluster.Status.ACLBootstrapSecretName
		if bootstrapSecretName == "" {
			bootstrapSecretName = phases.BootstrapSecretName(cluster.Name)
		}
		bootstrapSecret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{
			Name:      bootstrapSecretName,
			Namespace: cluster.Namespace,
		}, bootstrapSecret); err != nil {
			return fmt.Errorf("failed to get a cleanup auth token (management and bootstrap secrets both unavailable): %w", err)
		}
		authToken = string(bootstrapSecret.Data[phases.SecretKeySecretID])
	}

	internalAddr := nomad.InternalServiceAddress(cluster.Name, cluster.Namespace, true)
	nomadClient, err := r.autoscalerNomadClient(ctx, cluster, internalAddr)
	if err != nil {
		return err
	}

	if autoscaler.Status.TokenAccessorID != "" {
		if err := nomadClient.DeleteACLToken(authToken, autoscaler.Status.TokenAccessorID); err != nil {
			if !nomad.IsNetworkError(err) {
				log.Error(err, "Failed to delete autoscaler agent token")
			} else if loadBalancerAddr := nomad.LoadBalancerAddress(cluster.Status.AdvertiseAddress, true); loadBalancerAddr != "" {
				if lbClient, lbErr := r.autoscalerNomadClient(ctx, cluster, loadBalancerAddr); lbErr == nil {
					_ = lbClient.DeleteACLToken(authToken, autoscaler.Status.TokenAccessorID)
				}
			}
		} else {
			log.Info("Deleted autoscaler agent token", "accessor", autoscaler.Status.TokenAccessorID)
		}
	}

	if autoscaler.Status.PolicyName != "" {
		if err := nomadClient.DeleteACLPolicy(authToken, autoscaler.Status.PolicyName); err != nil {
			if !nomad.IsNetworkError(err) {
				log.Error(err, "Failed to delete autoscaler agent policy")
			} else if loadBalancerAddr := nomad.LoadBalancerAddress(cluster.Status.AdvertiseAddress, true); loadBalancerAddr != "" {
				if lbClient, lbErr := r.autoscalerNomadClient(ctx, cluster, loadBalancerAddr); lbErr == nil {
					_ = lbClient.DeleteACLPolicy(authToken, autoscaler.Status.PolicyName)
				}
			}
		} else {
			log.Info("Deleted autoscaler agent policy", "policy", autoscaler.Status.PolicyName)
		}
	}

	return nil
}

// generateAutoscalerConfig renders the agent HCL. Policy documents are
// deliberately not rendered here: application scaling and Dynamic
// Application Sizing policies live in job specifications and reach the
// agent through its Nomad policy source.
func generateAutoscalerConfig(a *nomadv1alpha1.NomadAutoscaler, nomadAddr string) string {
	// The agent watches a single Nomad namespace or the wildcard. With
	// multiple specific namespaces the agent watches "*" and the ACL
	// token enforces the real boundary (wildcard reads return only what
	// the token can see).
	nomadNamespace := "*"
	if len(a.Spec.Namespaces) == 1 {
		nomadNamespace = a.Spec.Namespaces[0]
	}

	config := fmt.Sprintf(`log_level    = "%s"
enable_debug = %t

nomad {
  address   = "%s"
  ca_cert   = "/tls/ca.crt"
  namespace = "%s"
}

http {
  bind_address = "0.0.0.0"
  bind_port    = 8080
}

telemetry {
  prometheus_metrics = true
}
`, a.Spec.LogLevel, a.Spec.EnableDebug, nomadAddr, nomadNamespace)

	if a.Spec.Replicas > 1 {
		config += fmt.Sprintf(`
high_availability {
  enabled        = true
  lock_namespace = "%s"
  lock_path      = "%s"
}
`, autoscalerLockNamespace, autoscalerLockPath(a))
	}

	// DAS loads historical usage from Prometheus; without this APM the
	// agent's vertical policy handlers fail to start.
	if a.Spec.DynamicApplicationSizing.Enabled {
		config += fmt.Sprintf(`
apm "prometheus" {
  driver = "prometheus"
  config = {
    address = "%s"
  }
}
`, a.Spec.DynamicApplicationSizing.PrometheusURL)
	}

	return config
}

// reconcileConfigMap creates or updates the agent config ConfigMap.
func (r *NomadAutoscalerReconciler) reconcileConfigMap(ctx context.Context, autoscaler *nomadv1alpha1.NomadAutoscaler, config string) error {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      autoscalerConfigMapName(autoscaler),
			Namespace: autoscaler.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, cm, func() error {
		cm.Data = map[string]string{
			"autoscaler.hcl": config,
		}
		return controllerutil.SetControllerReference(autoscaler, cm, r.Scheme)
	})

	return err
}

// reconcileTokenSecret creates or updates the Secret holding the
// agent's Nomad token, using the shared key convention.
func (r *NomadAutoscalerReconciler) reconcileTokenSecret(ctx context.Context, autoscaler *nomadv1alpha1.NomadAutoscaler, nomadToken string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      autoscalerTokenName(autoscaler),
			Namespace: autoscaler.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		secret.Type = corev1.SecretTypeOpaque
		secret.Data = map[string][]byte{
			phases.SecretKeySecretID:   []byte(nomadToken),
			phases.SecretKeyAccessorID: []byte(autoscaler.Status.TokenAccessorID),
		}
		return controllerutil.SetControllerReference(autoscaler, secret, r.Scheme)
	})

	return err
}

// autoscalerAgentLabels returns the selector labels for the agent
// workload. managed-by matches phases.GetLabels — one operator, one
// identity.
func autoscalerAgentLabels(autoscaler *nomadv1alpha1.NomadAutoscaler) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "nomad-autoscaler-agent",
		"app.kubernetes.io/instance":   autoscaler.Name,
		"app.kubernetes.io/managed-by": "nomad-operator",
	}
}

// autoscalerImageRef builds the image reference; digest pinning takes
// precedence over tag, same contract as phases.ImageRef. Repository
// and tag are apiserver-defaulted (default={} on spec.image), never
// empty here.
func autoscalerImageRef(a *nomadv1alpha1.NomadAutoscaler) string {
	if a.Spec.Image.Digest != "" {
		return a.Spec.Image.Repository + "@" + a.Spec.Image.Digest
	}
	return a.Spec.Image.Repository + ":" + a.Spec.Image.Tag
}

// reconcileDeployment creates or updates the agent Deployment.
func (r *NomadAutoscalerReconciler) reconcileDeployment(ctx context.Context, autoscaler *nomadv1alpha1.NomadAutoscaler, cluster *nomadv1alpha1.NomadCluster, configChecksum, secretsChecksum string) error {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      autoscalerAgentName(autoscaler),
			Namespace: autoscaler.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, deploy, func() error {
		deploy.Spec = appsv1.DeploymentSpec{
			Replicas: ptr.To(autoscaler.Spec.Replicas),
			Selector: &metav1.LabelSelector{
				MatchLabels: autoscalerAgentLabels(autoscaler),
			},
			// Surge rollouts keep a warm standby up before the old
			// leader terminates, minimising the leadership gap.
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge:       ptr.To(intstr.FromInt32(1)),
					MaxUnavailable: ptr.To(intstr.FromInt32(0)),
				},
			},
			Template: r.buildAgentPodTemplate(autoscaler, cluster, configChecksum, secretsChecksum),
		}
		return controllerutil.SetControllerReference(autoscaler, deploy, r.Scheme)
	})

	return err
}

// buildAgentPodTemplate builds the agent pod template. The checksum
// annotations roll the Deployment when spec-derived config or the
// minted token changes.
func (r *NomadAutoscalerReconciler) buildAgentPodTemplate(
	autoscaler *nomadv1alpha1.NomadAutoscaler, cluster *nomadv1alpha1.NomadCluster,
	configChecksum, secretsChecksum string,
) corev1.PodTemplateSpec {
	template := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: autoscalerAgentLabels(autoscaler),
			Annotations: map[string]string{
				"checksum/config":  configChecksum,
				"checksum/secrets": secretsChecksum,
			},
		},
		Spec: corev1.PodSpec{
			// PSS restricted, same profile as the server pods.
			SecurityContext: phases.PodSecurityContext(cluster.Spec.OpenShift.Enabled),
			Containers: []corev1.Container{
				{
					Name:            "autoscaler",
					Image:           autoscalerImageRef(autoscaler),
					ImagePullPolicy: autoscaler.Spec.Image.PullPolicy,
					Command: []string{
						"nomad-autoscaler", "agent",
						"-config", "/config/autoscaler.hcl",
					},
					Env: []corev1.EnvVar{
						{
							Name: "NOMAD_TOKEN",
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: autoscalerTokenName(autoscaler),
									},
									Key: phases.SecretKeySecretID,
								},
							},
						},
					},
					Ports: []corev1.ContainerPort{
						{Name: "http", ContainerPort: 8080},
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path: "/v1/health",
								Port: intstr.FromString("http"),
							},
						},
						InitialDelaySeconds: 3,
					},
					LivenessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{
								Path: "/v1/health",
								Port: intstr.FromString("http"),
							},
						},
						InitialDelaySeconds: 10,
						PeriodSeconds:       30,
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "tmp",
							MountPath: "/tmp",
						},
						{
							Name:      "config",
							MountPath: "/config",
							ReadOnly:  true,
						},
						{
							Name:      "tls",
							MountPath: "/tls",
							ReadOnly:  true,
						},
					},
					Resources:       autoscaler.Spec.Resources,
					SecurityContext: phases.ContainerSecurityContext(),
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "tmp",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
				{
					Name: "config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: autoscalerConfigMapName(autoscaler),
							},
						},
					},
				},
				{
					Name: "tls",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: phases.TLSSecretName(cluster.Name),
						},
					},
				},
			},
			NodeSelector: autoscaler.Spec.NodeSelector,
			Tolerations:  autoscaler.Spec.Tolerations,
		},
	}

	// A standby on the same node as the leader protects nothing:
	// spread replicas across nodes (preferred, so single-node labs
	// still schedule).
	if autoscaler.Spec.Replicas > 1 {
		template.Spec.Affinity = &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
					{
						Weight: 100,
						PodAffinityTerm: corev1.PodAffinityTerm{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: autoscalerAgentLabels(autoscaler),
							},
							TopologyKey: "kubernetes.io/hostname",
						},
					},
				},
			},
		}
	}

	return template
}

// reconcilePDB keeps a PodDisruptionBudget in step with replicas: one
// exists only in HA mode, so voluntary evictions cannot take leader
// and standby together.
func (r *NomadAutoscalerReconciler) reconcilePDB(ctx context.Context, autoscaler *nomadv1alpha1.NomadAutoscaler) error {
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      autoscalerPDBName(autoscaler),
			Namespace: autoscaler.Namespace,
		},
	}

	if autoscaler.Spec.Replicas <= 1 {
		if err := r.Delete(ctx, pdb); err != nil && !k8serrors.IsNotFound(err) {
			return err
		}
		return nil
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, pdb, func() error {
		pdb.Spec = policyv1.PodDisruptionBudgetSpec{
			MinAvailable: ptr.To(intstr.FromInt32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: autoscalerAgentLabels(autoscaler),
			},
		}
		return controllerutil.SetControllerReference(autoscaler, pdb, r.Scheme)
	})

	return err
}

// reconcileMonitoring creates the metrics Service and ServiceMonitor.
// Gated on spec.monitoring plus Prometheus Operator CRD discovery, the
// same contract as the cluster monitoring phase.
func (r *NomadAutoscalerReconciler) reconcileMonitoring(ctx context.Context, autoscaler *nomadv1alpha1.NomadAutoscaler) error {
	if !autoscaler.Spec.Monitoring.IsEnabled() {
		return nil
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      autoscalerServiceName(autoscaler),
			Namespace: autoscaler.Namespace,
		},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
		labels := autoscalerAgentLabels(autoscaler)
		svc.Labels = map[string]string{
			"app.kubernetes.io/name":       labels["app.kubernetes.io/name"],
			"app.kubernetes.io/instance":   autoscaler.Name,
			"app.kubernetes.io/managed-by": "nomad-operator",
			"nomad.hashicorp.com/metrics":  "true",
		}
		svc.Spec.Selector = labels
		svc.Spec.Ports = []corev1.ServicePort{
			{Name: "http", Port: 8080, TargetPort: intstr.FromString("http")},
		}
		return controllerutil.SetControllerReference(autoscaler, svc, r.Scheme)
	})
	if err != nil {
		return err
	}

	if !discovery.HasGVK(r.RESTMapper(), autoscalerServiceMonitorGVK) {
		return nil
	}

	// The agent API is plain HTTP — no TLS config, unlike the cluster
	// ServiceMonitor.
	sm := &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      autoscalerServiceName(autoscaler),
			Namespace: autoscaler.Namespace,
		},
	}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, sm, func() error {
		sm.Labels = autoscalerAgentLabels(autoscaler)
		sm.Spec = monitoringv1.ServiceMonitorSpec{
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/instance":  autoscaler.Name,
					"nomad.hashicorp.com/metrics": "true",
				},
			},
			NamespaceSelector: monitoringv1.NamespaceSelector{
				MatchNames: []string{autoscaler.Namespace},
			},
			Endpoints: []monitoringv1.Endpoint{
				{
					Port:          "http",
					Path:          "/v1/metrics",
					Interval:      monitoringv1.Duration("30s"),
					ScrapeTimeout: monitoringv1.Duration("10s"),
					Params: map[string][]string{
						"format": {"prometheus"},
					},
				},
			},
		}
		return controllerutil.SetControllerReference(autoscaler, sm, r.Scheme)
	})
	return err
}

// setCondition updates a condition, leaving LastTransitionTime to
// meta.SetStatusCondition.
func (r *NomadAutoscalerReconciler) setCondition(autoscaler *nomadv1alpha1.NomadAutoscaler, condition metav1.Condition) {
	meta.SetStatusCondition(&autoscaler.Status.Conditions, condition)
}

// SetupWithManager sets up the controller with the Manager.
// ServiceMonitor is deliberately not in Owns: the CRD may be absent
// and the watch would fail at startup — same reasoning as the cluster
// monitoring phase.
func (r *NomadAutoscalerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nomadv1alpha1.NomadAutoscaler{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.Service{}).
		Owns(&appsv1.Deployment{}).
		Owns(&policyv1.PodDisruptionBudget{}).
		Named("nomadautoscaler").
		Complete(r)
}
