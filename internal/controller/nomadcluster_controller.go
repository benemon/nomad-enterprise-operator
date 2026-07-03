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

// Package controller implements the Kubernetes controller for NomadCluster resources.
package controller

import (
	"context"
	"fmt"
	"reflect"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/internal/controller/phases"
	"github.com/hashicorp/nomad-enterprise-operator/internal/metrics"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
)

const (
	// Finalizer name
	nomadClusterFinalizer = "nomad.hashicorp.com/finalizer"

	// defaultRequeueInterval governs the steady-state timer-driven requeue cadence.
	// Watches handle most reconcile triggers; this timer only catches things watches
	// can't see (LoadBalancer IP allocation, license expiry, periodic status enrichment).
	// 5 minutes is a sensible balance: long enough that healthy clusters do not produce
	// per-30s reconcile churn at fleet scale, short enough that LB-IP and license
	// transitions are picked up within a single human attention span.
	// Shorter requeues for "waiting on resource" scenarios (LB IP not yet assigned,
	// pod not yet ready) continue to use Requeue(15*time.Second, …) from phase.go.
	defaultRequeueInterval = 5 * time.Minute
)

// NomadClusterReconciler reconciles a NomadCluster object
type NomadClusterReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	RESTConfig *rest.Config
	Recorder   record.EventRecorder

	// NomadClientFactory overrides Nomad API client construction for the
	// finalizer's ACL cleanup (AC-2.4.7 order test). nil in production —
	// nomad.NewClient is used.
	NomadClientFactory func(cfg nomad.ClientConfig) (nomad.NomadAPI, error)
}

// newNomadClient builds a Nomad API client for finalizer cleanup,
// honouring the injected factory in tests. The production path carries
// the D4b request counter like every other operator Nomad client.
func (r *NomadClusterReconciler) newNomadClient(cfg nomad.ClientConfig) (nomad.NomadAPI, error) {
	if r.NomadClientFactory != nil {
		return r.NomadClientFactory(cfg)
	}
	c, err := nomad.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return metrics.InstrumentNomadAPI(c), nil
}

// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadclusters,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadclusters/status,verbs=patch
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadclusters/finalizers,verbs=update

// RBAC trimmed to observed runtime usage (neo-6xm.3 audit). Every
// resource the cache-backed client reads keeps get;list;watch (a Get
// through the default client starts an informer); write verbs exist
// only where a call site does. Owned resources are garbage-collected
// via ownerReferences, so most delete verbs are unnecessary.
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create

// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups=route.openshift.io,resources=routes/custom-host,verbs=create;update
// +kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors;prometheusrules,verbs=get;list;watch;create;update

// Reconcile is part of the main kubernetes reconciliation loop
func (r *NomadClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the NomadCluster instance
	cluster := &nomadv1alpha1.NomadCluster{}
	if err := r.Get(ctx, req.NamespacedName, cluster); err != nil {
		if k8serrors.IsNotFound(err) {
			log.Info("NomadCluster resource not found, ignoring")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get NomadCluster: %w", err)
	}

	// Handle deletion
	if !cluster.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, cluster)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(cluster, nomadClusterFinalizer) {
		controllerutil.AddFinalizer(cluster, nomadClusterFinalizer)
		if err := r.Update(ctx, cluster); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	// Initialize status if needed
	if cluster.Status.Phase == "" {
		patchBase := cluster.DeepCopy()
		cluster.Status.Phase = nomadv1alpha1.ClusterPhasePending
		if err := r.Status().Patch(ctx, cluster, client.MergeFrom(patchBase)); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Snapshot the cluster at the top of Reconcile so phase-internal
	// status mutations (e.g. CertificatePhase.updateCAStatus) are captured
	// in the final Status().Patch diff. Snapshotting only inside
	// updateFinalStatus misses anything a phase wrote before it ran —
	// previously caught silently because envtest happy-path didn't assert
	// on phase-written status fields, exposed by e2e.
	reconcileStartSnapshot := cluster.DeepCopy()

	// Create phase context
	phaseCtx := phases.NewPhaseContext(r.Client, r.Scheme, log, r.RESTConfig)
	phaseCtx.Recorder = r.Recorder

	// Execute reconciliation phases in order
	phaseList := r.buildPhases(phaseCtx)

	for _, phase := range phaseList {
		log.V(1).Info("Executing phase", "phase", phase.Name())

		result := phases.TimedExecute(ctx, phase, cluster)

		if result.Error != nil {
			log.Error(result.Error, "Phase failed", "phase", phase.Name(), "message", result.Message)

			patchBase := cluster.DeepCopy()
			cluster.Status.Phase = nomadv1alpha1.ClusterPhaseFailed
			// A phase may carry a specific user-actionable reason
			// (neo-0zq, e.g. LicenseSecretNotFound); fall back to the
			// generic PhaseFailed otherwise. Entering a specific-reason
			// state emits a Warning Event once per transition.
			reason := "PhaseFailed"
			if result.Reason != "" {
				reason = result.Reason
			}
			if prev := meta.FindStatusCondition(cluster.Status.Conditions, "Ready"); r.Recorder != nil &&
				result.Reason != "" && (prev == nil || prev.Reason != reason) {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, reason, result.Message)
			}
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:    "Ready",
				Status:  metav1.ConditionFalse,
				Reason:  reason,
				Message: fmt.Sprintf("%s: %s", phase.Name(), result.Message),
			})
			if err := r.Status().Patch(ctx, cluster, client.MergeFrom(patchBase)); err != nil {
				log.Error(err, "Failed to patch status after phase failure")
			}

			return ctrl.Result{RequeueAfter: defaultRequeueInterval}, result.Error
		}

		if result.Requeue {
			log.Info("Phase requested requeue", "phase", phase.Name(), "after", result.RequeueAfter, "message", result.Message, "reason", result.Reason)

			reason := result.Reason
			if reason == "" {
				reason = "Reconciling"
			}

			patchBase := cluster.DeepCopy()
			cluster.Status.Phase = nomadv1alpha1.ClusterPhaseCreating
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:    "Ready",
				Status:  metav1.ConditionFalse,
				Reason:  reason,
				Message: result.Message,
			})
			if err := r.Status().Patch(ctx, cluster, client.MergeFrom(patchBase)); err != nil {
				log.Error(err, "Failed to patch status during requeue")
			}

			return ctrl.Result{RequeueAfter: result.RequeueAfter}, nil
		}
	}

	// All phases completed successfully - update final status
	if err := r.updateFinalStatus(ctx, cluster, phaseCtx, reconcileStartSnapshot); err != nil {
		log.Error(err, "Failed to update final status")
		return ctrl.Result{}, err
	}

	log.Info("Reconciliation completed successfully")
	return ctrl.Result{RequeueAfter: defaultRequeueInterval}, nil
}

func (r *NomadClusterReconciler) buildPhases(ctx *phases.PhaseContext) []phases.Phase {
	return []phases.Phase{
		phases.NewServiceAccountPhase(ctx),
		phases.NewRBACPhase(ctx),
		phases.NewGossipPhase(ctx),
		phases.NewServicesPhase(ctx),
		phases.NewAdvertisePhase(ctx),
		phases.NewCertificatePhase(ctx), // After Advertise so LoadBalancer IP is in cert SANs
		phases.NewSecretsPhase(ctx),
		phases.NewConfigMapPhase(ctx),
		phases.NewStatefulSetPhase(ctx),
		phases.NewPDBPhase(ctx),       // After StatefulSet so PDB selector matches running pods (D1 / neo-fp3)
		phases.NewScaleDownPhase(ctx), // After StatefulSet so sts exists for replica gap detection (D2b / neo-1ve.2)
		phases.NewRoutePhase(ctx),
		phases.NewMonitoringPhase(ctx),
		phases.NewACLBootstrapPhase(ctx),
		phases.NewClusterStatusPhase(ctx), // Query Nomad API for status enrichment
	}
}

func (r *NomadClusterReconciler) handleDeletion(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if controllerutil.ContainsFinalizer(cluster, nomadClusterFinalizer) {
		log.Info("Handling NomadCluster deletion")

		// Attempt to clean up Nomad-side ACL resources. The bootstrap
		// Secret is read here (AC-2.4.2), before anything deletes it —
		// it carries no ownerReference (C3), precisely so this cleanup
		// can still authenticate against Nomad during deletion.
		// Gated on spec (not status): cleanup uses deterministic names,
		// so it must run even when the status cache fields were never
		// persisted (AC-2.4.7 leak window).
		// Non-fatal — Kubernetes-owned resources are cleaned up via owner references
		if cluster.Spec.Server.ACL.Enabled {
			if err := r.cleanupNomadACLResources(ctx, cluster); err != nil {
				log.Error(err, "Failed to clean up Nomad-side ACL resources, continuing")
			}
		}

		// Clean up PVCs created by StatefulSet volumeClaimTemplates.
		// These are not owned by the NomadCluster so won't be garbage
		// collected automatically. Gated on spec.persistence.reclaimPolicy:
		// under Retain (the default) the PVCs survive deletion so Raft
		// state outlives accidental CR removal; the value in effect at
		// deletion time wins (AC-2.3.15 — not retroactive).
		if cluster.Spec.Persistence.ReclaimPolicy == nomadv1alpha1.ReclaimPolicyDelete {
			if err := r.cleanupPVCs(ctx, cluster); err != nil {
				log.Error(err, "Failed to cleanup PVCs")
				return ctrl.Result{}, err
			}
		} else {
			log.Info("Retaining PVCs per spec.persistence.reclaimPolicy",
				"reclaimPolicy", cluster.Spec.Persistence.ReclaimPolicy)
		}

		// AC-2.4.3: delete the bootstrap Secret last. It has no
		// ownerReference (C3), so without this explicit delete it would
		// leak on every cluster deletion. Nomad-side cleanup above is
		// best-effort; the Secret is removed regardless of its outcome.
		bootstrapSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      phases.BootstrapSecretName(cluster.Name),
				Namespace: cluster.Namespace,
			},
		}
		if err := r.Delete(ctx, bootstrapSecret); err != nil && !k8serrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}

		// Remove finalizer
		controllerutil.RemoveFinalizer(cluster, nomadClusterFinalizer)
		if err := r.Update(ctx, cluster); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// cleanupPVCs deletes PVCs created by the StatefulSet volumeClaimTemplates
func (r *NomadClusterReconciler) cleanupPVCs(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) error {
	log := logf.FromContext(ctx)

	// List PVCs with matching labels
	pvcList := &corev1.PersistentVolumeClaimList{}
	if err := r.List(ctx, pvcList,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(phases.GetSelectorLabels(cluster)),
	); err != nil {
		return err
	}

	// Delete each PVC
	for _, pvc := range pvcList.Items {
		log.Info("Deleting PVC", "name", pvc.Name)
		if err := r.Delete(ctx, &pvc); err != nil && !k8serrors.IsNotFound(err) {
			return err
		}
	}

	return nil
}

// cleanupNomadACLResources revokes the operator-created Nomad-side ACL
// tokens and policies — management first, then status (C4 / AC-2.4.7).
// Deterministic names are the source of truth, NOT the status cache
// fields: a cluster deleted between Nomad-side creation and the status
// write must still get its policy revoked. Per-resource failures are
// logged and cleanup continues (best-effort).
func (r *NomadClusterReconciler) cleanupNomadACLResources(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) error {
	log := logf.FromContext(ctx)

	// Retrieve bootstrap token for authentication. The Secret name is
	// operator-owned per ADR 0003.
	bootstrapSecretName := phases.BootstrapSecretName(cluster.Name)

	bootstrapSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      bootstrapSecretName,
		Namespace: cluster.Namespace,
	}, bootstrapSecret); err != nil {
		return fmt.Errorf("failed to get bootstrap secret for cleanup: %w", err)
	}
	bootstrapToken := string(bootstrapSecret.Data[phases.SecretKeySecretID])
	if bootstrapToken == "" {
		return fmt.Errorf("bootstrap secret has empty secret-id")
	}

	// Create Nomad client targeting the internal service address
	address := nomad.InternalServiceAddress(cluster.Name, cluster.Namespace, true)

	// Load TLS CA cert for the cleanup client. mTLS is always enabled so we
	// replicate the TLS secret lookup here (cleanupOperatorStatusResources is
	// on NomadClusterReconciler, not PhaseContext).
	var caCert []byte
	tlsSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      phases.TLSSecretName(cluster.Name),
		Namespace: cluster.Namespace,
	}, tlsSecret); err != nil {
		log.Error(err, "Failed to get TLS secret for cleanup client, Nomad ACL resources may be leaked")
		// Non-fatal: proceed with best-effort cleanup
	} else {
		caCert = tlsSecret.Data["ca.crt"]
	}

	cfg := nomad.ClientConfig{
		Address:    address,
		Token:      bootstrapToken,
		TLSEnabled: true,
		CACert:     caCert,
		Timeout:    10 * time.Second,
	}

	nomadClient, err := r.newNomadClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Nomad client for cleanup: %w", err)
	}

	// Revoke each derived credential, management first (AC-2.4.7 order).
	// The token accessor ID lives in the Secret of the same deterministic
	// name; a missing Secret or Nomad-side not-found just means there is
	// nothing to revoke. The management token has no policy — it is
	// management-type (Nomad has no ACL-write policy grammar).
	for _, cred := range []struct {
		name      string
		hasPolicy bool
	}{
		{phases.OperatorManagementSecretName(cluster.Name), false},
		{phases.OperatorStatusName(cluster.Name), true},
	} {
		secret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{
			Name:      cred.name,
			Namespace: cluster.Namespace,
		}, secret); err == nil {
			if accessorID := string(secret.Data[phases.SecretKeyAccessorID]); accessorID != "" {
				if err := nomadClient.DeleteACLToken(bootstrapToken, accessorID); err != nil {
					log.Error(err, "Failed to delete ACL token", "name", cred.name, "accessorID", accessorID)
				} else {
					log.Info("Deleted ACL token", "name", cred.name, "accessorID", accessorID)
				}
			}
		}

		if !cred.hasPolicy {
			continue
		}
		if err := nomadClient.DeleteACLPolicy(bootstrapToken, cred.name); err != nil {
			log.Error(err, "Failed to delete ACL policy", "policy", cred.name)
		} else {
			log.Info("Deleted ACL policy", "policy", cred.name)
		}
	}

	return nil
}

func (r *NomadClusterReconciler) updateFinalStatus(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, phaseCtx *phases.PhaseContext, reconcileStartSnapshot *nomadv1alpha1.NomadCluster) error {
	// Use the top-of-Reconcile snapshot so phase-internal mutations
	// (e.g. CertificatePhase.updateCAStatus) are captured in the patch
	// diff alongside everything updateFinalStatus writes below.
	//
	// Two purposes:
	//   (1) client.MergeFrom(patchBase) — the merge patch sent to the
	//       server contains only the status fields changed during this
	//       reconcile, so concurrent reconciles or external mutations
	//       to other fields do not race on resourceVersion
	//       (A3 / design review §5.5).
	//   (2) The .Status sub-copy feeds AC-2.8.4's lastReconcileTime
	//       gate: only advance the field when something other than
	//       itself changed, or when the heartbeat threshold has elapsed.
	patchBase := reconcileStartSnapshot
	statusSnapshot := &patchBase.Status

	// Get StatefulSet status
	r.updateStatefulSetStatus(ctx, cluster)

	// C9 (neo-jmq / AC-2.5.7): sub-resource state lives in dedicated
	// status sub-fields; the single Ready condition computed below is
	// the only condition. See the contract comment on the api package.
	if phaseCtx.AdvertiseAddress != "" {
		cluster.Status.AdvertiseAddress = phaseCtx.AdvertiseAddress
	}

	cluster.Status.GossipKeySecretName = phases.GossipSecretName(cluster)

	// Check ACL bootstrap status
	r.updateACLBootstrapStatus(ctx, cluster)

	// status.routeHost is written by RoutePhase (the Route's owner)
	// within the reconcile-start patch window — no second computation
	// here (neo-bjm).

	// License and autopilot sub-fields from phase context (populated by
	// ClusterStatusPhase; nil on probe miss preserves last-known state)
	if phaseCtx.License != nil {
		cluster.Status.License = phaseCtx.License
	}
	if phaseCtx.Autopilot != nil {
		cluster.Status.Autopilot = phaseCtx.Autopilot
	}

	// Update leader info from phase context (populated by ClusterStatusPhase)
	if phaseCtx.LeaderAddress != "" {
		cluster.Status.LeaderAddress = phaseCtx.LeaderAddress
	}

	// Update Nomad version from phase context (populated by C7 probe).
	// Guarded on non-empty so a probe miss after a previous success
	// preserves the last-known version rather than clobbering it.
	if phaseCtx.NomadVersion != "" {
		cluster.Status.NomadVersion = phaseCtx.NomadVersion
	}

	// Single Ready condition (AC-2.5.5 precondition, AC-2.5.6 reasons).
	// Order is deterministic: infrastructure first (replicas), then
	// Nomad-side health (license, autopilot). Unknown probe state (nil
	// sub-field) does not fail Ready.
	ready := metav1.Condition{
		Type:    "Ready",
		Status:  metav1.ConditionTrue,
		Reason:  "ClusterReady",
		Message: fmt.Sprintf("Nomad cluster is running with %d/%d replicas", cluster.Status.ReadyReplicas, cluster.Spec.Replicas),
	}
	switch {
	case caExpired(cluster):
		// Checked before replicas: an expired CA kills TLS cluster-wide,
		// which also manifests as unready replicas — without this case
		// the outage would be misreported as WaitingForReplicas
		// (neo-ru9, user-decided in scope).
		cluster.Status.Phase = nomadv1alpha1.ClusterPhaseRunning
		ready.Status = metav1.ConditionFalse
		ready.Reason = "CAExpired"
		ready.Message = "CA certificate has expired; TLS handshakes fail cluster-wide. See status.certificateAuthority"
	case cluster.Status.ReadyReplicas != cluster.Spec.Replicas || cluster.Status.ReadyReplicas == 0:
		cluster.Status.Phase = nomadv1alpha1.ClusterPhaseCreating
		ready.Status = metav1.ConditionFalse
		ready.Reason = "WaitingForReplicas"
		ready.Message = fmt.Sprintf("Waiting for replicas: %d/%d ready", cluster.Status.ReadyReplicas, cluster.Spec.Replicas)
	case cluster.Status.License != nil && !cluster.Status.License.Valid:
		// Pods are up (phase stays Running); the cluster is degraded.
		cluster.Status.Phase = nomadv1alpha1.ClusterPhaseRunning
		ready.Status = metav1.ConditionFalse
		ready.Reason = "LicenseExpired"
		ready.Message = "Nomad Enterprise license has expired; see status.license"
	case cluster.Status.Autopilot != nil && !cluster.Status.Autopilot.Healthy:
		cluster.Status.Phase = nomadv1alpha1.ClusterPhaseRunning
		ready.Status = metav1.ConditionFalse
		ready.Reason = "AutopilotUnhealthy"
		ready.Message = "Raft autopilot reports unhealthy servers; see status.autopilot"
	default:
		cluster.Status.Phase = nomadv1alpha1.ClusterPhaseRunning
	}
	meta.SetStatusCondition(&cluster.Status.Conditions, ready)

	// One-shot Event: emit the first time we observe Ready=True for this
	// cluster. The debounce field on Status survives operator restart so
	// we never re-emit. Downstream issues (B6 audit migration, etc.) use
	// the same status-field pattern for their per-cluster one-shots.
	// The flag mutation falls within updateFinalStatus's existing
	// patchBase/Status().Patch window, so it lands in the merge patch.
	if ready.Status == metav1.ConditionTrue &&
		!cluster.Status.InitialReconcileEventEmitted && r.Recorder != nil {
		r.Recorder.Event(cluster, corev1.EventTypeNormal, "Reconciled",
			"InitialReconcileComplete")
		cluster.Status.InitialReconcileEventEmitted = true
	}

	// Update observed generation. ObservedGeneration is gated separately
	// from lastReconcileTime — we always set it to match the latest
	// observed spec generation.
	cluster.Status.ObservedGeneration = cluster.Generation

	// Decide whether to advance status.lastReconcileTime per AC-2.8.4.
	// Skip the lastReconcileTime field itself in the diff (otherwise the
	// last write's timestamp would always look like a change).
	r.maybeAdvanceLastReconcileTime(cluster, statusSnapshot)

	return r.Status().Patch(ctx, cluster, client.MergeFrom(patchBase))
}

// caExpired reports whether the cluster's CA certificate is past its
// expiry per status.certificateAuthority (neo-ru9). Empty or
// unparseable expiry — including pre-first-reconcile — is not expired.
func caExpired(cluster *nomadv1alpha1.NomadCluster) bool {
	ca := cluster.Status.CertificateAuthority
	if ca == nil || ca.ExpiryTime == "" {
		return false
	}
	expiry, err := time.Parse(time.RFC3339, ca.ExpiryTime)
	if err != nil {
		return false
	}
	return time.Now().After(expiry)
}

// maybeAdvanceLastReconcileTime applies the AC-2.8.4 gate: advance
// status.lastReconcileTime only if any other status field changed this
// reconcile, OR if defaultRequeueInterval/2 (the heartbeat threshold) has
// elapsed since the previous update.
//
// The heartbeat threshold ensures the field continues to advance even when
// the cluster is idle — operators watching .status.lastReconcileTime for
// "is the operator alive?" still see updates, just at half-requeue cadence
// rather than every loop.
func (r *NomadClusterReconciler) maybeAdvanceLastReconcileTime(cluster *nomadv1alpha1.NomadCluster, snapshot *nomadv1alpha1.NomadClusterStatus) {
	// Compute "did anything other than lastReconcileTime change". Cheapest
	// way to compare is to copy the current and the snapshot, zero out the
	// LastReconcileTime field on both, and DeepEqual.
	a := cluster.Status.DeepCopy()
	b := snapshot.DeepCopy()
	a.LastReconcileTime = nil
	b.LastReconcileTime = nil
	stateChanged := !reflect.DeepEqual(a, b)

	heartbeatThreshold := defaultRequeueInterval / 2
	heartbeatDue := snapshot.LastReconcileTime == nil ||
		time.Since(snapshot.LastReconcileTime.Time) >= heartbeatThreshold

	if stateChanged || heartbeatDue {
		now := metav1.Now()
		cluster.Status.LastReconcileTime = &now
	}
	// else: leave cluster.Status.LastReconcileTime as the snapshot value.
	// The caller still issues Status().Patch with client.MergeFrom(patchBase);
	// if no Status fields changed at all, the merge patch is empty and the
	// server-side write is a no-op.
}

// updateStatefulSetStatus mirrors the StatefulSet replica counters into
// status sub-fields (C9: no per-resource condition — readiness feeds
// the single Ready condition in updateFinalStatus).
func (r *NomadClusterReconciler) updateStatefulSetStatus(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) {
	sts := &appsv1.StatefulSet{}
	if err := r.Get(ctx, client.ObjectKey{Name: cluster.Name, Namespace: cluster.Namespace}, sts); err != nil {
		return
	}

	cluster.Status.ReadyReplicas = sts.Status.ReadyReplicas
	cluster.Status.CurrentReplicas = sts.Status.CurrentReplicas
}

// updateACLBootstrapStatus mirrors ACL bootstrap completion into status
// sub-fields.
func (r *NomadClusterReconciler) updateACLBootstrapStatus(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) {
	if !cluster.Spec.Server.ACL.Enabled {
		return
	}

	bootstrapSecretName := phases.BootstrapSecretName(cluster.Name)

	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: bootstrapSecretName, Namespace: cluster.Namespace}, secret); err == nil {
		cluster.Status.ACLBootstrapped = true
		cluster.Status.ACLBootstrapSecretName = bootstrapSecretName
	}
}

// SetupWithManager sets up the controller with the Manager.
// secretRefIndexes maps a field-index key to the extractor pulling that
// Secret reference out of a NomadCluster spec (D5 / neo-380). Shared by
// SetupWithManager (real manager cache) and unit tests (fake client
// WithIndex) so the two cannot drift.
var secretRefIndexes = map[string]func(*nomadv1alpha1.NomadCluster) string{
	"spec.license.secretName": func(c *nomadv1alpha1.NomadCluster) string {
		return c.Spec.License.SecretName
	},
	"spec.server.tls.ca.secretName": func(c *nomadv1alpha1.NomadCluster) string {
		if c.Spec.Server.TLS.CA == nil {
			return ""
		}
		return c.Spec.Server.TLS.CA.SecretName
	},
	"spec.gossip.secretName": func(c *nomadv1alpha1.NomadCluster) string {
		return c.Spec.Gossip.SecretName
	},
}

func (r *NomadClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// D5 (neo-380): index the spec fields that can reference external
	// Secrets so findClustersReferencingSecret is an indexed lookup, not
	// a namespace-wide list+filter on every Secret event.
	for key, extract := range secretRefIndexes {
		extract := extract
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &nomadv1alpha1.NomadCluster{}, key,
			func(obj client.Object) []string {
				if name := extract(obj.(*nomadv1alpha1.NomadCluster)); name != "" {
					return []string{name}
				}
				return nil
			}); err != nil {
			return fmt.Errorf("failed to register field index %s: %w", key, err)
		}
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&nomadv1alpha1.NomadCluster{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.Service{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&appsv1.StatefulSet{}).
		// Watch external secrets (not owned by NomadCluster) for rolling restarts.
		//
		// D5 (neo-380) deliberately does NOT add a cache.Options.ByObject
		// filter for Secrets, deviating from the design doc's AC-D5.2.
		// The filter needs union semantics — operator-labelled OR
		// named-per-convention OR dynamically user-referenced (license/CA/
		// gossip Secrets with arbitrary names, possibly cross-namespace) —
		// and controller-runtime selectors are static: they cannot express
		// "referenced by some NomadCluster". A label-only filter would
		// silently break both the phases' Get calls for unlabelled user
		// Secrets (cache-backed reads return NotFound for uncached
		// objects) and this rolling-restart watch. The reconcile-storm
		// concern is already solved by the field-indexed map function
		// (zero requests for unreferenced Secrets); what remains is
		// informer memory, acceptable at the documented ≤200-cluster
		// scale. Revisit only with a mechanism like operator-applied
		// reference labels plus an APIReader migration for user Secrets.
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findClustersReferencingSecret),
		).
		Named("nomadcluster").
		Complete(r)
}

// findClustersReferencingSecret returns reconcile requests for NomadClusters that reference the given secret.
// This enables rolling restarts when external secrets (TLS, license, S3 credentials) change.
func (r *NomadClusterReconciler) findClustersReferencingSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}

	// Skip secrets owned by a NomadCluster (already handled by Owns)
	for _, ref := range secret.GetOwnerReferences() {
		if ref.Kind == "NomadCluster" {
			return nil
		}
	}

	// D5 (neo-380): indexed lookups against the secretRefIndexes fields
	// instead of listing every NomadCluster in the namespace. A cluster
	// can match more than one index (e.g. the same Secret named for both
	// license and gossip), so requests are deduplicated.
	seen := map[types.NamespacedName]bool{}
	var requests []reconcile.Request
	for key := range secretRefIndexes {
		clusterList := &nomadv1alpha1.NomadClusterList{}
		if err := r.List(ctx, clusterList,
			client.InNamespace(secret.Namespace),
			client.MatchingFields{key: secret.Name},
		); err != nil {
			continue
		}
		for _, cluster := range clusterList.Items {
			name := types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}
			if seen[name] {
				continue
			}
			seen[name] = true
			requests = append(requests, reconcile.Request{NamespacedName: name})
		}
	}

	return requests
}
