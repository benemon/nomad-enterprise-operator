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
	"k8s.io/apimachinery/pkg/runtime/schema"
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
	"github.com/hashicorp/nomad-enterprise-operator/internal/discovery"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"

	routev1 "github.com/openshift/api/route/v1"
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
}

// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadclusters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadclusters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadclusters/finalizers,verbs=update

// +kubebuilder:rbac:groups="",resources=configmaps;secrets;services;serviceaccounts;pods;persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=route.openshift.io,resources=routes/custom-host,verbs=create;update;patch
// +kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors;prometheusrules,verbs=get;list;watch;create;update;patch;delete

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

		result := phase.Execute(ctx, cluster)

		if result.Error != nil {
			log.Error(result.Error, "Phase failed", "phase", phase.Name(), "message", result.Message)

			patchBase := cluster.DeepCopy()
			cluster.Status.Phase = nomadv1alpha1.ClusterPhaseFailed
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:    nomadv1alpha1.ConditionTypeReady,
				Status:  metav1.ConditionFalse,
				Reason:  "PhaseFailed",
				Message: fmt.Sprintf("%s: %s", phase.Name(), result.Message),
			})
			if err := r.Status().Patch(ctx, cluster, client.MergeFrom(patchBase)); err != nil {
				log.Error(err, "Failed to patch status after phase failure")
			}

			return ctrl.Result{RequeueAfter: defaultRequeueInterval}, result.Error
		}

		if result.Requeue {
			log.Info("Phase requested requeue", "phase", phase.Name(), "after", result.RequeueAfter, "message", result.Message)

			patchBase := cluster.DeepCopy()
			cluster.Status.Phase = nomadv1alpha1.ClusterPhaseCreating
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:    nomadv1alpha1.ConditionTypeReady,
				Status:  metav1.ConditionFalse,
				Reason:  "Reconciling",
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

		// Attempt to clean up Nomad-side ACL resources
		// Non-fatal — Kubernetes-owned resources are cleaned up via owner references
		if cluster.Status.OperatorStatusPolicyName != "" {
			if err := r.cleanupOperatorStatusResources(ctx, cluster); err != nil {
				log.Error(err, "Failed to clean up operator status ACL resources, continuing")
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

// cleanupOperatorStatusResources attempts to delete the Nomad-side ACL token
// and policy created for the operator status token. Failures are non-fatal.
func (r *NomadClusterReconciler) cleanupOperatorStatusResources(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) error {
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
	bootstrapToken := string(bootstrapSecret.Data["secret-id"])
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
		Name:      cluster.Name + "-tls",
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

	nomadClient, err := nomad.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Nomad client for cleanup: %w", err)
	}

	// Revoke the operator status token if we can read its accessor ID
	if cluster.Status.OperatorStatusSecretName != "" {
		opSecret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{
			Name:      cluster.Status.OperatorStatusSecretName,
			Namespace: cluster.Namespace,
		}, opSecret); err == nil {
			accessorID := string(opSecret.Data[phases.SecretKeyAccessorID])
			if accessorID != "" {
				if err := nomadClient.DeleteACLToken(bootstrapToken, accessorID); err != nil {
					log.Error(err, "Failed to delete operator status ACL token", "accessorID", accessorID)
				} else {
					log.Info("Deleted operator status ACL token", "accessorID", accessorID)
				}
			}
		}
	}

	// Delete the operator status policy
	if err := nomadClient.DeleteACLPolicy(bootstrapToken, cluster.Status.OperatorStatusPolicyName); err != nil {
		log.Error(err, "Failed to delete operator status ACL policy", "policy", cluster.Status.OperatorStatusPolicyName)
		return err
	}
	log.Info("Deleted operator status ACL policy", "policy", cluster.Status.OperatorStatusPolicyName)

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

	// Update advertise address from phase context and set condition
	if phaseCtx.AdvertiseAddress != "" {
		cluster.Status.AdvertiseAddress = phaseCtx.AdvertiseAddress
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeAdvertiseResolved,
			Status:  metav1.ConditionTrue,
			Reason:  "AddressResolved",
			Message: fmt.Sprintf("Advertise address resolved: %s", phaseCtx.AdvertiseAddress),
		})
	} else {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeAdvertiseResolved,
			Status:  metav1.ConditionFalse,
			Reason:  "WaitingForLoadBalancer",
			Message: "Waiting for LoadBalancer IP to be assigned",
		})
	}

	// Determine gossip key secret name and check condition
	gossipSecretName := cluster.Name + "-gossip"
	if cluster.Spec.Gossip.SecretName != "" {
		gossipSecretName = cluster.Spec.Gossip.SecretName
	}
	cluster.Status.GossipKeySecretName = gossipSecretName

	gossipSecret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: gossipSecretName, Namespace: cluster.Namespace}, gossipSecret); err == nil {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeGossipKeyReady,
			Status:  metav1.ConditionTrue,
			Reason:  "GossipKeyExists",
			Message: fmt.Sprintf("Gossip encryption key configured in secret %s", gossipSecretName),
		})
	} else {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeGossipKeyReady,
			Status:  metav1.ConditionFalse,
			Reason:  "GossipKeyNotFound",
			Message: fmt.Sprintf("Gossip key secret %s not found", gossipSecretName),
		})
	}

	// Check services condition
	r.updateServicesStatus(ctx, cluster)

	// Check ACL bootstrap status
	r.updateACLBootstrapStatus(ctx, cluster)

	// Get Route host if enabled and set condition
	r.updateRouteStatus(ctx, cluster)

	// Check monitoring condition. Mirrors the MonitoringPhase gate:
	// spec.monitoring.enabled AND Prometheus Operator CRDs installed,
	// independent of openshift.enabled (B4 / AC-2.2.4).
	if cluster.Spec.Monitoring.Enabled &&
		discovery.HasGVK(r.RESTMapper(), schema.GroupVersionKind{
			Group: "monitoring.coreos.com", Version: "v1", Kind: "ServiceMonitor",
		}) {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeMonitoringReady,
			Status:  metav1.ConditionTrue,
			Reason:  "MonitoringConfigured",
			Message: "ServiceMonitor and PrometheusRule resources configured",
		})
	}

	// Update license status from phase context (populated by ClusterStatusPhase)
	r.updateLicenseStatus(cluster, phaseCtx)

	// Update autopilot status from phase context (populated by ClusterStatusPhase)
	r.updateAutopilotStatus(cluster, phaseCtx)

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

	// Determine cluster phase and overall Ready condition
	if cluster.Status.ReadyReplicas == cluster.Spec.Replicas && cluster.Status.ReadyReplicas > 0 {
		cluster.Status.Phase = nomadv1alpha1.ClusterPhaseRunning
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeReady,
			Status:  metav1.ConditionTrue,
			Reason:  "ClusterReady",
			Message: fmt.Sprintf("Nomad cluster is running with %d/%d replicas", cluster.Status.ReadyReplicas, cluster.Spec.Replicas),
		})

		// One-shot Event: emit the first time we observe Ready=True for this
		// cluster. The debounce field on Status survives operator restart so
		// we never re-emit. Downstream issues (B6 audit migration, etc.) use
		// the same status-field pattern for their per-cluster one-shots.
		// The flag mutation falls within updateFinalStatus's existing
		// patchBase/Status().Patch window, so it lands in the merge patch.
		if !cluster.Status.InitialReconcileEventEmitted && r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, "Reconciled",
				"InitialReconcileComplete")
			cluster.Status.InitialReconcileEventEmitted = true
		}
	} else {
		cluster.Status.Phase = nomadv1alpha1.ClusterPhaseCreating
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeReady,
			Status:  metav1.ConditionFalse,
			Reason:  "WaitingForReplicas",
			Message: fmt.Sprintf("Waiting for replicas: %d/%d ready", cluster.Status.ReadyReplicas, cluster.Spec.Replicas),
		})
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

// updateStatefulSetStatus updates the cluster status based on StatefulSet state.
func (r *NomadClusterReconciler) updateStatefulSetStatus(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) {
	sts := &appsv1.StatefulSet{}
	if err := r.Get(ctx, client.ObjectKey{Name: cluster.Name, Namespace: cluster.Namespace}, sts); err != nil {
		if !k8serrors.IsNotFound(err) {
			return
		}
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeStatefulSetReady,
			Status:  metav1.ConditionFalse,
			Reason:  "StatefulSetNotFound",
			Message: "StatefulSet has not been created yet",
		})
		return
	}

	cluster.Status.ReadyReplicas = sts.Status.ReadyReplicas
	cluster.Status.CurrentReplicas = sts.Status.CurrentReplicas

	if sts.Status.ReadyReplicas == *sts.Spec.Replicas && sts.Status.ReadyReplicas > 0 {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeStatefulSetReady,
			Status:  metav1.ConditionTrue,
			Reason:  "AllReplicasReady",
			Message: fmt.Sprintf("StatefulSet has %d/%d replicas ready", sts.Status.ReadyReplicas, *sts.Spec.Replicas),
		})
	} else {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeStatefulSetReady,
			Status:  metav1.ConditionFalse,
			Reason:  "ReplicasNotReady",
			Message: fmt.Sprintf("StatefulSet has %d/%d replicas ready", sts.Status.ReadyReplicas, *sts.Spec.Replicas),
		})
	}
}

// updateServicesStatus updates the cluster status based on service availability.
func (r *NomadClusterReconciler) updateServicesStatus(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) {
	internalSvc := &corev1.Service{}
	externalSvc := &corev1.Service{}
	internalExists := r.Get(ctx, client.ObjectKey{Name: cluster.Name + "-internal", Namespace: cluster.Namespace}, internalSvc) == nil
	externalExists := r.Get(ctx, client.ObjectKey{Name: cluster.Name + "-external", Namespace: cluster.Namespace}, externalSvc) == nil

	if internalExists && externalExists {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeServicesReady,
			Status:  metav1.ConditionTrue,
			Reason:  "ServicesCreated",
			Message: "All required services have been created",
		})
		return
	}

	var missing []string
	if !internalExists {
		missing = append(missing, cluster.Name+"-internal")
	}
	if !externalExists {
		missing = append(missing, cluster.Name+"-external")
	}
	meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
		Type:    nomadv1alpha1.ConditionTypeServicesReady,
		Status:  metav1.ConditionFalse,
		Reason:  "ServicesMissing",
		Message: fmt.Sprintf("Missing services: %v", missing),
	})
}

// updateACLBootstrapStatus updates the cluster status based on ACL bootstrap state.
func (r *NomadClusterReconciler) updateACLBootstrapStatus(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) {
	if !cluster.Spec.Server.ACL.Enabled {
		return
	}

	bootstrapSecretName := phases.BootstrapSecretName(cluster.Name)

	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: bootstrapSecretName, Namespace: cluster.Namespace}, secret); err == nil {
		cluster.Status.ACLBootstrapped = true
		cluster.Status.ACLBootstrapSecretName = bootstrapSecretName
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeACLBootstrapped,
			Status:  metav1.ConditionTrue,
			Reason:  "ACLBootstrapComplete",
			Message: fmt.Sprintf("ACL bootstrap token stored in secret %s", bootstrapSecretName),
		})
	} else {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeACLBootstrapped,
			Status:  metav1.ConditionFalse,
			Reason:  "ACLBootstrapPending",
			Message: "ACL bootstrap has not completed yet",
		})
	}
}

// updateRouteStatus updates the cluster status based on OpenShift Route state.
func (r *NomadClusterReconciler) updateRouteStatus(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) {
	if !cluster.Spec.OpenShift.Enabled || !cluster.Spec.OpenShift.Route.Enabled {
		return
	}

	route := &routev1.Route{}
	if err := r.Get(ctx, client.ObjectKey{Name: "console", Namespace: cluster.Namespace}, route); err != nil {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeRouteReady,
			Status:  metav1.ConditionFalse,
			Reason:  "RouteNotFound",
			Message: "OpenShift Route has not been created yet",
		})
		return
	}

	if len(route.Status.Ingress) > 0 && route.Status.Ingress[0].Host != "" {
		cluster.Status.RouteHost = route.Status.Ingress[0].Host
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeRouteReady,
			Status:  metav1.ConditionTrue,
			Reason:  "RouteAdmitted",
			Message: fmt.Sprintf("Route available at %s", route.Status.Ingress[0].Host),
		})
	} else {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeRouteReady,
			Status:  metav1.ConditionFalse,
			Reason:  "RouteNotAdmitted",
			Message: "Route created but not yet admitted by router",
		})
	}
}

// updateLicenseStatus updates the cluster status based on license information.
func (r *NomadClusterReconciler) updateLicenseStatus(cluster *nomadv1alpha1.NomadCluster, phaseCtx *phases.PhaseContext) {
	if phaseCtx.License != nil {
		cluster.Status.License = phaseCtx.License
		if !phaseCtx.License.Valid {
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:    nomadv1alpha1.ConditionTypeLicenseValid,
				Status:  metav1.ConditionFalse,
				Reason:  "LicenseExpired",
				Message: "Nomad Enterprise license has expired",
			})
			return
		}

		// Parse expiration time to check if expiring soon
		expirationTime, err := time.Parse(time.RFC3339, phaseCtx.License.ExpirationTime)
		if err == nil && time.Until(expirationTime) < 30*24*time.Hour {
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:    nomadv1alpha1.ConditionTypeLicenseValid,
				Status:  metav1.ConditionTrue,
				Reason:  "LicenseExpiringSoon",
				Message: fmt.Sprintf("License expires at %s (within 30 days)", phaseCtx.License.ExpirationTime),
			})
		} else {
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:    nomadv1alpha1.ConditionTypeLicenseValid,
				Status:  metav1.ConditionTrue,
				Reason:  "LicenseActive",
				Message: fmt.Sprintf("License is valid, expires at %s", phaseCtx.License.ExpirationTime),
			})
		}
	} else if phaseCtx.LicenseError != nil {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeLicenseValid,
			Status:  metav1.ConditionUnknown,
			Reason:  "LicenseCheckFailed",
			Message: fmt.Sprintf("Unable to retrieve license info: %v", phaseCtx.LicenseError),
		})
	}
}

// updateAutopilotStatus updates the cluster status based on autopilot health.
func (r *NomadClusterReconciler) updateAutopilotStatus(cluster *nomadv1alpha1.NomadCluster, phaseCtx *phases.PhaseContext) {
	if phaseCtx.Autopilot != nil {
		cluster.Status.Autopilot = phaseCtx.Autopilot
		if !phaseCtx.Autopilot.Healthy {
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:    nomadv1alpha1.ConditionTypeAutopilotHealthy,
				Status:  metav1.ConditionFalse,
				Reason:  "QuorumUnhealthy",
				Message: "Raft autopilot reports unhealthy quorum",
			})
			return
		}

		if phaseCtx.Autopilot.FailureTolerance == 0 {
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:    nomadv1alpha1.ConditionTypeAutopilotHealthy,
				Status:  metav1.ConditionFalse,
				Reason:  "NoFailureTolerance",
				Message: "Raft quorum is healthy but has no failure tolerance",
			})
		} else {
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:    nomadv1alpha1.ConditionTypeAutopilotHealthy,
				Status:  metav1.ConditionTrue,
				Reason:  "QuorumHealthy",
				Message: fmt.Sprintf("Raft quorum is healthy with failure tolerance of %d", phaseCtx.Autopilot.FailureTolerance),
			})
		}
	} else if phaseCtx.AutopilotError != nil {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:    nomadv1alpha1.ConditionTypeAutopilotHealthy,
			Status:  metav1.ConditionUnknown,
			Reason:  "AutopilotCheckFailed",
			Message: fmt.Sprintf("Unable to retrieve autopilot health: %v", phaseCtx.AutopilotError),
		})
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *NomadClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nomadv1alpha1.NomadCluster{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.Service{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&appsv1.StatefulSet{}).
		// Watch external secrets (not owned by NomadCluster) for rolling restarts
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

	// List all NomadClusters in the same namespace
	clusterList := &nomadv1alpha1.NomadClusterList{}
	if err := r.List(ctx, clusterList, client.InNamespace(secret.Namespace)); err != nil {
		return nil
	}

	var requests []reconcile.Request
	for _, cluster := range clusterList.Items {
		// Check if this cluster references the secret
		if r.clusterReferencesSecret(&cluster, secret.Name) {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      cluster.Name,
					Namespace: cluster.Namespace,
				},
			})
		}
	}

	return requests
}

// clusterReferencesSecret checks if a NomadCluster references the given secret name.
func (r *NomadClusterReconciler) clusterReferencesSecret(cluster *nomadv1alpha1.NomadCluster, secretName string) bool {
	// Check license secret (external reference only - inline creates a managed secret)
	if cluster.Spec.License.SecretName == secretName {
		return true
	}

	// Check user-provided CA secret
	if cluster.Spec.Server.TLS.CA != nil && cluster.Spec.Server.TLS.CA.SecretName == secretName {
		return true
	}

	// Check gossip secret (external reference)
	if cluster.Spec.Gossip.SecretName == secretName {
		return true
	}

	return false
}
