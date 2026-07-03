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
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/internal/controller/phases"
	"github.com/hashicorp/nomad-enterprise-operator/internal/metrics"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
)

const (
	snapshotFinalizer      = "nomad.hashicorp.com/snapshot-cleanup"
	snapshotRequeueDefault = 30 * time.Second
)

// NomadSnapshotReconciler reconciles a NomadSnapshot object.
// Ensure idiom: this controller uses controllerutil.CreateOrUpdate; the
// cluster phases hand-roll Get-then-write. Match the file you edit.
type NomadSnapshotReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	// NomadClientFactory overrides Nomad API client construction for
	// tests (same shape as NomadClusterReconciler). nil in production —
	// nomad.NewClient wrapped with the D4b request counter is used.
	NomadClientFactory func(cfg nomad.ClientConfig) (nomad.NomadAPI, error)
}

// Deterministic names of the resources a NomadSnapshot owns (neo-08p):
// each is built in one place so construction sites and status-write
// sites cannot disagree.
func snapshotJobName(s *nomadv1alpha1.NomadSnapshot) string       { return s.Name + "-snapshot" }
func snapshotAgentName(s *nomadv1alpha1.NomadSnapshot) string     { return s.Name + "-snapshot-agent" }
func snapshotConfigMapName(s *nomadv1alpha1.NomadSnapshot) string { return s.Name + "-snapshot-config" }
func snapshotTokenName(s *nomadv1alpha1.NomadSnapshot) string     { return s.Name + "-snapshot-token" }
func snapshotPVCName(s *nomadv1alpha1.NomadSnapshot) string       { return s.Name + "-snapshots" }

// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadsnapshots,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadsnapshots/status,verbs=patch
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadsnapshots/finalizers,verbs=update
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadclusters,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;delete

// Reconcile handles NomadSnapshot reconciliation.
//
// Status-write contract: every helper mutating snapshot.Status issues
// its own Status().Patch with a patchBase snapshotted just before the
// mutation — the final patch is NOT a catch-all for earlier writes.
func (r *NomadSnapshotReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the NomadSnapshot instance
	snapshot := &nomadv1alpha1.NomadSnapshot{}
	if err := r.Get(ctx, req.NamespacedName, snapshot); err != nil {
		if k8serrors.IsNotFound(err) {
			log.Info("NomadSnapshot resource not found, ignoring")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get NomadSnapshot")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !snapshot.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, snapshot)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(snapshot, snapshotFinalizer) {
		controllerutil.AddFinalizer(snapshot, snapshotFinalizer)
		if err := r.Update(ctx, snapshot); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	// Resolve cluster reference
	clusterNamespace := snapshot.Namespace
	if snapshot.Spec.ClusterRef.Namespace != "" {
		clusterNamespace = snapshot.Spec.ClusterRef.Namespace
	}

	// Verify the referenced NomadCluster exists
	cluster := &nomadv1alpha1.NomadCluster{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      snapshot.Spec.ClusterRef.Name,
		Namespace: clusterNamespace,
	}, cluster); err != nil {
		if k8serrors.IsNotFound(err) {
			log.Error(err, "Referenced NomadCluster not found", "cluster", snapshot.Spec.ClusterRef.Name)
			patchBase := snapshot.DeepCopy()
			r.setCondition(snapshot, metav1.Condition{
				Type:    "Ready",
				Status:  metav1.ConditionFalse,
				Reason:  "ClusterNotFound",
				Message: fmt.Sprintf("Referenced NomadCluster %s not found", snapshot.Spec.ClusterRef.Name),
			})
			if err := r.Status().Patch(ctx, snapshot, client.MergeFrom(patchBase)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: snapshotRequeueDefault}, nil
		}
		return ctrl.Result{}, err
	}

	// Check if cluster has ACL bootstrapped
	if !cluster.Status.ACLBootstrapped {
		log.Info("Waiting for NomadCluster ACL bootstrap", "cluster", cluster.Name)
		patchBase := snapshot.DeepCopy()
		r.setCondition(snapshot, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "WaitingForACLBootstrap",
			Message: "Waiting for NomadCluster ACL bootstrap to complete",
		})
		if err := r.Status().Patch(ctx, snapshot, client.MergeFrom(patchBase)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: snapshotRequeueDefault}, nil
	}

	// Get the cluster's management token (C4 / neo-pfx): the bootstrap
	// token is sealed after minting it, so snapshot-agent policy/token
	// creation authenticates with the management token. The
	// Secret appears one reconcile after ACL bootstrap — wait for it.
	managementSecretName := phases.OperatorManagementSecretName(cluster.Name)
	managementSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      managementSecretName,
		Namespace: clusterNamespace,
	}, managementSecret); err != nil {
		log.Info("Waiting for cluster management token secret", "secret", managementSecretName)
		patchBase := snapshot.DeepCopy()
		r.setCondition(snapshot, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "WaitingForManagementToken",
			Message: fmt.Sprintf("Waiting for cluster management token secret %s", managementSecretName),
		})
		if err := r.Status().Patch(ctx, snapshot, client.MergeFrom(patchBase)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: snapshotRequeueDefault}, nil
	}

	managementToken := string(managementSecret.Data[phases.SecretKeySecretID])
	if managementToken == "" {
		log.Info("Management token secret has no secret-id", "secret", managementSecretName)
		return ctrl.Result{RequeueAfter: snapshotRequeueDefault}, nil
	}

	// Build Nomad address for the snapshot agent deployment
	internalAddr := nomad.InternalServiceAddress(cluster.Name, clusterNamespace, true)

	// Create or get a dedicated ACL token for the snapshot agent.
	// The token is scoped to operator:write which grants snapshot-save and
	// license-read capabilities (required by the snapshot agent).
	snapshotToken, err := r.ensureSnapshotToken(ctx, snapshot, cluster, clusterNamespace, managementToken)
	if err != nil {
		log.Error(err, "Failed to ensure snapshot agent token")
		patchBase := snapshot.DeepCopy()
		r.setCondition(snapshot, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "TokenCreationFailed",
			Message: fmt.Sprintf("Failed to create snapshot agent token: %v", err),
		})
		if err := r.Status().Patch(ctx, snapshot, client.MergeFrom(patchBase)); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: snapshotRequeueDefault}, nil
	}

	// Store snapshot agent token in a Secret for the Deployment to reference
	if err := r.reconcileTokenSecret(ctx, snapshot, snapshotToken); err != nil {
		log.Error(err, "Failed to reconcile token secret")
		return ctrl.Result{}, err
	}

	// Create PVC for local storage if specified
	if snapshot.Spec.Target.Local != nil {
		if err := r.reconcilePVC(ctx, snapshot); err != nil {
			log.Error(err, "Failed to reconcile PVC")
			return ctrl.Result{}, err
		}
	}

	// Generate the agent config once; the ConfigMap stores it and the
	// workload's pod template carries its checksum so config changes
	// roll the agent (AC-2.7.6a).
	agentConfig := r.generateSnapshotConfig(snapshot)
	configChecksum := phases.ConfigChecksum(map[string]string{"snapshot.hcl": agentConfig})

	// Create ConfigMap with snapshot agent config
	if err := r.reconcileConfigMap(ctx, snapshot, agentConfig); err != nil {
		log.Error(err, "Failed to reconcile ConfigMap")
		return ctrl.Result{}, err
	}

	// Schedule present: long-lived Deployment. Absent: one-shot Job
	// (interval "0"). Mode switch deletes the other mode's workload;
	// switching away from a running Job is CEL-rejected at admission.
	if snapshot.Spec.Schedule != nil {
		return r.reconcileRecurring(ctx, snapshot, cluster, internalAddr, configChecksum)
	}
	return r.reconcileOneShot(ctx, snapshot, cluster, internalAddr, configChecksum)
}

// reconcileRecurring runs the schedule-present mode: snapshot-agent
// Deployment, status from Deployment observation (AC-2.7.2 / 2.7.6).
func (r *NomadSnapshotReconciler) reconcileRecurring(
	ctx context.Context, snapshot *nomadv1alpha1.NomadSnapshot,
	cluster *nomadv1alpha1.NomadCluster, internalAddr, configChecksum string,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Mode switch: remove a leftover one-shot Job.
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name: snapshotJobName(snapshot), Namespace: snapshot.Namespace,
	}}
	if err := r.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil && !k8serrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	if err := r.reconcileDeployment(ctx, snapshot, cluster, internalAddr, configChecksum); err != nil {
		log.Error(err, "Failed to reconcile Deployment")
		return ctrl.Result{}, err
	}

	deploymentName := snapshotAgentName(snapshot)

	patchBase := snapshot.DeepCopy()
	snapshot.Status.ObservedGeneration = snapshot.Generation
	snapshot.Status.Operation = nomadv1alpha1.SnapshotOperationDeployment
	snapshot.Status.Phase = ""
	snapshot.Status.JobName = ""
	snapshot.Status.DeploymentName = deploymentName
	snapshot.Status.ConfigMapName = snapshotConfigMapName(snapshot)
	snapshot.Status.NomadAddress = internalAddr

	// Fetch deployment to get replica status
	deploy := &appsv1.Deployment{}
	if err := r.Get(ctx, types.NamespacedName{Name: deploymentName, Namespace: snapshot.Namespace}, deploy); err == nil {
		snapshot.Status.DesiredReplicas = ptr.Deref(deploy.Spec.Replicas, 1)
		snapshot.Status.ReadyReplicas = deploy.Status.ReadyReplicas
	}

	// Set condition based on deployment readiness
	if snapshot.Status.ReadyReplicas > 0 {
		r.setCondition(snapshot, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionTrue,
			Reason:  "Deployed",
			Message: "Snapshot agent deployment is running",
		})

		// The agent snapshots on its own clock; NextScheduled is the
		// operator's projection, advanced only when the previous one
		// lapses — one status write per interval, not per reconcile.
		if interval, perr := time.ParseDuration(snapshot.Spec.Schedule.Interval); perr == nil {
			if snapshot.Status.NextScheduled == nil || snapshot.Status.NextScheduled.Time.Before(time.Now()) {
				snapshot.Status.NextScheduled = &metav1.Time{Time: time.Now().Add(interval)}
			}
		}
	} else {
		r.setCondition(snapshot, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "DeploymentNotReady",
			Message: "Snapshot agent deployment is not yet ready",
		})
	}
	r.setDegraded(snapshot, false, "OperationHealthy", "")

	if err := r.Status().Patch(ctx, snapshot, client.MergeFrom(patchBase)); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// reconcileOneShot runs the schedule-absent mode: one snapshot Job,
// status from Job observation. Another snapshot needs a new CR.
func (r *NomadSnapshotReconciler) reconcileOneShot(
	ctx context.Context, snapshot *nomadv1alpha1.NomadSnapshot,
	cluster *nomadv1alpha1.NomadCluster, internalAddr, configChecksum string,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Mode switch: remove a leftover recurring Deployment.
	staleDeploy := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: snapshotAgentName(snapshot), Namespace: snapshot.Namespace,
	}}
	if err := r.Delete(ctx, staleDeploy, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil && !k8serrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	jobName := snapshotJobName(snapshot)
	job := &batchv1.Job{}
	err := r.Get(ctx, types.NamespacedName{Name: jobName, Namespace: snapshot.Namespace}, job)
	if k8serrors.IsNotFound(err) {
		if err := r.createSnapshotJob(ctx, snapshot, cluster, internalAddr, configChecksum, jobName); err != nil {
			log.Error(err, "Failed to create snapshot Job")
			return ctrl.Result{}, err
		}
		// Re-read for status observation below; NotFound just means the
		// cache hasn't caught up — the requeue covers it.
		if err := r.Get(ctx, types.NamespacedName{Name: jobName, Namespace: snapshot.Namespace}, job); err != nil && !k8serrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	} else if err != nil {
		return ctrl.Result{}, err
	}

	patchBase := snapshot.DeepCopy()
	snapshot.Status.ObservedGeneration = snapshot.Generation
	snapshot.Status.Operation = nomadv1alpha1.SnapshotOperationJob
	snapshot.Status.JobName = jobName
	snapshot.Status.ConfigMapName = snapshotConfigMapName(snapshot)
	snapshot.Status.NomadAddress = internalAddr
	snapshot.Status.DeploymentName = ""
	snapshot.Status.NextScheduled = nil
	snapshot.Status.DesiredReplicas = 0
	snapshot.Status.ReadyReplicas = 0

	// AC-2.7.5: phase from Job observation.
	wasDegraded := meta.IsStatusConditionTrue(snapshot.Status.Conditions, "Degraded")
	switch {
	case job.Name == "":
		snapshot.Status.Phase = nomadv1alpha1.SnapshotPhasePending
	case job.Status.Succeeded > 0:
		snapshot.Status.Phase = nomadv1alpha1.SnapshotPhaseSucceeded
		snapshot.Status.LastSnapshot = &nomadv1alpha1.SnapshotInfo{
			Time:   job.Status.CompletionTime,
			Status: "Success",
		}
		r.setCondition(snapshot, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionTrue,
			Reason:  "SnapshotSucceeded",
			Message: "One-shot snapshot Job completed successfully",
		})
		r.setDegraded(snapshot, false, "OperationHealthy", "")
	case jobFailed(job):
		snapshot.Status.Phase = nomadv1alpha1.SnapshotPhaseFailed
		snapshot.Status.LastSnapshot = &nomadv1alpha1.SnapshotInfo{
			Time:   &metav1.Time{Time: time.Now()},
			Status: "Failed",
			Error:  "snapshot Job exhausted its retries; see Job pod logs",
		}
		r.setCondition(snapshot, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "SnapshotFailed",
			Message: "One-shot snapshot Job failed",
		})
		// AC-2.7.8: Degraded condition emits a Warning Event, once per
		// transition into the degraded state.
		r.setDegraded(snapshot, true, "SnapshotJobFailed",
			fmt.Sprintf("Snapshot Job %s failed after exhausting retries", jobName))
		if !wasDegraded && r.Recorder != nil {
			r.Recorder.Event(snapshot, corev1.EventTypeWarning, "SnapshotDegraded",
				fmt.Sprintf("Snapshot Job %s failed after exhausting retries", jobName))
		}
	default:
		snapshot.Status.Phase = nomadv1alpha1.SnapshotPhaseRunning
		r.setCondition(snapshot, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "SnapshotRunning",
			Message: "One-shot snapshot Job is running",
		})
	}

	if err := r.Status().Patch(ctx, snapshot, client.MergeFrom(patchBase)); err != nil {
		return ctrl.Result{}, err
	}

	// Terminal phases need no requeue — the Job watch catches everything
	// in between.
	if snapshot.Status.Phase == nomadv1alpha1.SnapshotPhaseSucceeded ||
		snapshot.Status.Phase == nomadv1alpha1.SnapshotPhaseFailed {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{RequeueAfter: snapshotRequeueDefault}, nil
}

// jobFailed reports whether the Job has the terminal Failed condition.
func jobFailed(job *batchv1.Job) bool {
	for _, c := range job.Status.Conditions {
		if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// setDegraded maintains the Degraded condition (AC-2.7.8).
func (r *NomadSnapshotReconciler) setDegraded(snapshot *nomadv1alpha1.NomadSnapshot, degraded bool, reason, message string) {
	status := metav1.ConditionFalse
	if degraded {
		status = metav1.ConditionTrue
	}
	if message == "" {
		message = "Snapshot operation is healthy"
	}
	r.setCondition(snapshot, metav1.Condition{
		Type:    "Degraded",
		Status:  status,
		Reason:  reason,
		Message: message,
	})
}

// handleDeletion cleans up the Nomad ACL token and policy, then removes the finalizer.
func (r *NomadSnapshotReconciler) handleDeletion(ctx context.Context, snapshot *nomadv1alpha1.NomadSnapshot) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if controllerutil.ContainsFinalizer(snapshot, snapshotFinalizer) {
		// Best-effort cleanup of Nomad-side resources
		if snapshot.Status.TokenAccessorID != "" || snapshot.Status.PolicyName != "" {
			if err := r.cleanupNomadResources(ctx, snapshot); err != nil {
				log.Error(err, "Failed to clean up Nomad ACL resources, continuing with deletion")
			}
		}

		controllerutil.RemoveFinalizer(snapshot, snapshotFinalizer)
		if err := r.Update(ctx, snapshot); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// runNomadWithFallback mirrors phases.runNomadWithFallback with this
// controller's client config: internal Service first, one LB retry on
// network error. fn must be idempotent.
func (r *NomadSnapshotReconciler) runNomadWithFallback(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, clusterNamespace string, fn func(nomad.NomadAPI) error) error {
	nomadClient, err := r.snapshotNomadClient(ctx, cluster, clusterNamespace,
		nomad.InternalServiceAddress(cluster.Name, clusterNamespace, true))
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
	nomadClient, cerr := r.snapshotNomadClient(ctx, cluster, clusterNamespace, loadBalancerAddr)
	if cerr != nil {
		return cerr
	}
	return fn(nomadClient)
}

// snapshotNomadClient creates a Nomad client for snapshot controller operations.
// Since verify_https_client is off, only the CA cert is needed for TLS verification.
// The production path carries the D4b request counter like every other
// operator Nomad client; tests inject via NomadClientFactory.
func (r *NomadSnapshotReconciler) snapshotNomadClient(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, clusterNamespace, address string) (nomad.NomadAPI, error) {
	cfg := nomad.ClientConfig{
		Address:    address,
		TLSEnabled: true,
	}

	tlsSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      phases.TLSSecretName(cluster.Name),
		Namespace: clusterNamespace,
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

// SnapshotAgentPolicyRules defines the ACL policy for the snapshot agent.
// Requires operator:write which grants snapshot-save and license-read capabilities.
const snapshotAgentPolicyRules = `
operator {
  policy = "write"
}
`

// ensureSnapshotToken creates or retrieves a dedicated ACL token for the snapshot agent.
func (r *NomadSnapshotReconciler) ensureSnapshotToken(
	ctx context.Context, snapshot *nomadv1alpha1.NomadSnapshot,
	cluster *nomadv1alpha1.NomadCluster, clusterNamespace, authToken string,
) (string, error) {
	log := logf.FromContext(ctx)

	policyName := fmt.Sprintf("snapshot-agent-%s-%s", snapshot.Namespace, snapshot.Name)

	// One idempotent sequence against Nomad: reuse the recorded token if
	// it still exists, else upsert the policy and mint a fresh token.
	// runNomadWithFallback retries the whole sequence once via the
	// LoadBalancer on a network error (neo-6al).
	var existingSecretID string
	var newToken *nomad.ACLTokenResult
	err := r.runNomadWithFallback(ctx, cluster, clusterNamespace, func(nomadClient nomad.NomadAPI) error {
		if snapshot.Status.TokenAccessorID != "" {
			token, terr := nomadClient.GetACLToken(authToken, snapshot.Status.TokenAccessorID)
			if terr != nil {
				return terr
			}
			if token != nil {
				existingSecretID = token.SecretID
				return nil
			}
			log.Info("Existing token not found, creating new one", "accessor", snapshot.Status.TokenAccessorID)
		}

		if perr := nomadClient.CreateACLPolicy(authToken, policyName, "Snapshot agent policy for "+snapshot.Name, snapshotAgentPolicyRules); perr != nil {
			return fmt.Errorf("failed to create snapshot agent policy: %w", perr)
		}
		t, terr := nomadClient.CreateACLTokenWithPolicies(authToken, policyName, []string{policyName})
		if terr != nil {
			return fmt.Errorf("failed to create snapshot agent token: %w", terr)
		}
		newToken = t
		return nil
	})
	if err != nil {
		return "", err
	}
	if existingSecretID != "" {
		log.V(1).Info("Using existing snapshot agent token", "accessor", snapshot.Status.TokenAccessorID)
		return existingSecretID, nil
	}

	log.Info("Created snapshot agent token", "accessor", newToken.AccessorID, "policy", policyName)

	// Update status with accessor ID and policy name for cleanup
	patchBase := snapshot.DeepCopy()
	snapshot.Status.TokenAccessorID = newToken.AccessorID
	snapshot.Status.PolicyName = policyName
	if err := r.Status().Patch(ctx, snapshot, client.MergeFrom(patchBase)); err != nil {
		return "", fmt.Errorf("failed to patch status with token accessor: %w", err)
	}

	return newToken.SecretID, nil
}

// cleanupNomadResources deletes the snapshot agent's ACL token and policy from Nomad.
func (r *NomadSnapshotReconciler) cleanupNomadResources(ctx context.Context, snapshot *nomadv1alpha1.NomadSnapshot) error {
	log := logf.FromContext(ctx)

	clusterNamespace := snapshot.Namespace
	if snapshot.Spec.ClusterRef.Namespace != "" {
		clusterNamespace = snapshot.Spec.ClusterRef.Namespace
	}

	cluster := &nomadv1alpha1.NomadCluster{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      snapshot.Spec.ClusterRef.Name,
		Namespace: clusterNamespace,
	}, cluster); err != nil {
		return fmt.Errorf("failed to get cluster: %w", err)
	}

	// Prefer the management token (C4 / neo-pfx); fall back to the
	// bootstrap token — during cluster teardown the management token may
	// already be revoked while the bootstrap Secret survives until the
	// cluster finalizer's last step (C3).
	authToken := ""
	managementSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      phases.OperatorManagementSecretName(cluster.Name),
		Namespace: clusterNamespace,
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
			Namespace: clusterNamespace,
		}, bootstrapSecret); err != nil {
			return fmt.Errorf("failed to get a cleanup auth token (management and bootstrap secrets both unavailable): %w", err)
		}
		authToken = string(bootstrapSecret.Data[phases.SecretKeySecretID])
	}

	internalAddr := nomad.InternalServiceAddress(cluster.Name, clusterNamespace, true)
	nomadClient, err := r.snapshotNomadClient(ctx, cluster, clusterNamespace, internalAddr)
	if err != nil {
		return err
	}

	// Delete token
	if snapshot.Status.TokenAccessorID != "" {
		if err := nomadClient.DeleteACLToken(authToken, snapshot.Status.TokenAccessorID); err != nil {
			if !nomad.IsNetworkError(err) {
				log.Error(err, "Failed to delete snapshot agent token")
			} else if loadBalancerAddr := nomad.LoadBalancerAddress(cluster.Status.AdvertiseAddress, true); loadBalancerAddr != "" {
				if lbClient, lbErr := r.snapshotNomadClient(ctx, cluster, clusterNamespace, loadBalancerAddr); lbErr == nil {
					_ = lbClient.DeleteACLToken(authToken, snapshot.Status.TokenAccessorID)
				}
			}
		} else {
			log.Info("Deleted snapshot agent token", "accessor", snapshot.Status.TokenAccessorID)
		}
	}

	// Delete policy
	if snapshot.Status.PolicyName != "" {
		if err := nomadClient.DeleteACLPolicy(authToken, snapshot.Status.PolicyName); err != nil {
			if !nomad.IsNetworkError(err) {
				log.Error(err, "Failed to delete snapshot agent policy")
			} else if loadBalancerAddr := nomad.LoadBalancerAddress(cluster.Status.AdvertiseAddress, true); loadBalancerAddr != "" {
				if lbClient, lbErr := r.snapshotNomadClient(ctx, cluster, clusterNamespace, loadBalancerAddr); lbErr == nil {
					_ = lbClient.DeleteACLPolicy(authToken, snapshot.Status.PolicyName)
				}
			}
		} else {
			log.Info("Deleted snapshot agent policy", "policy", snapshot.Status.PolicyName)
		}
	}

	return nil
}

// reconcileConfigMap creates or updates the snapshot agent ConfigMap
func (r *NomadSnapshotReconciler) reconcileConfigMap(ctx context.Context, snapshot *nomadv1alpha1.NomadSnapshot, config string) error {
	configMapName := snapshotConfigMapName(snapshot)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: snapshot.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, cm, func() error {
		cm.Data = map[string]string{
			"snapshot.hcl": config,
		}
		return controllerutil.SetControllerReference(snapshot, cm, r.Scheme)
	})

	return err
}

// generateSnapshotConfig renders the agent HCL. Target stanzas are
// mode-agnostic; only the interval differs ("0" = one-shot).
func (r *NomadSnapshotReconciler) generateSnapshotConfig(snapshot *nomadv1alpha1.NomadSnapshot) string {
	var config string
	if snapshot.Spec.Schedule == nil {
		// One-shot: no retention pruning — a single explicit snapshot
		// must never delete existing artifacts in the target.
		config = `snapshot {
  interval = "0"
}
`
	} else {
		interval := snapshot.Spec.Schedule.Interval
		if interval == "" {
			interval = "1h"
		}
		retain := snapshot.Spec.Schedule.Retain
		if retain == 0 {
			retain = 24
		}

		config = fmt.Sprintf(`snapshot {
  interval         = "%s"
  retain           = %d
  stale            = %t
  deregister_after = "8h"
}
`, interval, retain, snapshot.Spec.Schedule.Stale)
	}

	// Add storage backend config
	if snapshot.Spec.Target.S3 != nil {
		s3 := snapshot.Spec.Target.S3
		config += fmt.Sprintf(`
aws_s3 {
  bucket              = "%s"
  region              = "%s"
`, s3.Bucket, s3.Region)
		if s3.Endpoint != "" {
			config += fmt.Sprintf(`  endpoint            = "%s"
`, s3.Endpoint)
		}
		config += fmt.Sprintf(`  s3_force_path_style = %t
}
`, s3.ForcePathStyle)
	}

	if snapshot.Spec.Target.GCS != nil {
		gcs := snapshot.Spec.Target.GCS
		config += fmt.Sprintf(`
google_cloud_storage {
  bucket = "%s"
}
`, gcs.Bucket)
	}

	if snapshot.Spec.Target.Azure != nil {
		azure := snapshot.Spec.Target.Azure
		config += fmt.Sprintf(`
azure_blob_storage {
  container_name = "%s"
  account_name   = "%s"
}
`, azure.Container, azure.AccountName)
	}

	if snapshot.Spec.Target.Local != nil {
		local := snapshot.Spec.Target.Local
		path := local.Path
		if path == "" {
			path = "/snapshots"
		}
		config += fmt.Sprintf(`
local_storage {
  path = "%s"
}
`, path)
	}

	return config
}

// reconcileTokenSecret creates or updates the Secret holding the snapshot agent's Nomad token.
// Uses the same key convention as the bootstrap and operator-status Secrets.
func (r *NomadSnapshotReconciler) reconcileTokenSecret(ctx context.Context, snapshot *nomadv1alpha1.NomadSnapshot, nomadToken string) error {
	secretName := snapshotTokenName(snapshot)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: snapshot.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		secret.Type = corev1.SecretTypeOpaque
		secret.Data = map[string][]byte{
			phases.SecretKeySecretID:   []byte(nomadToken),
			phases.SecretKeyAccessorID: []byte(snapshot.Status.TokenAccessorID),
		}
		return controllerutil.SetControllerReference(snapshot, secret, r.Scheme)
	})

	return err
}

// snapshotAgentLabels returns the selector labels for the snapshot
// agent workload (shared by the Deployment and Job pod templates).
// managed-by matches phases.GetLabels — one operator, one identity
// (neo-e3y); a test pins the two helpers to the same value.
func snapshotAgentLabels(snapshot *nomadv1alpha1.NomadSnapshot) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "nomad-snapshot-agent",
		"app.kubernetes.io/instance":   snapshot.Name,
		"app.kubernetes.io/managed-by": "nomad-operator",
	}
}

// buildAgentPodTemplate builds the snapshot agent pod template used by
// BOTH modes (AC-2.7.4: consistent target handling across modes). The
// config checksum annotation makes spec-derived config changes roll the
// recurring Deployment (AC-2.7.6a); it is inert on the immutable Job.
func (r *NomadSnapshotReconciler) buildAgentPodTemplate(
	snapshot *nomadv1alpha1.NomadSnapshot, cluster *nomadv1alpha1.NomadCluster,
	nomadAddr, configChecksum string,
) corev1.PodTemplateSpec {
	configMapName := snapshotConfigMapName(snapshot)
	tokenSecretName := snapshotTokenName(snapshot)

	// Image defaults set via kubebuilder tags on ImageSpec; digest
	// pinning takes precedence (neo-4xj)
	image := phases.ImageRef(cluster)

	template := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels:      snapshotAgentLabels(snapshot),
			Annotations: map[string]string{"checksum/config": configChecksum},
		},
		Spec: corev1.PodSpec{
			// PSS restricted (neo-8xu), same profile as the server pods.
			SecurityContext: phases.PodSecurityContext(cluster.Spec.OpenShift.Enabled),
			Containers: []corev1.Container{
				{
					Name:  "snapshot-agent",
					Image: image,
					Command: []string{
						"nomad", "operator", "snapshot", "agent",
						"/config/snapshot.hcl",
					},
					Env: []corev1.EnvVar{
						{
							Name:  "NOMAD_ADDR",
							Value: nomadAddr,
						},
						{
							Name:  "NOMAD_CACERT",
							Value: "/tls/ca.crt",
						},
						{
							Name: "NOMAD_TOKEN",
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: tokenSecretName,
									},
									Key: phases.SecretKeySecretID,
								},
							},
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						// Snapshot staging before upload happens under
						// /tmp; the root filesystem is read-only.
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
					Resources:       snapshot.Spec.Resources,
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
								Name: configMapName,
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
			NodeSelector: snapshot.Spec.NodeSelector,
			Tolerations:  snapshot.Spec.Tolerations,
		},
	}

	// Add storage credentials if specified
	r.addStorageCredentials(snapshot, &template.Spec)

	// Add local PVC if specified
	if snapshot.Spec.Target.Local != nil {
		r.addLocalStorage(snapshot, &template.Spec)
	}

	return template
}

// reconcileDeployment creates or updates the snapshot agent Deployment
func (r *NomadSnapshotReconciler) reconcileDeployment(ctx context.Context, snapshot *nomadv1alpha1.NomadSnapshot, cluster *nomadv1alpha1.NomadCluster, nomadAddr, configChecksum string) error {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      snapshotAgentName(snapshot),
			Namespace: snapshot.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, deploy, func() error {
		deploy.Spec = appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: snapshotAgentLabels(snapshot),
			},
			Template: r.buildAgentPodTemplate(snapshot, cluster, nomadAddr, configChecksum),
		}
		return controllerutil.SetControllerReference(snapshot, deploy, r.Scheme)
	})

	return err
}

// createSnapshotJob creates the one-shot snapshot Job (AC-2.7.1). Jobs
// are immutable, so this is create-only: the Job observed at call time
// did not exist. RestartPolicy OnFailure + backoffLimit bound retries;
// exhaustion surfaces as phase=Failed via jobFailed.
func (r *NomadSnapshotReconciler) createSnapshotJob(
	ctx context.Context, snapshot *nomadv1alpha1.NomadSnapshot,
	cluster *nomadv1alpha1.NomadCluster, nomadAddr, configChecksum, jobName string,
) error {
	template := r.buildAgentPodTemplate(snapshot, cluster, nomadAddr, configChecksum)
	template.Spec.RestartPolicy = corev1.RestartPolicyOnFailure

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: snapshot.Namespace,
			Labels:    snapshotAgentLabels(snapshot),
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: ptr.To(int32(3)),
			Template:     template,
		},
	}

	if err := controllerutil.SetControllerReference(snapshot, job, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, job); err != nil && !k8serrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// addStorageCredentials adds environment variables from credentials secrets
func (r *NomadSnapshotReconciler) addStorageCredentials(snapshot *nomadv1alpha1.NomadSnapshot, podSpec *corev1.PodSpec) {
	container := &podSpec.Containers[0]

	if snapshot.Spec.Target.S3 != nil && snapshot.Spec.Target.S3.CredentialsSecretRef != nil {
		container.Env = append(container.Env,
			corev1.EnvVar{
				Name: "AWS_ACCESS_KEY_ID",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: *snapshot.Spec.Target.S3.CredentialsSecretRef,
						Key:                  "AWS_ACCESS_KEY_ID",
					},
				},
			},
			corev1.EnvVar{
				Name: "AWS_SECRET_ACCESS_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: *snapshot.Spec.Target.S3.CredentialsSecretRef,
						Key:                  "AWS_SECRET_ACCESS_KEY",
					},
				},
			},
		)
	}

	if snapshot.Spec.Target.GCS != nil && snapshot.Spec.Target.GCS.CredentialsSecretRef != nil {
		// Mount GCP credentials as a file
		podSpec.Volumes = append(podSpec.Volumes, corev1.Volume{
			Name: "gcp-credentials",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: snapshot.Spec.Target.GCS.CredentialsSecretRef.Name,
				},
			},
		})
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
			Name:      "gcp-credentials",
			MountPath: "/gcp",
			ReadOnly:  true,
		})
		container.Env = append(container.Env, corev1.EnvVar{
			Name:  "GOOGLE_APPLICATION_CREDENTIALS",
			Value: "/gcp/GOOGLE_APPLICATION_CREDENTIALS",
		})
	}

	if snapshot.Spec.Target.Azure != nil && snapshot.Spec.Target.Azure.CredentialsSecretRef != nil {
		container.Env = append(container.Env, corev1.EnvVar{
			Name: "AZURE_BLOB_ACCOUNT_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: *snapshot.Spec.Target.Azure.CredentialsSecretRef,
					Key:                  "AZURE_BLOB_ACCOUNT_KEY",
				},
			},
		})
	}
}

// reconcilePVC creates or updates the PVC for local snapshot storage
func (r *NomadSnapshotReconciler) reconcilePVC(ctx context.Context, snapshot *nomadv1alpha1.NomadSnapshot) error {
	local := snapshot.Spec.Target.Local
	pvcName := snapshotPVCName(snapshot)

	// Parse size
	size := local.Size
	if size == "" {
		size = "10Gi"
	}
	quantity, err := resource.ParseQuantity(size)
	if err != nil {
		return fmt.Errorf("invalid PVC size %q: %w", size, err)
	}

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pvcName,
			Namespace: snapshot.Namespace,
		},
	}

	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, pvc, func() error {
		// Only set spec on create — PVC spec is immutable. Guarded on
		// ResourceVersion (set on every persisted object) rather than
		// CreationTimestamp, which some clients (notably the fake test
		// client) do not populate (neo-tih).
		if pvc.ResourceVersion == "" {
			pvc.Spec = corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{
					corev1.ReadWriteOnce,
				},
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceStorage: quantity,
					},
				},
				StorageClassName: local.StorageClassName,
			}
		}
		return controllerutil.SetControllerReference(snapshot, pvc, r.Scheme)
	})

	return err
}

// addLocalStorage adds PVC mount for local storage
func (r *NomadSnapshotReconciler) addLocalStorage(snapshot *nomadv1alpha1.NomadSnapshot, podSpec *corev1.PodSpec) {
	local := snapshot.Spec.Target.Local
	path := local.Path
	if path == "" {
		path = "/snapshots"
	}

	pvcName := snapshotPVCName(snapshot)

	podSpec.Volumes = append(podSpec.Volumes, corev1.Volume{
		Name: "snapshots",
		VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: pvcName,
			},
		},
	})

	container := &podSpec.Containers[0]
	container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
		Name:      "snapshots",
		MountPath: path,
	})
}

// setCondition updates a condition, leaving LastTransitionTime to
// meta.SetStatusCondition — hand-stamping metav1.Now() churns steady
// state.
func (r *NomadSnapshotReconciler) setCondition(snapshot *nomadv1alpha1.NomadSnapshot, condition metav1.Condition) {
	meta.SetStatusCondition(&snapshot.Status.Conditions, condition)
}

// SetupWithManager sets up the controller with the Manager
func (r *NomadSnapshotReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nomadv1alpha1.NomadSnapshot{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.PersistentVolumeClaim{}).
		Owns(&appsv1.Deployment{}).
		Owns(&batchv1.Job{}).
		Named("nomadsnapshot").
		Complete(r)
}
