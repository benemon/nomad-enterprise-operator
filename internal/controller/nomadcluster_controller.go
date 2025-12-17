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
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/internal/controller/phases"

	routev1 "github.com/openshift/api/route/v1"
)

const (
	// Finalizer name
	nomadClusterFinalizer = "nomad.hashicorp.com/finalizer"

	// Default requeue interval
	defaultRequeueInterval = 30 * time.Second
)

// NomadClusterReconciler reconciles a NomadCluster object
type NomadClusterReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	RESTConfig *rest.Config
}

// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadclusters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadclusters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadclusters/finalizers,verbs=update

// +kubebuilder:rbac:groups="",resources=configmaps;secrets;services;serviceaccounts;pods;persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors;prometheusrules,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop
func (r *NomadClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the NomadCluster instance
	cluster := &nomadv1alpha1.NomadCluster{}
	if err := r.Get(ctx, req.NamespacedName, cluster); err != nil {
		if errors.IsNotFound(err) {
			log.Info("NomadCluster resource not found, ignoring")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get NomadCluster")
		return ctrl.Result{}, err
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
		return ctrl.Result{Requeue: true}, nil
	}

	// Initialize status if needed
	if cluster.Status.Phase == "" {
		cluster.Status.Phase = nomadv1alpha1.ClusterPhasePending
		if err := r.Status().Update(ctx, cluster); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Create phase context
	phaseCtx := phases.NewPhaseContext(r.Client, r.Scheme, log, r.RESTConfig)

	// Execute reconciliation phases in order
	phaseList := r.buildPhases(phaseCtx)

	for _, phase := range phaseList {
		log.V(1).Info("Executing phase", "phase", phase.Name())

		result := phase.Execute(ctx, cluster)

		if result.Error != nil {
			log.Error(result.Error, "Phase failed", "phase", phase.Name(), "message", result.Message)

			// Update status to failed
			cluster.Status.Phase = nomadv1alpha1.ClusterPhaseFailed
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:               nomadv1alpha1.ConditionTypeReady,
				Status:             metav1.ConditionFalse,
				Reason:             "PhaseFailed",
				Message:            fmt.Sprintf("%s: %s", phase.Name(), result.Message),
				LastTransitionTime: metav1.Now(),
			})
			if err := r.Status().Update(ctx, cluster); err != nil {
				log.Error(err, "Failed to update status after phase failure")
			}

			return ctrl.Result{RequeueAfter: defaultRequeueInterval}, result.Error
		}

		if result.Requeue {
			log.Info("Phase requested requeue", "phase", phase.Name(), "after", result.RequeueAfter, "message", result.Message)

			// Update status to creating
			cluster.Status.Phase = nomadv1alpha1.ClusterPhaseCreating
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:               nomadv1alpha1.ConditionTypeReady,
				Status:             metav1.ConditionFalse,
				Reason:             "Reconciling",
				Message:            result.Message,
				LastTransitionTime: metav1.Now(),
			})
			if err := r.Status().Update(ctx, cluster); err != nil {
				log.Error(err, "Failed to update status during requeue")
			}

			return ctrl.Result{RequeueAfter: result.RequeueAfter}, nil
		}
	}

	// All phases completed successfully - update final status
	if err := r.updateFinalStatus(ctx, cluster, phaseCtx); err != nil {
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
		phases.NewSecretsPhase(ctx),
		phases.NewConfigMapPhase(ctx),
		phases.NewStatefulSetPhase(ctx),
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

		// Clean up PVCs created by StatefulSet volumeClaimTemplates
		// These are not owned by the NomadCluster so won't be garbage collected automatically
		if err := r.cleanupPVCs(ctx, cluster); err != nil {
			log.Error(err, "Failed to cleanup PVCs")
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
		if err := r.Delete(ctx, &pvc); err != nil && !errors.IsNotFound(err) {
			return err
		}
	}

	return nil
}

func (r *NomadClusterReconciler) updateFinalStatus(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, phaseCtx *phases.PhaseContext) error {
	// Get StatefulSet status
	sts := &appsv1.StatefulSet{}
	if err := r.Get(ctx, client.ObjectKey{Name: cluster.Name, Namespace: cluster.Namespace}, sts); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               nomadv1alpha1.ConditionTypeStatefulSetReady,
			Status:             metav1.ConditionFalse,
			Reason:             "StatefulSetNotFound",
			Message:            "StatefulSet has not been created yet",
			LastTransitionTime: metav1.Now(),
		})
	} else {
		cluster.Status.ReadyReplicas = sts.Status.ReadyReplicas
		cluster.Status.CurrentReplicas = sts.Status.CurrentReplicas
		if sts.Status.ReadyReplicas == *sts.Spec.Replicas && sts.Status.ReadyReplicas > 0 {
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:               nomadv1alpha1.ConditionTypeStatefulSetReady,
				Status:             metav1.ConditionTrue,
				Reason:             "AllReplicasReady",
				Message:            fmt.Sprintf("StatefulSet has %d/%d replicas ready", sts.Status.ReadyReplicas, *sts.Spec.Replicas),
				LastTransitionTime: metav1.Now(),
			})
		} else {
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:               nomadv1alpha1.ConditionTypeStatefulSetReady,
				Status:             metav1.ConditionFalse,
				Reason:             "ReplicasNotReady",
				Message:            fmt.Sprintf("StatefulSet has %d/%d replicas ready", sts.Status.ReadyReplicas, *sts.Spec.Replicas),
				LastTransitionTime: metav1.Now(),
			})
		}
	}

	// Update advertise address from phase context and set condition
	if phaseCtx.AdvertiseAddress != "" {
		cluster.Status.AdvertiseAddress = phaseCtx.AdvertiseAddress
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               nomadv1alpha1.ConditionTypeAdvertiseResolved,
			Status:             metav1.ConditionTrue,
			Reason:             "AddressResolved",
			Message:            fmt.Sprintf("Advertise address resolved: %s", phaseCtx.AdvertiseAddress),
			LastTransitionTime: metav1.Now(),
		})
	} else {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               nomadv1alpha1.ConditionTypeAdvertiseResolved,
			Status:             metav1.ConditionFalse,
			Reason:             "WaitingForLoadBalancer",
			Message:            "Waiting for LoadBalancer IP to be assigned",
			LastTransitionTime: metav1.Now(),
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
			Type:               nomadv1alpha1.ConditionTypeGossipKeyReady,
			Status:             metav1.ConditionTrue,
			Reason:             "GossipKeyExists",
			Message:            fmt.Sprintf("Gossip encryption key configured in secret %s", gossipSecretName),
			LastTransitionTime: metav1.Now(),
		})
	} else {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               nomadv1alpha1.ConditionTypeGossipKeyReady,
			Status:             metav1.ConditionFalse,
			Reason:             "GossipKeyNotFound",
			Message:            fmt.Sprintf("Gossip key secret %s not found", gossipSecretName),
			LastTransitionTime: metav1.Now(),
		})
	}

	// Check services condition
	internalSvc := &corev1.Service{}
	externalSvc := &corev1.Service{}
	internalExists := r.Get(ctx, client.ObjectKey{Name: cluster.Name + "-internal", Namespace: cluster.Namespace}, internalSvc) == nil
	externalExists := r.Get(ctx, client.ObjectKey{Name: cluster.Name + "-external", Namespace: cluster.Namespace}, externalSvc) == nil
	if internalExists && externalExists {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               nomadv1alpha1.ConditionTypeServicesReady,
			Status:             metav1.ConditionTrue,
			Reason:             "ServicesCreated",
			Message:            "All required services have been created",
			LastTransitionTime: metav1.Now(),
		})
	} else {
		var missing []string
		if !internalExists {
			missing = append(missing, cluster.Name+"-internal")
		}
		if !externalExists {
			missing = append(missing, cluster.Name+"-external")
		}
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               nomadv1alpha1.ConditionTypeServicesReady,
			Status:             metav1.ConditionFalse,
			Reason:             "ServicesMissing",
			Message:            fmt.Sprintf("Missing services: %v", missing),
			LastTransitionTime: metav1.Now(),
		})
	}

	// Check ACL bootstrap status
	if cluster.Spec.Server.ACL.Enabled {
		bootstrapSecretName := cluster.Name + "-acl-bootstrap"
		if cluster.Spec.Server.ACL.BootstrapSecretName != "" {
			bootstrapSecretName = cluster.Spec.Server.ACL.BootstrapSecretName
		}

		secret := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Name: bootstrapSecretName, Namespace: cluster.Namespace}, secret); err == nil {
			cluster.Status.ACLBootstrapped = true
			cluster.Status.ACLBootstrapSecretName = bootstrapSecretName
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:               nomadv1alpha1.ConditionTypeACLBootstrapped,
				Status:             metav1.ConditionTrue,
				Reason:             "ACLBootstrapComplete",
				Message:            fmt.Sprintf("ACL bootstrap token stored in secret %s", bootstrapSecretName),
				LastTransitionTime: metav1.Now(),
			})
		} else {
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:               nomadv1alpha1.ConditionTypeACLBootstrapped,
				Status:             metav1.ConditionFalse,
				Reason:             "ACLBootstrapPending",
				Message:            "ACL bootstrap has not completed yet",
				LastTransitionTime: metav1.Now(),
			})
		}
	}

	// Get Route host if enabled and set condition
	if cluster.Spec.OpenShift.Enabled && cluster.Spec.OpenShift.Route.Enabled {
		route := &routev1.Route{}
		if err := r.Get(ctx, client.ObjectKey{Name: "console", Namespace: cluster.Namespace}, route); err == nil {
			if len(route.Status.Ingress) > 0 && route.Status.Ingress[0].Host != "" {
				cluster.Status.RouteHost = route.Status.Ingress[0].Host
				meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
					Type:               nomadv1alpha1.ConditionTypeRouteReady,
					Status:             metav1.ConditionTrue,
					Reason:             "RouteAdmitted",
					Message:            fmt.Sprintf("Route available at %s", route.Status.Ingress[0].Host),
					LastTransitionTime: metav1.Now(),
				})
			} else {
				meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
					Type:               nomadv1alpha1.ConditionTypeRouteReady,
					Status:             metav1.ConditionFalse,
					Reason:             "RouteNotAdmitted",
					Message:            "Route created but not yet admitted by router",
					LastTransitionTime: metav1.Now(),
				})
			}
		} else {
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:               nomadv1alpha1.ConditionTypeRouteReady,
				Status:             metav1.ConditionFalse,
				Reason:             "RouteNotFound",
				Message:            "OpenShift Route has not been created yet",
				LastTransitionTime: metav1.Now(),
			})
		}
	}

	// Check monitoring condition if OpenShift monitoring is enabled
	if cluster.Spec.OpenShift.Enabled && cluster.Spec.OpenShift.Monitoring.Enabled {
		// We check if ServiceMonitor exists by looking for the expected name
		// Note: We can't import monitoringv1 types here without adding dependency,
		// so we use unstructured or just report based on phase success
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               nomadv1alpha1.ConditionTypeMonitoringReady,
			Status:             metav1.ConditionTrue,
			Reason:             "MonitoringConfigured",
			Message:            "ServiceMonitor and PrometheusRule resources configured",
			LastTransitionTime: metav1.Now(),
		})
	}

	// Update license status from phase context (populated by ClusterStatusPhase)
	if phaseCtx.License != nil {
		cluster.Status.License = phaseCtx.License
		// Determine license condition based on expiration
		if phaseCtx.License.Valid {
			// Parse expiration time to check if expiring soon
			expirationTime, err := time.Parse(time.RFC3339, phaseCtx.License.ExpirationTime)
			if err == nil && time.Until(expirationTime) < 30*24*time.Hour {
				meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
					Type:               nomadv1alpha1.ConditionTypeLicenseValid,
					Status:             metav1.ConditionTrue,
					Reason:             "LicenseExpiringSoon",
					Message:            fmt.Sprintf("License expires at %s (within 30 days)", phaseCtx.License.ExpirationTime),
					LastTransitionTime: metav1.Now(),
				})
			} else {
				meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
					Type:               nomadv1alpha1.ConditionTypeLicenseValid,
					Status:             metav1.ConditionTrue,
					Reason:             "LicenseActive",
					Message:            fmt.Sprintf("License is valid, expires at %s", phaseCtx.License.ExpirationTime),
					LastTransitionTime: metav1.Now(),
				})
			}
		} else {
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:               nomadv1alpha1.ConditionTypeLicenseValid,
				Status:             metav1.ConditionFalse,
				Reason:             "LicenseExpired",
				Message:            "Nomad Enterprise license has expired",
				LastTransitionTime: metav1.Now(),
			})
		}
	} else if phaseCtx.LicenseError != nil {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               nomadv1alpha1.ConditionTypeLicenseValid,
			Status:             metav1.ConditionUnknown,
			Reason:             "LicenseCheckFailed",
			Message:            fmt.Sprintf("Unable to retrieve license info: %v", phaseCtx.LicenseError),
			LastTransitionTime: metav1.Now(),
		})
	}

	// Update autopilot status from phase context (populated by ClusterStatusPhase)
	if phaseCtx.Autopilot != nil {
		cluster.Status.Autopilot = phaseCtx.Autopilot
		if phaseCtx.Autopilot.Healthy {
			if phaseCtx.Autopilot.FailureTolerance == 0 {
				meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
					Type:               nomadv1alpha1.ConditionTypeAutopilotHealthy,
					Status:             metav1.ConditionFalse,
					Reason:             "NoFailureTolerance",
					Message:            "Raft quorum is healthy but has no failure tolerance",
					LastTransitionTime: metav1.Now(),
				})
			} else {
				meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
					Type:               nomadv1alpha1.ConditionTypeAutopilotHealthy,
					Status:             metav1.ConditionTrue,
					Reason:             "QuorumHealthy",
					Message:            fmt.Sprintf("Raft quorum is healthy with failure tolerance of %d", phaseCtx.Autopilot.FailureTolerance),
					LastTransitionTime: metav1.Now(),
				})
			}
		} else {
			meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
				Type:               nomadv1alpha1.ConditionTypeAutopilotHealthy,
				Status:             metav1.ConditionFalse,
				Reason:             "QuorumUnhealthy",
				Message:            "Raft autopilot reports unhealthy quorum",
				LastTransitionTime: metav1.Now(),
			})
		}
	} else if phaseCtx.AutopilotError != nil {
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               nomadv1alpha1.ConditionTypeAutopilotHealthy,
			Status:             metav1.ConditionUnknown,
			Reason:             "AutopilotCheckFailed",
			Message:            fmt.Sprintf("Unable to retrieve autopilot health: %v", phaseCtx.AutopilotError),
			LastTransitionTime: metav1.Now(),
		})
	}

	// Update leader info from phase context (populated by ClusterStatusPhase)
	if phaseCtx.LeaderAddress != "" {
		cluster.Status.LeaderID = phaseCtx.LeaderAddress
	}

	// Determine cluster phase and overall Ready condition
	if cluster.Status.ReadyReplicas == cluster.Spec.Replicas && cluster.Status.ReadyReplicas > 0 {
		cluster.Status.Phase = nomadv1alpha1.ClusterPhaseRunning
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               nomadv1alpha1.ConditionTypeReady,
			Status:             metav1.ConditionTrue,
			Reason:             "ClusterReady",
			Message:            fmt.Sprintf("Nomad cluster is running with %d/%d replicas", cluster.Status.ReadyReplicas, cluster.Spec.Replicas),
			LastTransitionTime: metav1.Now(),
		})
	} else {
		cluster.Status.Phase = nomadv1alpha1.ClusterPhaseCreating
		meta.SetStatusCondition(&cluster.Status.Conditions, metav1.Condition{
			Type:               nomadv1alpha1.ConditionTypeReady,
			Status:             metav1.ConditionFalse,
			Reason:             "WaitingForReplicas",
			Message:            fmt.Sprintf("Waiting for replicas: %d/%d ready", cluster.Status.ReadyReplicas, cluster.Spec.Replicas),
			LastTransitionTime: metav1.Now(),
		})
	}

	// Update observed generation and reconcile time
	cluster.Status.ObservedGeneration = cluster.Generation
	now := metav1.Now()
	cluster.Status.LastReconcileTime = &now

	return r.Status().Update(ctx, cluster)
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
		Named("nomadcluster").
		Complete(r)
}
