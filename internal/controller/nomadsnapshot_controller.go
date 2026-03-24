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
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
)

const (
	snapshotFinalizer      = "nomad.hashicorp.com/snapshot-cleanup"
	snapshotRequeueDefault = 30 * time.Second
)

// NomadSnapshotReconciler reconciles a NomadSnapshot object
type NomadSnapshotReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadsnapshots,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadsnapshots/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadsnapshots/finalizers,verbs=update
// +kubebuilder:rbac:groups=nomad.hashicorp.com,resources=nomadclusters,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps;secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete

// Reconcile handles NomadSnapshot reconciliation
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
			r.setCondition(snapshot, metav1.Condition{
				Type:    "Ready",
				Status:  metav1.ConditionFalse,
				Reason:  "ClusterNotFound",
				Message: fmt.Sprintf("Referenced NomadCluster %s not found", snapshot.Spec.ClusterRef.Name),
			})
			if err := r.Status().Update(ctx, snapshot); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: snapshotRequeueDefault}, nil
		}
		return ctrl.Result{}, err
	}

	// Check if cluster has ACL bootstrapped
	if !cluster.Status.ACLBootstrapped {
		log.Info("Waiting for NomadCluster ACL bootstrap", "cluster", cluster.Name)
		r.setCondition(snapshot, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "WaitingForACLBootstrap",
			Message: "Waiting for NomadCluster ACL bootstrap to complete",
		})
		if err := r.Status().Update(ctx, snapshot); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: snapshotRequeueDefault}, nil
	}

	// Get bootstrap token from cluster
	bootstrapSecretName := cluster.Status.ACLBootstrapSecretName
	if bootstrapSecretName == "" {
		bootstrapSecretName = cluster.Name + "-acl-bootstrap"
	}

	bootstrapSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      bootstrapSecretName,
		Namespace: clusterNamespace,
	}, bootstrapSecret); err != nil {
		log.Error(err, "Failed to get bootstrap token secret", "secret", bootstrapSecretName)
		r.setCondition(snapshot, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "BootstrapSecretNotFound",
			Message: fmt.Sprintf("Bootstrap secret %s not found", bootstrapSecretName),
		})
		if err := r.Status().Update(ctx, snapshot); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: snapshotRequeueDefault}, nil
	}

	bootstrapToken := string(bootstrapSecret.Data["secret-id"])
	if bootstrapToken == "" {
		log.Info("Bootstrap secret has no secret-id", "secret", bootstrapSecretName)
		return ctrl.Result{RequeueAfter: snapshotRequeueDefault}, nil
	}

	// Build Nomad address for the snapshot agent deployment
	internalAddr := nomad.InternalServiceAddress(cluster.Name, clusterNamespace, true)

	// Create or get a dedicated ACL token for the snapshot agent.
	// The token is scoped to operator:write which grants snapshot-save and
	// license-read capabilities (required by the snapshot agent).
	snapshotToken, err := r.ensureSnapshotToken(ctx, snapshot, cluster, clusterNamespace, bootstrapToken)
	if err != nil {
		log.Error(err, "Failed to ensure snapshot agent token")
		r.setCondition(snapshot, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "TokenCreationFailed",
			Message: fmt.Sprintf("Failed to create snapshot agent token: %v", err),
		})
		if err := r.Status().Update(ctx, snapshot); err != nil {
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

	// Create ConfigMap with snapshot agent config
	if err := r.reconcileConfigMap(ctx, snapshot); err != nil {
		log.Error(err, "Failed to reconcile ConfigMap")
		return ctrl.Result{}, err
	}

	// Create Deployment for snapshot agent
	// Always use internal address for the deployment since it runs inside the cluster
	if err := r.reconcileDeployment(ctx, snapshot, cluster, internalAddr); err != nil {
		log.Error(err, "Failed to reconcile Deployment")
		return ctrl.Result{}, err
	}

	// Update status with deployment information
	deploymentName := snapshot.Name + "-snapshot-agent"
	configMapName := snapshot.Name + "-snapshot-config"

	snapshot.Status.ObservedGeneration = snapshot.Generation
	snapshot.Status.DeploymentName = deploymentName
	snapshot.Status.ConfigMapName = configMapName
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
	} else {
		r.setCondition(snapshot, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "DeploymentNotReady",
			Message: "Snapshot agent deployment is not yet ready",
		})
	}

	if err := r.Status().Update(ctx, snapshot); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
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

// snapshotNomadClient creates a Nomad client for snapshot controller operations.
// Since verify_https_client is off, only the CA cert is needed for TLS verification.
func (r *NomadSnapshotReconciler) snapshotNomadClient(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, clusterNamespace, address string) (*nomad.Client, error) {
	cfg := nomad.ClientConfig{
		Address:    address,
		TLSEnabled: true,
	}

	tlsSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      cluster.Name + "-tls",
		Namespace: clusterNamespace,
	}, tlsSecret); err != nil {
		return nil, fmt.Errorf("failed to get TLS secret: %w", err)
	}
	cfg.CACert = tlsSecret.Data["ca.crt"]

	return nomad.NewClient(cfg)
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
	cluster *nomadv1alpha1.NomadCluster, clusterNamespace, bootstrapToken string,
) (string, error) {
	log := logf.FromContext(ctx)

	internalAddr := nomad.InternalServiceAddress(cluster.Name, clusterNamespace, true)
	loadBalancerAddr := nomad.LoadBalancerAddress(cluster.Status.AdvertiseAddress, true)

	// Try internal service first, fall back to LoadBalancer
	nomadClient, err := r.snapshotNomadClient(ctx, cluster, clusterNamespace, internalAddr)
	if err != nil {
		return "", err
	}

	policyName := fmt.Sprintf("snapshot-agent-%s-%s", snapshot.Namespace, snapshot.Name)

	// If we already have a token, try to look it up
	if snapshot.Status.TokenAccessorID != "" {
		token, err := nomadClient.GetACLToken(bootstrapToken, snapshot.Status.TokenAccessorID)
		if err == nil && token != nil {
			log.V(1).Info("Using existing snapshot agent token", "accessor", snapshot.Status.TokenAccessorID)
			return token.SecretID, nil
		}
		if nomad.IsNetworkError(err) && loadBalancerAddr != "" {
			nomadClient, err = r.snapshotNomadClient(ctx, cluster, clusterNamespace, loadBalancerAddr)
			if err != nil {
				return "", err
			}
			token, err = nomadClient.GetACLToken(bootstrapToken, snapshot.Status.TokenAccessorID)
			if err == nil && token != nil {
				return token.SecretID, nil
			}
		}
		log.Info("Existing token not found, creating new one", "accessor", snapshot.Status.TokenAccessorID)
	}

	// Create the policy (upsert, idempotent)
	err = nomadClient.CreateACLPolicy(bootstrapToken, policyName, "Snapshot agent policy for "+snapshot.Name, snapshotAgentPolicyRules)
	if nomad.IsNetworkError(err) && loadBalancerAddr != "" {
		nomadClient, err = r.snapshotNomadClient(ctx, cluster, clusterNamespace, loadBalancerAddr)
		if err != nil {
			return "", err
		}
		err = nomadClient.CreateACLPolicy(bootstrapToken, policyName, "Snapshot agent policy for "+snapshot.Name, snapshotAgentPolicyRules)
	}
	if err != nil {
		return "", fmt.Errorf("failed to create snapshot agent policy: %w", err)
	}

	// Create a client token bound to the policy
	newToken, err := nomadClient.CreateACLTokenWithPolicies(bootstrapToken, policyName, []string{policyName})
	if err != nil {
		return "", fmt.Errorf("failed to create snapshot agent token: %w", err)
	}

	log.Info("Created snapshot agent token", "accessor", newToken.AccessorID, "policy", policyName)

	// Update status with accessor ID and policy name for cleanup
	snapshot.Status.TokenAccessorID = newToken.AccessorID
	snapshot.Status.PolicyName = policyName
	if err := r.Status().Update(ctx, snapshot); err != nil {
		return "", fmt.Errorf("failed to update status with token accessor: %w", err)
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

	bootstrapSecretName := cluster.Status.ACLBootstrapSecretName
	if bootstrapSecretName == "" {
		bootstrapSecretName = cluster.Name + "-acl-bootstrap"
	}

	bootstrapSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      bootstrapSecretName,
		Namespace: clusterNamespace,
	}, bootstrapSecret); err != nil {
		return fmt.Errorf("failed to get bootstrap secret: %w", err)
	}
	bootstrapToken := string(bootstrapSecret.Data["secret-id"])

	internalAddr := nomad.InternalServiceAddress(cluster.Name, clusterNamespace, true)
	nomadClient, err := r.snapshotNomadClient(ctx, cluster, clusterNamespace, internalAddr)
	if err != nil {
		return err
	}

	// Delete token
	if snapshot.Status.TokenAccessorID != "" {
		if err := nomadClient.DeleteACLToken(bootstrapToken, snapshot.Status.TokenAccessorID); err != nil {
			if !nomad.IsNetworkError(err) {
				log.Error(err, "Failed to delete snapshot agent token")
			} else if loadBalancerAddr := nomad.LoadBalancerAddress(cluster.Status.AdvertiseAddress, true); loadBalancerAddr != "" {
				if lbClient, lbErr := r.snapshotNomadClient(ctx, cluster, clusterNamespace, loadBalancerAddr); lbErr == nil {
					_ = lbClient.DeleteACLToken(bootstrapToken, snapshot.Status.TokenAccessorID)
				}
			}
		} else {
			log.Info("Deleted snapshot agent token", "accessor", snapshot.Status.TokenAccessorID)
		}
	}

	// Delete policy
	if snapshot.Status.PolicyName != "" {
		if err := nomadClient.DeleteACLPolicy(bootstrapToken, snapshot.Status.PolicyName); err != nil {
			if !nomad.IsNetworkError(err) {
				log.Error(err, "Failed to delete snapshot agent policy")
			} else if loadBalancerAddr := nomad.LoadBalancerAddress(cluster.Status.AdvertiseAddress, true); loadBalancerAddr != "" {
				if lbClient, lbErr := r.snapshotNomadClient(ctx, cluster, clusterNamespace, loadBalancerAddr); lbErr == nil {
					_ = lbClient.DeleteACLPolicy(bootstrapToken, snapshot.Status.PolicyName)
				}
			}
		} else {
			log.Info("Deleted snapshot agent policy", "policy", snapshot.Status.PolicyName)
		}
	}

	return nil
}

// reconcileConfigMap creates or updates the snapshot agent ConfigMap
func (r *NomadSnapshotReconciler) reconcileConfigMap(ctx context.Context, snapshot *nomadv1alpha1.NomadSnapshot) error {
	configMapName := snapshot.Name + "-snapshot-config"

	// Generate HCL config
	config := r.generateSnapshotConfig(snapshot)

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

// generateSnapshotConfig generates the HCL config for the snapshot agent
func (r *NomadSnapshotReconciler) generateSnapshotConfig(snapshot *nomadv1alpha1.NomadSnapshot) string {
	interval := snapshot.Spec.Schedule.Interval
	if interval == "" {
		interval = "1h"
	}
	retain := snapshot.Spec.Schedule.Retain
	if retain == 0 {
		retain = 24
	}

	config := fmt.Sprintf(`snapshot {
  interval         = "%s"
  retain           = %d
  stale            = %t
  deregister_after = "8h"
}
`, interval, retain, snapshot.Spec.Schedule.Stale)

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
	secretName := snapshot.Name + "-snapshot-token"

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: snapshot.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		secret.Type = corev1.SecretTypeOpaque
		secret.Data = map[string][]byte{
			"secret-id":   []byte(nomadToken),
			"accessor-id": []byte(snapshot.Status.TokenAccessorID),
		}
		return controllerutil.SetControllerReference(snapshot, secret, r.Scheme)
	})

	return err
}

// reconcileDeployment creates or updates the snapshot agent Deployment
func (r *NomadSnapshotReconciler) reconcileDeployment(ctx context.Context, snapshot *nomadv1alpha1.NomadSnapshot, cluster *nomadv1alpha1.NomadCluster, nomadAddr string) error {
	deploymentName := snapshot.Name + "-snapshot-agent"
	configMapName := snapshot.Name + "-snapshot-config"
	tokenSecretName := snapshot.Name + "-snapshot-token"

	// Image defaults set via kubebuilder tags on ImageSpec
	image := fmt.Sprintf("%s:%s", cluster.Spec.Image.Repository, cluster.Spec.Image.Tag)

	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName,
			Namespace: snapshot.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, deploy, func() error {
		labels := map[string]string{
			"app.kubernetes.io/name":       "nomad-snapshot-agent",
			"app.kubernetes.io/instance":   snapshot.Name,
			"app.kubernetes.io/managed-by": "nomad-enterprise-operator",
		}

		deploy.Spec = appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
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
											Key: "secret-id",
										},
									},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
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
							Resources: snapshot.Spec.Resources,
						},
					},
					Volumes: []corev1.Volume{
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
									SecretName: cluster.Name + "-tls",
								},
							},
						},
					},
					NodeSelector: snapshot.Spec.NodeSelector,
					Tolerations:  snapshot.Spec.Tolerations,
				},
			},
		}

		// Add storage credentials if specified
		r.addStorageCredentials(snapshot, &deploy.Spec.Template.Spec)

		// Add local PVC if specified
		if snapshot.Spec.Target.Local != nil {
			r.addLocalStorage(snapshot, &deploy.Spec.Template.Spec)
		}

		return controllerutil.SetControllerReference(snapshot, deploy, r.Scheme)
	})

	return err
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
	pvcName := snapshot.Name + "-snapshots"

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
		// Only set spec on create (PVC spec is immutable)
		if pvc.CreationTimestamp.IsZero() {
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

	pvcName := snapshot.Name + "-snapshots"

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

// setCondition updates a condition on the snapshot
func (r *NomadSnapshotReconciler) setCondition(snapshot *nomadv1alpha1.NomadSnapshot, condition metav1.Condition) {
	condition.LastTransitionTime = metav1.Now()
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
		Named("nomadsnapshot").
		Complete(r)
}
