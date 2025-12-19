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

package phases

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// StatefulSetPhase creates and manages the Nomad server StatefulSet.
type StatefulSetPhase struct {
	*PhaseContext
}

// NewStatefulSetPhase creates a new StatefulSetPhase.
func NewStatefulSetPhase(ctx *PhaseContext) *StatefulSetPhase {
	return &StatefulSetPhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *StatefulSetPhase) Name() string {
	return "StatefulSet"
}

// Execute creates or updates the Nomad server StatefulSet.
func (p *StatefulSetPhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	sts := p.buildStatefulSet(ctx, cluster)

	if err := controllerutil.SetControllerReference(cluster, sts, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on StatefulSet")
	}

	existing := &appsv1.StatefulSet{}
	err := p.Client.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			p.Log.Info("Creating StatefulSet", "name", sts.Name, "replicas", *sts.Spec.Replicas)
			if err := p.Client.Create(ctx, sts); err != nil {
				return Error(err, "Failed to create StatefulSet")
			}
			return OK()
		}
		return Error(err, "Failed to get StatefulSet")
	}

	// Update StatefulSet if spec changed
	if p.needsUpdate(existing, sts) {
		// Preserve fields that shouldn't be updated
		sts.Spec.VolumeClaimTemplates = existing.Spec.VolumeClaimTemplates

		existing.Spec = sts.Spec
		existing.Annotations = sts.Annotations
		p.Log.Info("Updating StatefulSet", "name", sts.Name)
		if err := p.Client.Update(ctx, existing); err != nil {
			return Error(err, "Failed to update StatefulSet")
		}
	}

	return OK()
}

func (p *StatefulSetPhase) buildStatefulSet(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) *appsv1.StatefulSet {
	replicas := cluster.Spec.Replicas
	if replicas == 0 {
		replicas = 3
	}

	// Build container image
	image := cluster.Spec.Image.Repository
	if image == "" {
		image = "hashicorp/nomad"
	}
	tag := cluster.Spec.Image.Tag
	if tag == "" {
		tag = "1.11-ent"
	}
	imageFull := fmt.Sprintf("%s:%s", image, tag)

	pullPolicy := cluster.Spec.Image.PullPolicy
	if pullPolicy == "" {
		pullPolicy = corev1.PullIfNotPresent
	}

	// Determine probe scheme
	probeScheme := corev1.URISchemeHTTP
	if cluster.Spec.Server.TLS.Enabled {
		probeScheme = corev1.URISchemeHTTPS
	}

	// Build environment variables
	env := p.buildEnvVars(cluster)

	// Build volume mounts
	volumeMounts := p.buildVolumeMounts(cluster)

	// Build volumes
	volumes := p.buildVolumes(cluster)

	// Build volume claim templates
	volumeClaimTemplates := p.buildVolumeClaimTemplates(cluster)

	// Build pod spec
	podSpec := corev1.PodSpec{
		ServiceAccountName: cluster.Name,
		ImagePullSecrets:   cluster.Spec.ImagePullSecrets,
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot: boolPtr(true),
			// fsGroup is managed by OpenShift SCC
		},
		Containers: []corev1.Container{
			{
				Name:            "nomad",
				Image:           imageFull,
				ImagePullPolicy: pullPolicy,
				Command:         []string{"nomad", "agent", "-config=/nomad/config"},
				Env:             env,
				Ports: []corev1.ContainerPort{
					{Name: "http", ContainerPort: 4646, Protocol: corev1.ProtocolTCP},
					{Name: "rpc", ContainerPort: 4647, Protocol: corev1.ProtocolTCP},
					{Name: "serf", ContainerPort: 4648, Protocol: corev1.ProtocolTCP},
				},
				LivenessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{
							Path:   "/v1/agent/health?type=server",
							Port:   intstr.FromInt(4646),
							Scheme: probeScheme,
						},
					},
					InitialDelaySeconds: 30,
					PeriodSeconds:       10,
					TimeoutSeconds:      5,
					FailureThreshold:    3,
				},
				ReadinessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{
							Path:   "/v1/agent/health?type=server",
							Port:   intstr.FromInt(4646),
							Scheme: probeScheme,
						},
					},
					InitialDelaySeconds: 10,
					PeriodSeconds:       5,
					TimeoutSeconds:      3,
					FailureThreshold:    2,
				},
				Resources:    getResourcesWithDefaults(cluster.Spec.Resources),
				VolumeMounts: volumeMounts,
			},
		},
		Volumes:      volumes,
		NodeSelector: cluster.Spec.NodeSelector,
		Tolerations:  cluster.Spec.Tolerations,
	}

	// Add affinity if configured
	if cluster.Spec.Affinity != nil && cluster.Spec.Affinity.PodAntiAffinity.Enabled {
		podSpec.Affinity = p.buildAffinity(cluster)
	}

	// Add topology spread constraints
	if len(cluster.Spec.TopologySpreadConstraints) > 0 {
		podSpec.TopologySpreadConstraints = cluster.Spec.TopologySpreadConstraints
	}

	// Get config checksum for pod annotation - include all config-affecting fields
	// This ensures pods restart when any config changes
	configChecksum := ConfigChecksum(map[string]string{
		"advertise":        p.AdvertiseAddress,
		"gossip":           p.GossipKey,
		"acl":              strconv.FormatBool(cluster.Spec.Server.ACL.Enabled),
		"tls":              strconv.FormatBool(cluster.Spec.Server.TLS.Enabled),
		"audit":            strconv.FormatBool(cluster.Spec.Server.Audit.Enabled),
		"auditDelivery":    cluster.Spec.Server.Audit.DeliveryGuarantee,
		"replicas":         strconv.Itoa(int(replicas)),
		"region":           cluster.Spec.Topology.Region,
		"datacenter":       cluster.Spec.Topology.Datacenter,
		"snapshotEnabled":  strconv.FormatBool(cluster.Spec.Server.Snapshot.Enabled),
		"snapshotBucket":   cluster.Spec.Server.Snapshot.S3.Bucket,
		"snapshotEndpoint": cluster.Spec.Server.Snapshot.S3.Endpoint,
	})

	// Get secrets checksum for pod annotation - hash actual secret contents
	// This ensures pods restart when referenced secrets change
	secretsChecksum, err := p.computeSecretsChecksum(ctx, cluster)
	if err != nil {
		p.Log.Error(err, "Failed to compute secrets checksum, using empty hash")
		secretsChecksum = ""
	}

	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Spec: appsv1.StatefulSetSpec{
			ServiceName:         cluster.Name + "-headless",
			Replicas:            &replicas,
			PodManagementPolicy: appsv1.ParallelPodManagement,
			UpdateStrategy: appsv1.StatefulSetUpdateStrategy{
				Type: appsv1.RollingUpdateStatefulSetStrategyType,
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: GetSelectorLabels(cluster),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: GetSelectorLabels(cluster),
					Annotations: map[string]string{
						"checksum/config":  configChecksum,
						"checksum/secrets": secretsChecksum,
					},
				},
				Spec: podSpec,
			},
			VolumeClaimTemplates: volumeClaimTemplates,
		},
	}

	return sts
}

func (p *StatefulSetPhase) buildEnvVars(cluster *nomadv1alpha1.NomadCluster) []corev1.EnvVar {
	// Get the effective license secret name (handles inline vs external)
	licenseSecretName := GetLicenseSecretName(cluster)
	licenseKey := cluster.Spec.License.SecretKey
	if licenseKey == "" {
		licenseKey = "license"
	}

	env := []corev1.EnvVar{
		{
			Name: "NOMAD_LICENSE",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: licenseSecretName,
					},
					Key: licenseKey,
				},
			},
		},
		{
			Name: "NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.namespace",
				},
			},
		},
		{
			Name: "POD_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.name",
				},
			},
		},
		{
			Name: "POD_IP",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "status.podIP",
				},
			},
		},
	}

	// Add S3 credentials for snapshots (handles both inline and external secrets)
	s3CredentialsSecretName := GetS3CredentialsSecretName(cluster)
	if cluster.Spec.Server.Snapshot.Enabled && s3CredentialsSecretName != "" {
		env = append(env,
			corev1.EnvVar{
				Name: "AWS_ACCESS_KEY_ID",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: s3CredentialsSecretName,
						},
						Key: "access-key-id",
					},
				},
			},
			corev1.EnvVar{
				Name: "AWS_SECRET_ACCESS_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: s3CredentialsSecretName,
						},
						Key: "secret-access-key",
					},
				},
			},
		)
	}

	return env
}

func (p *StatefulSetPhase) buildVolumeMounts(cluster *nomadv1alpha1.NomadCluster) []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{
		{
			Name:      "data",
			MountPath: "/nomad/data",
		},
		{
			Name:      "config",
			MountPath: "/nomad/config",
			ReadOnly:  true,
		},
	}

	// Add audit volume mount (always needed when audit is enabled)
	if cluster.Spec.Server.Audit.Enabled {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      "audit",
			MountPath: "/nomad/audit",
		})
	}

	// Add TLS volume mount
	if cluster.Spec.Server.TLS.Enabled {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      "tls",
			MountPath: "/nomad/tls",
			ReadOnly:  true,
		})
	}

	return mounts
}

func (p *StatefulSetPhase) buildVolumes(cluster *nomadv1alpha1.NomadCluster) []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: cluster.Name + "-config",
					},
				},
			},
		},
	}

	// Add TLS volume from secret (handles both inline and external secrets)
	if cluster.Spec.Server.TLS.Enabled {
		tlsSecretName := GetTLSSecretName(cluster)
		volumes = append(volumes, corev1.Volume{
			Name: "tls",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: tlsSecretName,
				},
			},
		})
	}

	// Add emptyDir for data if persistence is disabled (size is empty)
	if !isPersistenceEnabled(cluster) {
		volumes = append(volumes, corev1.Volume{
			Name: "data",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		})
	}

	return volumes
}

// isPersistenceEnabled returns true if persistence is enabled.
// Persistence is enabled if Size is non-empty (the Enabled field is deprecated).
func isPersistenceEnabled(cluster *nomadv1alpha1.NomadCluster) bool {
	// Size has a default of "10Gi" via kubebuilder, so it should always be set
	// unless explicitly cleared. Check for non-empty size.
	return cluster.Spec.Persistence.Size != ""
}

func (p *StatefulSetPhase) buildVolumeClaimTemplates(cluster *nomadv1alpha1.NomadCluster) []corev1.PersistentVolumeClaim {
	if !isPersistenceEnabled(cluster) {
		return nil
	}

	dataSize := cluster.Spec.Persistence.Size

	templates := []corev1.PersistentVolumeClaim{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "data",
				Labels: GetLabels(cluster),
			},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceStorage: resource.MustParse(dataSize),
					},
				},
			},
		},
	}

	// Add storage class if specified
	if cluster.Spec.Persistence.StorageClassName != "" {
		templates[0].Spec.StorageClassName = &cluster.Spec.Persistence.StorageClassName
	}

	// Add audit volume when audit is enabled (opinionated: audit always gets persistent storage)
	if cluster.Spec.Server.Audit.Enabled {
		// Prefer new AuditSpec fields, fall back to persistence.audit for backward compatibility
		auditSize := cluster.Spec.Server.Audit.Size
		if auditSize == "" {
			auditSize = cluster.Spec.Persistence.Audit.Size
		}
		if auditSize == "" {
			auditSize = "5Gi"
		}

		auditStorageClass := cluster.Spec.Server.Audit.StorageClassName
		if auditStorageClass == "" {
			auditStorageClass = cluster.Spec.Persistence.Audit.StorageClassName
		}

		auditPVC := corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "audit",
				Labels: GetLabels(cluster),
			},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceStorage: resource.MustParse(auditSize),
					},
				},
			},
		}

		if auditStorageClass != "" {
			auditPVC.Spec.StorageClassName = &auditStorageClass
		}

		templates = append(templates, auditPVC)
	}

	return templates
}

func (p *StatefulSetPhase) buildAffinity(cluster *nomadv1alpha1.NomadCluster) *corev1.Affinity {
	antiAffinity := cluster.Spec.Affinity.PodAntiAffinity

	topologyKey := antiAffinity.TopologyKey
	if topologyKey == "" {
		topologyKey = "kubernetes.io/hostname"
	}

	labelSelector := &metav1.LabelSelector{
		MatchLabels: GetSelectorLabels(cluster),
	}

	if antiAffinity.Type == "required" {
		return &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: labelSelector,
						TopologyKey:   topologyKey,
					},
				},
			},
		}
	}

	// Default to preferred
	weight := antiAffinity.Weight
	if weight == 0 {
		weight = 100
	}

	return &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
				{
					Weight: weight,
					PodAffinityTerm: corev1.PodAffinityTerm{
						LabelSelector: labelSelector,
						TopologyKey:   topologyKey,
					},
				},
			},
		},
	}
}

func (p *StatefulSetPhase) needsUpdate(existing, desired *appsv1.StatefulSet) bool {
	// Check replicas
	if *existing.Spec.Replicas != *desired.Spec.Replicas {
		return true
	}

	// Check container image
	if len(existing.Spec.Template.Spec.Containers) > 0 && len(desired.Spec.Template.Spec.Containers) > 0 {
		if existing.Spec.Template.Spec.Containers[0].Image != desired.Spec.Template.Spec.Containers[0].Image {
			return true
		}
	}

	// Check config checksum annotation
	existingChecksum := existing.Spec.Template.Annotations["checksum/config"]
	desiredChecksum := desired.Spec.Template.Annotations["checksum/config"]
	if existingChecksum != desiredChecksum {
		return true
	}

	// Check secrets checksum annotation (triggers rolling restart when secrets change)
	existingSecretsChecksum := existing.Spec.Template.Annotations["checksum/secrets"]
	desiredSecretsChecksum := desired.Spec.Template.Annotations["checksum/secrets"]
	return existingSecretsChecksum != desiredSecretsChecksum
}

func boolPtr(b bool) *bool {
	return &b
}

// getResourcesWithDefaults returns resource requirements with sensible defaults applied.
// Defaults: requests: cpu=250m, memory=512Mi; limits: cpu=2, memory=2Gi
func getResourcesWithDefaults(resources corev1.ResourceRequirements) corev1.ResourceRequirements {
	result := resources.DeepCopy()

	// Initialize maps if nil
	if result.Requests == nil {
		result.Requests = corev1.ResourceList{}
	}
	if result.Limits == nil {
		result.Limits = corev1.ResourceList{}
	}

	// Apply request defaults
	if _, ok := result.Requests[corev1.ResourceCPU]; !ok {
		result.Requests[corev1.ResourceCPU] = resource.MustParse("250m")
	}
	if _, ok := result.Requests[corev1.ResourceMemory]; !ok {
		result.Requests[corev1.ResourceMemory] = resource.MustParse("512Mi")
	}

	// Apply limit defaults
	if _, ok := result.Limits[corev1.ResourceCPU]; !ok {
		result.Limits[corev1.ResourceCPU] = resource.MustParse("2")
	}
	if _, ok := result.Limits[corev1.ResourceMemory]; !ok {
		result.Limits[corev1.ResourceMemory] = resource.MustParse("2Gi")
	}

	return *result
}

// computeSecretsChecksum reads all referenced secrets and computes a combined hash.
// When any secret changes, the hash changes, triggering a rolling restart.
func (p *StatefulSetPhase) computeSecretsChecksum(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (string, error) {
	h := sha256.New()

	// Collect secret names to hash
	secretNames := []string{}

	// License secret
	if licenseSecret := GetLicenseSecretName(cluster); licenseSecret != "" {
		secretNames = append(secretNames, licenseSecret)
	}

	// Gossip secret
	if gossipSecret := GetGossipSecretName(cluster); gossipSecret != "" {
		secretNames = append(secretNames, gossipSecret)
	}

	// TLS secret
	if cluster.Spec.Server.TLS.Enabled {
		if tlsSecret := GetTLSSecretName(cluster); tlsSecret != "" {
			secretNames = append(secretNames, tlsSecret)
		}
	}

	// S3 credentials secret
	if cluster.Spec.Server.Snapshot.Enabled {
		if s3Secret := GetS3CredentialsSecretName(cluster); s3Secret != "" {
			secretNames = append(secretNames, s3Secret)
		}
	}

	// Sort for deterministic ordering
	sort.Strings(secretNames)

	// Read and hash each secret's data
	for _, name := range secretNames {
		secret := &corev1.Secret{}
		err := p.Client.Get(ctx, types.NamespacedName{
			Name:      name,
			Namespace: cluster.Namespace,
		}, secret)
		if err != nil {
			if errors.IsNotFound(err) {
				// Secret doesn't exist yet, include name with empty data
				h.Write([]byte(name + ":"))
				continue
			}
			return "", fmt.Errorf("failed to get secret %s: %w", name, err)
		}

		// Hash secret name and data
		h.Write([]byte(name + ":"))

		// Sort keys for deterministic ordering
		keys := make([]string, 0, len(secret.Data))
		for k := range secret.Data {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			h.Write([]byte(k))
			h.Write(secret.Data[k])
		}
	}

	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

// GetGossipSecretName returns the gossip secret name for the cluster.
func GetGossipSecretName(cluster *nomadv1alpha1.NomadCluster) string {
	if cluster.Spec.Gossip.SecretName != "" {
		return cluster.Spec.Gossip.SecretName
	}
	return cluster.Name + "-gossip"
}
