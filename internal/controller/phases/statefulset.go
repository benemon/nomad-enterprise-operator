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
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"time"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/hcl"
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

// auditDeliveryChecksumValue keeps the delivery guarantee out of the
// restart checksum while audit is disabled: the rendered HCL carries no
// audit block then, so a lever change must not roll the servers.
func auditDeliveryChecksumValue(cluster *nomadv1alpha1.NomadCluster) string {
	if !cluster.Spec.Server.Audit.IsEnabled() {
		return ""
	}
	return hcl.AuditDeliveryGuarantee(cluster)
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

	// During scale-down, ScaleDownPhase owns sts.spec.replicas (it
	// patches only after peer removal) — preserve the existing count
	// here so the phases don't race.
	if existing.Spec.Replicas != nil && *existing.Spec.Replicas > cluster.Spec.Replicas {
		sts.Spec.Replicas = existing.Spec.Replicas
	}

	// Scale-up is serialized: one replica per reconcile, gated on the
	// previous server reaching the voter set. Simultaneous joins race
	// Nomad's member reconciliation — leadership churn mid-join can
	// strand a server in an AddNonvoter/RemoveServer loop (neo-tma) —
	// while a lone join meets a settled leader. Initial creation still
	// starts all replicas at once: bootstrap_expect needs them.
	stepping := false
	if existing.Spec.Replicas != nil && *sts.Spec.Replicas > *existing.Spec.Replicas {
		// Exact match, not >=: a stale status carrying a pre-scale-down
		// voter count (e.g. 5 after 5→1) would otherwise walk the whole
		// ladder without any join settling. Stale-high now holds until
		// the status phase refreshes.
		next := *existing.Spec.Replicas
		ap := cluster.Status.Autopilot
		if ap != nil && ap.Healthy && int32(ap.Voters) == *existing.Spec.Replicas {
			next++
		}
		if next < *sts.Spec.Replicas {
			stepping = true
			if next == *existing.Spec.Replicas {
				p.Log.Info("Scale-up holding: previous replica not yet a settled voter",
					"replicas", next, "target", *sts.Spec.Replicas)
			}
			sts.Spec.Replicas = &next
		}
	}

	// Update StatefulSet if spec changed
	if update, reason := p.needsUpdate(existing, sts); update {
		// Preserve fields that shouldn't be updated
		sts.Spec.VolumeClaimTemplates = existing.Spec.VolumeClaimTemplates

		existing.Spec = sts.Spec
		existing.Annotations = sts.Annotations
		p.Log.Info("Updating StatefulSet", "name", sts.Name, "reason", reason)
		if err := p.Client.Update(ctx, existing); err != nil {
			return Error(err, "Failed to update StatefulSet")
		}
	}

	if stepping {
		// Revisit soon for the next step, but let the chain finish: the
		// voter gate reads status.autopilot, which ClusterStatusPhase
		// refreshes later in the chain — a short-circuiting Requeue here
		// would starve that refresh and deadlock the ladder.
		if p.RevisitAfter == 0 || p.RevisitAfter > 15*time.Second {
			p.RevisitAfter = 15 * time.Second
		}
	}
	return OK()
}

func (p *StatefulSetPhase) buildStatefulSet(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) *appsv1.StatefulSet {
	replicas := cluster.Spec.Replicas
	if replicas == 0 {
		replicas = 3
	}

	// Build container image (defaults set via kubebuilder tags on ImageSpec)
	imageFull := ImageRef(cluster)
	pullPolicy := cluster.Spec.Image.PullPolicy

	// Build environment variables
	env := p.buildEnvVars(cluster)

	// GOMEMLIMIT at 90% of the container memory limit: the Go GC paces
	// itself off heap growth and cannot see the cgroup ceiling, so RSS
	// (heap + retained + off-heap) otherwise walks into the OOM killer
	// with a healthy heap (neo-ddk matched sweeps). The soft limit makes
	// the runtime reclaim as RSS approaches it; the 10% headroom covers
	// what the runtime does not own (raft BoltDB mmap). Bare integer =
	// bytes.
	resources := getResourcesWithDefaults(cluster.Spec.Resources)
	memLimit := resources.Limits[corev1.ResourceMemory]
	env = append(env, corev1.EnvVar{
		Name:  "GOMEMLIMIT",
		Value: strconv.FormatInt(memLimit.Value()/10*9, 10),
	})

	// Build volume mounts
	volumeMounts := p.buildVolumeMounts(cluster)

	// Build volumes
	volumes := p.buildVolumes(cluster)

	// Build volume claim templates
	volumeClaimTemplates := p.buildVolumeClaimTemplates(cluster)

	// Each pod must drop its own FQDN from retry_join before starting:
	// Nomad's retry loop counts a self-join as success and never
	// re-attempts, so a parallel pod start loses the peer-DNS race and
	// quorum never forms (GH #11). The config Secret is shared across
	// pods, so the exclusion happens here; the filtered copy lands on a
	// memory-backed emptyDir to keep the gossip key off node disk.
	//
	// The peers.json block prevents single-voter address staleness
	// (neo-ixt): a lone server restarting with a new pod IP keeps its
	// Raft ID but not its address, and Nomad's member reconcile cannot
	// amend the sole voter's own entry — it aborts before ever adding
	// new servers, so a later scale-up strands at one voter. Guards:
	// bootstrap_expect = 1 (a multi-server config must never be reset
	// to self-only), existing raft state (fresh bootstraps and emptyDir
	// restarts stay on the normal path), and no sibling in headless DNS
	// (spec.replicas may already say 1 while scale-down peers are still
	// voters; their pods outlive their Raft entries, so a resolving
	// sibling means abort). The guard fails closed — a skipped heal
	// costs one more restart; a wrong heal resets a multi-server Raft
	// configuration. Address rows are taken only after Name lines (the
	// resolver's own address line would otherwise count).
	startCommand := fmt.Sprintf(
		`NODE_ID=$(cat /nomad/data/server/node-id 2>/dev/null || true)
if [ -n "$NODE_ID" ] && [ -n "${POD_IP}" ] && grep -q 'bootstrap_expect = 1$' /nomad/config/server.hcl; then
  ALONE=""
  for i in $(seq 1 30); do
    ADDRS=$(nslookup %[1]s-headless.%[2]s.svc.cluster.local 2>/dev/null | awk '/^Name:/{n=1;next} /^Address/{if(n)print $2}' || true)
    if [ -n "$ADDRS" ] && echo "$ADDRS" | grep -qx "${POD_IP}"; then
      if [ "$(echo "$ADDRS" | grep -cvx "${POD_IP}")" -eq 0 ]; then ALONE=yes; fi
      break
    fi
    sleep 1
  done
  if [ "$ALONE" = yes ]; then
    case "${POD_IP}" in *:*) SELF_ADDR="[${POD_IP}]";; *) SELF_ADDR="${POD_IP}";; esac
    echo "[{\"id\":\"$NODE_ID\",\"address\":\"$SELF_ADDR:4647\",\"non_voter\":false}]" > /nomad/data/server/raft/peers.json.tmp
    mv /nomad/data/server/raft/peers.json.tmp /nomad/data/server/raft/peers.json
    echo "wrote peers.json: single-server raft self-entry pinned to $SELF_ADDR"
  fi
fi
grep -vF "\"${POD_NAME}.%[1]s-headless.%[2]s.svc.cluster.local\"" /nomad/config/server.hcl > /nomad/config-runtime/server.hcl && exec nomad agent -config=/nomad/config-runtime/server.hcl`,
		cluster.Name, cluster.Namespace)

	// Build pod spec
	podSpec := corev1.PodSpec{
		ServiceAccountName: cluster.Name,
		ImagePullSecrets:   cluster.Spec.ImagePullSecrets,
		// PSS restricted (neo-8xu); identity fields conditional on
		// platform — see PodSecurityContext.
		SecurityContext: PodSecurityContext(cluster.Spec.OpenShift.Enabled),
		Containers: []corev1.Container{
			{
				Name:            "nomad",
				Image:           imageFull,
				ImagePullPolicy: pullPolicy,
				Command:         []string{"/bin/sh", "-ec", startCommand},
				Env:             env,
				Ports: []corev1.ContainerPort{
					{Name: "http", ContainerPort: 4646, Protocol: corev1.ProtocolTCP},
					{Name: "rpc", ContainerPort: 4647, Protocol: corev1.ProtocolTCP},
					{Name: "serf", ContainerPort: 4648, Protocol: corev1.ProtocolTCP},
				},
				// Liveness must be leader-INDEPENDENT (neo-pl4):
				// /v1/agent/health returns 500 without a cluster leader,
				// so an HTTP liveness check kills healthy followers
				// mid-election and turns one OOM into a quorum-loss
				// cascade. TCP asserts only that the agent is alive.
				LivenessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						TCPSocket: &corev1.TCPSocketAction{
							Port: intstr.FromInt(4646),
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
							Path:   "/v1/agent/health",
							Port:   intstr.FromInt(4646),
							Scheme: corev1.URISchemeHTTPS,
						},
					},
					InitialDelaySeconds: 10,
					PeriodSeconds:       5,
					TimeoutSeconds:      3,
					FailureThreshold:    2,
				},
				Resources:       resources,
				VolumeMounts:    volumeMounts,
				SecurityContext: ContainerSecurityContext(),
			},
		},
		Volumes:      volumes,
		NodeSelector: cluster.Spec.NodeSelector,
		Tolerations:  cluster.Spec.Tolerations,
	}

	// Pod anti-affinity is operator-owned per ADR 0003: preferred
	// (required is a footgun on small clusters), weight 100, hostname
	// topology. Applied at every replica count: preferred scheduling is
	// inert with nothing to avoid, and gating it on replicas makes the
	// pod template vary with scale — the resulting rolling restart of a
	// lone survivor changes its IP behind its Raft ID, and a
	// single-voter leader cannot repair its own stale address entry
	// (neo-tma). Multi-zone spreading uses the user-facing
	// spec.topologySpreadConstraints instead.
	podSpec.Affinity = buildOperatorAffinity(cluster)

	// Add topology spread constraints
	if len(cluster.Spec.TopologySpreadConstraints) > 0 {
		podSpec.TopologySpreadConstraints = cluster.Spec.TopologySpreadConstraints
	}

	// Checksum only non-scale-dependent config: the scale-dependent
	// HCL (bootstrap_expect, retry_join) is startup-only in Nomad, and
	// including it would roll pods — and break quorum — on every
	// replica change.
	keyringsJSON, _ := json.Marshal(p.Keyrings)
	configData := map[string]string{
		"advertise":      p.AdvertiseAddress,
		"gossip":         p.GossipKey,
		"acl":            strconv.FormatBool(cluster.Spec.Server.ACL.IsEnabled()),
		"tls":            "true",
		"audit":          strconv.FormatBool(cluster.Spec.Server.Audit.IsEnabled()),
		"audit-delivery": auditDeliveryChecksumValue(cluster),
		"region":         cluster.Spec.Topology.Region,
		"datacenter":     cluster.Spec.Topology.Datacenter,
		"keyrings":       string(keyringsJSON),
	}
	if _, _, ok := TrustBundle(cluster); ok {
		bundleChecksum, err := p.computeTrustBundleChecksum(ctx, cluster)
		if err != nil {
			p.Log.Error(err, "Failed to compute trust bundle checksum, using empty hash")
			bundleChecksum = ConfigChecksum(nil)
		}
		configData["trust-bundle"] = bundleChecksum
	}
	configChecksum := ConfigChecksum(configData)
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
	licenseSecretName := getLicenseSecretName(cluster)

	env := []corev1.EnvVar{
		{
			Name: "NOMAD_LICENSE",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: licenseSecretName,
					},
					// Key name is operator-owned per ADR 0003.
					Key: licenseSecretKey,
				},
			},
		},
		// fieldRef apiVersion is pinned throughout: the apiserver
		// defaults it on the stored object, and an unset value here
		// makes the env DeepEqual report drift on every reconcile.
		{
			Name: "NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  "metadata.namespace",
				},
			},
		},
		{
			Name: "POD_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  "metadata.name",
				},
			},
		},
		{
			Name: "POD_IP",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  "status.podIP",
				},
			},
		},
		// TLS environment variables for in-container Nomad CLI usage (e.g. kubectl exec debugging).
		// Client cert env vars are not needed since verify_https_client is off.
		{
			Name:  "NOMAD_ADDR",
			Value: "https://127.0.0.1:4646",
		},
		{
			Name:  "NOMAD_CACERT",
			Value: "/nomad/tls/ca.crt",
		},
	}

	return env
}

// buildKeyringVolumes returns the volumes and mounts for keyring
// secret material: the GCP service-account JSON and per-transit TLS
// files, at the paths the keyring phase renders into the HCL.
func buildKeyringVolumes(entries []nomadv1alpha1.KeyringEntry) ([]corev1.Volume, []corev1.VolumeMount) {
	var vols []corev1.Volume
	var mounts []corev1.VolumeMount
	for _, e := range entries {
		if e.GCPCKMS != nil && e.GCPCKMS.CredentialsSecretRef != nil {
			vols = append(vols, corev1.Volume{
				Name: "keyring-gcp-" + e.Name,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{SecretName: e.GCPCKMS.CredentialsSecretRef.Name},
				},
			})
			mounts = append(mounts, corev1.VolumeMount{
				Name: "keyring-gcp-" + e.Name, MountPath: "/nomad/keyring-gcp/" + e.Name, ReadOnly: true})
		}
		if e.Transit != nil && e.Transit.CASecretRef != nil {
			vols = append(vols, corev1.Volume{
				Name: "keyring-ca-" + e.Name,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{SecretName: e.Transit.CASecretRef.Name},
				},
			})
			mounts = append(mounts, corev1.VolumeMount{
				Name: "keyring-ca-" + e.Name, MountPath: KeyringTLSPath(e.Name), ReadOnly: true})
		}
		if e.Transit != nil && e.Transit.ClientCertSecretRef != nil {
			vols = append(vols, corev1.Volume{
				Name: "keyring-cc-" + e.Name,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{SecretName: e.Transit.ClientCertSecretRef.Name},
				},
			})
			mounts = append(mounts, corev1.VolumeMount{
				Name: "keyring-cc-" + e.Name, MountPath: KeyringTLSPath(e.Name) + "-client", ReadOnly: true})
		}
	}
	return vols, mounts
}

func (p *StatefulSetPhase) buildVolumeMounts(cluster *nomadv1alpha1.NomadCluster) []corev1.VolumeMount {
	_, keyringMounts := buildKeyringVolumes(p.KeyringEntries)
	mounts := append(keyringMounts, []corev1.VolumeMount{
		{
			Name:      "data",
			MountPath: "/nomad/data",
		},
		{
			Name:      "config",
			MountPath: "/nomad/config",
			ReadOnly:  true,
		},
		// Writable target for the self-filtered server.hcl copy
		{
			Name:      "config-runtime",
			MountPath: "/nomad/config-runtime",
		},
		// The root filesystem is read-only (PSS restricted, neo-8xu);
		// /tmp is the one scratch path Nomad may write outside data_dir.
		{
			Name:      "tmp",
			MountPath: "/tmp",
		},
	}...)

	// Add audit volume mount (always needed when audit is enabled)
	if cluster.Spec.Server.Audit.IsEnabled() {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      "audit",
			MountPath: "/nomad/audit",
		})
	}

	// TLS volume mount — mTLS is always enabled
	mounts = append(mounts, corev1.VolumeMount{
		Name:      "tls",
		MountPath: "/nomad/tls",
		ReadOnly:  true,
	})
	if _, _, ok := TrustBundle(cluster); ok {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      "trust-bundle",
			MountPath: "/etc/ssl/certs",
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
				Secret: &corev1.SecretVolumeSource{
					SecretName: cluster.Name + "-config",
				},
			},
		},
	}

	keyringVols, _ := buildKeyringVolumes(p.KeyringEntries)
	volumes = append(volumes, keyringVols...)

	// Memory-backed so the filtered server.hcl (gossip key, keyring
	// tokens) never touches node disk.
	configRuntimeLimit := resource.MustParse("1Mi")
	volumes = append(volumes, corev1.Volume{
		Name: "config-runtime",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium:    corev1.StorageMediumMemory,
				SizeLimit: &configRuntimeLimit,
			},
		},
	})
	if name, key, ok := TrustBundle(cluster); ok {
		volumes = append(volumes, corev1.Volume{
			Name: "trust-bundle",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: name},
					Items:                []corev1.KeyToPath{{Key: key, Path: "ca-certificates.crt"}},
				},
			},
		})
	}

	// Scratch space to pair with readOnlyRootFilesystem (neo-8xu)
	volumes = append(volumes, corev1.Volume{
		Name: "tmp",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	})

	// TLS volume from the operator-managed server certificate secret — mTLS is always enabled
	volumes = append(volumes, corev1.Volume{
		Name: "tls",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: TLSSecretName(cluster.Name),
			},
		},
	})

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
	var templates []corev1.PersistentVolumeClaim

	if isPersistenceEnabled(cluster) {
		dataSize := cluster.Spec.Persistence.Size

		dataPVC := corev1.PersistentVolumeClaim{
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
		}

		if cluster.Spec.Persistence.StorageClassName != "" {
			dataPVC.Spec.StorageClassName = &cluster.Spec.Persistence.StorageClassName
		}

		templates = append(templates, dataPVC)
	}

	// Audit PVC is independent of data persistence (B6 / AC-4.5.1):
	// audit always gets persistent storage when enabled, even when
	// spec.persistence is disabled and data runs on emptyDir.
	if cluster.Spec.Server.Audit.IsEnabled() {
		auditSize := cluster.Spec.Server.Audit.Size
		if auditSize == "" {
			auditSize = "5Gi"
		}

		auditStorageClass := cluster.Spec.Server.Audit.StorageClassName

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

// buildOperatorAffinity returns preferred (not required) hostname
// anti-affinity so small clusters co-locate instead of going Pending.
func buildOperatorAffinity(cluster *nomadv1alpha1.NomadCluster) *corev1.Affinity {
	return &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
				{
					Weight: 100,
					PodAffinityTerm: corev1.PodAffinityTerm{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: GetSelectorLabels(cluster),
						},
						TopologyKey: "kubernetes.io/hostname",
					},
				},
			},
		},
	}
}

// needsUpdate reports drift in phase-managed fields; the summary
// names the drifted field, without which unexpected rolling restarts
// are nearly undebuggable.
func (p *StatefulSetPhase) needsUpdate(existing, desired *appsv1.StatefulSet) (bool, string) {
	if *existing.Spec.Replicas != *desired.Spec.Replicas {
		return true, fmt.Sprintf("replicas %d -> %d", *existing.Spec.Replicas, *desired.Spec.Replicas)
	}

	if len(existing.Spec.Template.Spec.Containers) > 0 && len(desired.Spec.Template.Spec.Containers) > 0 {
		if existing.Spec.Template.Spec.Containers[0].Image != desired.Spec.Template.Spec.Containers[0].Image {
			return true, fmt.Sprintf("image %q -> %q",
				existing.Spec.Template.Spec.Containers[0].Image,
				desired.Spec.Template.Spec.Containers[0].Image)
		}
		// Without this, a changed startup command (e.g. the GH #11
		// retry_join self-filter) never reaches a live StatefulSet.
		if !reflect.DeepEqual(existing.Spec.Template.Spec.Containers[0].Command,
			desired.Spec.Template.Spec.Containers[0].Command) {
			return true, "container command"
		}
		// Handler-only comparison: numeric probe fields get
		// API-server defaults, so a full DeepEqual would roll forever.
		existingLiveness := existing.Spec.Template.Spec.Containers[0].LivenessProbe
		desiredLiveness := desired.Spec.Template.Spec.Containers[0].LivenessProbe
		if (existingLiveness == nil) != (desiredLiveness == nil) ||
			(existingLiveness != nil && !reflect.DeepEqual(existingLiveness.ProbeHandler, desiredLiveness.ProbeHandler)) {
			return true, "liveness probe handler"
		}
		if !reflect.DeepEqual(existing.Spec.Template.Spec.Containers[0].SecurityContext,
			desired.Spec.Template.Spec.Containers[0].SecurityContext) {
			return true, "container securityContext"
		}
		// Every env entry is operator-rendered with explicit values, so
		// DeepEqual cannot loop on API-server defaulting; the comparison
		// is what carries env additions (e.g. GOMEMLIMIT) to live
		// StatefulSets.
		if !reflect.DeepEqual(existing.Spec.Template.Spec.Containers[0].Env,
			desired.Spec.Template.Spec.Containers[0].Env) {
			return true, "container env"
		}
	}

	// Both contexts are operator-rendered with every field set, so a
	// full comparison cannot loop on API-server defaulting; it carries
	// the spec.openshift.enabled toggle to live StatefulSets, where
	// SCC-rejected pods otherwise stay rejected (neo-8nc).
	if !reflect.DeepEqual(existing.Spec.Template.Spec.SecurityContext, desired.Spec.Template.Spec.SecurityContext) {
		return true, "pod securityContext"
	}

	if reason := trustBundleDrift(existing.Spec.Template.Spec, desired.Spec.Template.Spec); reason != "" {
		return true, reason
	}

	existingChecksum := existing.Spec.Template.Annotations["checksum/config"]
	desiredChecksum := desired.Spec.Template.Annotations["checksum/config"]
	if existingChecksum != desiredChecksum {
		return true, fmt.Sprintf("checksum/config %s -> %s", existingChecksum, desiredChecksum)
	}

	existingSecretsChecksum := existing.Spec.Template.Annotations["checksum/secrets"]
	desiredSecretsChecksum := desired.Spec.Template.Annotations["checksum/secrets"]
	if existingSecretsChecksum != desiredSecretsChecksum {
		return true, fmt.Sprintf("checksum/secrets %s -> %s", existingSecretsChecksum, desiredSecretsChecksum)
	}
	return false, ""
}

func trustBundleDrift(existing, desired corev1.PodSpec) string {
	var existingMount, desiredMount *corev1.VolumeMount
	if len(existing.Containers) > 0 {
		for i := range existing.Containers[0].VolumeMounts {
			if existing.Containers[0].VolumeMounts[i].Name == "trust-bundle" {
				existingMount = &existing.Containers[0].VolumeMounts[i]
			}
		}
	}
	if len(desired.Containers) > 0 {
		for i := range desired.Containers[0].VolumeMounts {
			if desired.Containers[0].VolumeMounts[i].Name == "trust-bundle" {
				desiredMount = &desired.Containers[0].VolumeMounts[i]
			}
		}
	}
	if (existingMount == nil) != (desiredMount == nil) ||
		(existingMount != nil && (existingMount.MountPath != desiredMount.MountPath ||
			existingMount.ReadOnly != desiredMount.ReadOnly)) {
		return "trust bundle mount"
	}

	var existingVolume, desiredVolume *corev1.Volume
	for i := range existing.Volumes {
		if existing.Volumes[i].Name == "trust-bundle" {
			existingVolume = &existing.Volumes[i]
		}
	}
	for i := range desired.Volumes {
		if desired.Volumes[i].Name == "trust-bundle" {
			desiredVolume = &desired.Volumes[i]
		}
	}
	if (existingVolume == nil) != (desiredVolume == nil) ||
		(existingVolume != nil && (existingVolume.ConfigMap == nil || desiredVolume.ConfigMap == nil ||
			existingVolume.ConfigMap.Name != desiredVolume.ConfigMap.Name ||
			!reflect.DeepEqual(existingVolume.ConfigMap.Items, desiredVolume.ConfigMap.Items))) {
		return "trust bundle volume"
	}
	return ""
}

// getResourcesWithDefaults fills unset fields: requests 250m/512Mi,
// limits 2/2Gi.
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
	if licenseSecret := getLicenseSecretName(cluster); licenseSecret != "" {
		secretNames = append(secretNames, licenseSecret)
	}

	// Gossip secret
	if gossipSecret := GossipSecretName(cluster); gossipSecret != "" {
		secretNames = append(secretNames, gossipSecret)
	}

	// TLS secret — mTLS is always enabled
	secretNames = append(secretNames, TLSSecretName(cluster.Name))

	// Keyring credential/TLS secrets: rotation must roll pods
	secretNames = append(secretNames, KeyringSecretNamesFromEntries(p.KeyringEntries)...)

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

func (p *StatefulSetPhase) computeTrustBundleChecksum(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (string, error) {
	name, _, ok := TrustBundle(cluster)
	if !ok {
		return ConfigChecksum(nil), nil
	}

	cm := &corev1.ConfigMap{}
	if err := p.Client.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, cm); err != nil {
		if errors.IsNotFound(err) {
			return ConfigChecksum(nil), nil
		}
		return "", fmt.Errorf("failed to get trust bundle ConfigMap %s: %w", name, err)
	}

	data := make(map[string]string, len(cm.Data)+len(cm.BinaryData))
	for key, value := range cm.Data {
		data[key] = value
	}
	for key, value := range cm.BinaryData {
		data[key] = string(value)
	}
	return ConfigChecksum(data), nil
}

// getGossipSecretName returns the gossip secret name for the cluster.
