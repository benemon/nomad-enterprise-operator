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
	"fmt"
	"sort"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/hcl"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// ConfigMapPhase creates the Nomad server configuration ConfigMap.
type ConfigMapPhase struct {
	*PhaseContext
}

// NewConfigMapPhase creates a new ConfigMapPhase.
func NewConfigMapPhase(ctx *PhaseContext) *ConfigMapPhase {
	return &ConfigMapPhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *ConfigMapPhase) Name() string {
	return "ConfigMap"
}

// Execute creates or updates the Nomad server configuration ConfigMap.
func (p *ConfigMapPhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	// Generate server.hcl configuration
	generator := hcl.NewGenerator(cluster, p.AdvertiseAddress, p.GossipKey)
	serverHCL, err := generator.Generate()
	if err != nil {
		return Error(err, "Failed to generate server.hcl")
	}

	data := map[string]string{
		"server.hcl": serverHCL,
	}

	// Add extra config if specified
	if cluster.Spec.Server.ExtraConfig != "" {
		data["90-custom.hcl"] = cluster.Spec.Server.ExtraConfig
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name + "-config",
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Data: data,
	}

	if err := controllerutil.SetControllerReference(cluster, cm, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on ConfigMap")
	}

	existing := &corev1.ConfigMap{}
	err = p.Client.Get(ctx, types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			p.Log.Info("Creating ConfigMap", "name", cm.Name)
			if err := p.Client.Create(ctx, cm); err != nil {
				return Error(err, "Failed to create ConfigMap")
			}
			return OK()
		}
		return Error(err, "Failed to get ConfigMap")
	}

	// Auto-remediate: Update if content changed (handles config drift)
	if !configMapDataEqual(existing.Data, cm.Data) {
		existing.Data = cm.Data
		p.Log.Info("Auto-remediating ConfigMap drift", "name", cm.Name,
			"reason", "ConfigMap content differs from desired state")
		if err := p.Client.Update(ctx, existing); err != nil {
			return Error(err, "Failed to update ConfigMap")
		}
	}

	return OK()
}

// ConfigChecksum returns a hash of the ConfigMap content for pod annotations.
// Keys are sorted to ensure deterministic output across reconciliations.
func ConfigChecksum(data map[string]string) string {
	// Sort keys for deterministic hashing
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte(data[k]))
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

func configMapDataEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
