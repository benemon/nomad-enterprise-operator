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
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sort"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/hcl"
	appsv1 "k8s.io/api/apps/v1"
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

// Execute creates or updates the rendered server configuration. The
// artifact is a SECRET, not a ConfigMap: server.hcl carries the gossip
// encryption key (and inline keyring tokens), so it needs Secret-class
// custody — etcd encryption scope, RBAC class, tmpfs volume mounts.
func (p *ConfigMapPhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	// Generate server.hcl configuration
	generator := hcl.NewGenerator(cluster, p.AdvertiseAddress, p.GossipKey)
	generator.Keyrings = p.Keyrings
	serverHCL, err := generator.Generate()
	if err != nil {
		return Error(err, "Failed to generate server.hcl")
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name + "-config",
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Data: map[string][]byte{serverConfigKey: []byte(serverHCL)},
	}

	if err := controllerutil.SetControllerReference(cluster, secret, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on config Secret")
	}

	existing := &corev1.Secret{}
	err = p.Client.Get(ctx, types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			p.Log.Info("Creating config Secret", "name", secret.Name)
			if err := p.Client.Create(ctx, secret); err != nil {
				return Error(err, "Failed to create config Secret")
			}
			return p.reapLegacyConfigMap(ctx, cluster)
		}
		return Error(err, "Failed to get config Secret")
	}

	// Auto-remediate: Update if content changed (handles config drift)
	if !bytes.Equal(existing.Data[serverConfigKey], secret.Data[serverConfigKey]) {
		// Diagnostic for neo-8oy: surface which key drifted so future
		// regressions are visible without a separate debug cycle. The
		// dump is bounded to ~1KB excerpts to keep the operator log
		// readable on large rendered configs.
		drift := configMapDriftSummary(
			map[string]string{serverConfigKey: string(existing.Data[serverConfigKey])},
			map[string]string{serverConfigKey: serverHCL})
		existing.Data = secret.Data
		p.Log.Info("Auto-remediating config drift", "name", secret.Name, "drift", drift)
		if err := p.Client.Update(ctx, existing); err != nil {
			return Error(err, "Failed to update config Secret")
		}
	}

	return p.reapLegacyConfigMap(ctx, cluster)
}

// reapLegacyConfigMap deletes the pre-Secret rendered-config ConfigMap
// once the StatefulSet is fully rolled onto the Secret-backed template.
// Deleting it earlier risks kubelet volume-sync errors on old pods
// still mounting it.
func (p *ConfigMapPhase) reapLegacyConfigMap(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	cm := &corev1.ConfigMap{}
	err := p.Client.Get(ctx, types.NamespacedName{Name: cluster.Name + "-config", Namespace: cluster.Namespace}, cm)
	if err != nil {
		if errors.IsNotFound(err) {
			return OK()
		}
		return Error(err, "Failed to check legacy config ConfigMap")
	}
	sts := &appsv1.StatefulSet{}
	if err := p.Client.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: cluster.Namespace}, sts); err != nil {
		return OK() // no StatefulSet yet: keep the CM until the roll is provable
	}
	usesSecret := false
	for _, v := range sts.Spec.Template.Spec.Volumes {
		if v.Name == "config" && v.Secret != nil {
			usesSecret = true
		}
	}
	if usesSecret && statefulSetFullyRolled(ctx, p.Client, cluster) {
		p.Log.Info("Deleting legacy config ConfigMap", "name", cm.Name)
		if err := p.Client.Delete(ctx, cm); err != nil && !errors.IsNotFound(err) {
			return Error(err, "Failed to delete legacy config ConfigMap")
		}
	}
	return OK()
}

// configMapDriftSummary returns a structured comparison of two CM
// data maps, naming the keys that differ and showing the position of
// the first byte mismatch in each shared key. Used by the
// auto-remediation log so operators can see what drifted without
// having to extract both versions out of band.
func configMapDriftSummary(existing, desired map[string]string) map[string]string {
	out := map[string]string{}
	keys := map[string]bool{}
	for k := range existing {
		keys[k] = true
	}
	for k := range desired {
		keys[k] = true
	}
	for k := range keys {
		e, eok := existing[k]
		d, dok := desired[k]
		switch {
		case !eok:
			out[k] = "key added in desired"
		case !dok:
			out[k] = "key removed in desired"
		case e == d:
			// no drift
		default:
			diffAt := firstDiffOffset(e, d)
			out[k] = fmt.Sprintf("first diff at byte %d: existing=%q desired=%q",
				diffAt, snippet(e, diffAt), snippet(d, diffAt))
		}
	}
	return out
}

func firstDiffOffset(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

func snippet(s string, around int) string {
	start := around - 20
	if start < 0 {
		start = 0
	}
	end := around + 40
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
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
