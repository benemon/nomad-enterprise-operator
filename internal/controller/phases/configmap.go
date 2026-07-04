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
	"maps"
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
	generator.Keyrings = p.Keyrings
	serverHCL, err := generator.Generate()
	if err != nil {
		return Error(err, "Failed to generate server.hcl")
	}

	data := map[string]string{
		serverConfigKey: serverHCL,
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
	if !maps.Equal(existing.Data, cm.Data) {
		// Diagnostic for neo-8oy: surface which key drifted so future
		// regressions are visible without a separate debug cycle. The
		// dump is bounded to ~1KB excerpts to keep the operator log
		// readable on large rendered configs.
		drift := configMapDriftSummary(existing.Data, cm.Data)
		existing.Data = cm.Data
		p.Log.Info("Auto-remediating ConfigMap drift", "name", cm.Name, "drift", drift)
		if err := p.Client.Update(ctx, existing); err != nil {
			return Error(err, "Failed to update ConfigMap")
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
