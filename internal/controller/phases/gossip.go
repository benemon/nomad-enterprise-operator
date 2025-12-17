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
	"crypto/rand"
	"encoding/base64"
	"fmt"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// GossipPhase manages the gossip encryption key.
type GossipPhase struct {
	*PhaseContext
}

// NewGossipPhase creates a new GossipPhase.
func NewGossipPhase(ctx *PhaseContext) *GossipPhase {
	return &GossipPhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *GossipPhase) Name() string {
	return "GossipKey"
}

// Execute ensures a gossip encryption key exists, either from an external secret or auto-generated.
func (p *GossipPhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	secretKey := cluster.Spec.Gossip.SecretKey
	if secretKey == "" {
		secretKey = "gossip-key"
	}

	// If user provided external secret name, use it (VSO, sealed-secrets, etc.)
	if cluster.Spec.Gossip.SecretName != "" {
		return p.readExternalSecret(ctx, cluster, secretKey)
	}

	// Otherwise, check for operator-managed secret
	return p.ensureOperatorManagedSecret(ctx, cluster, secretKey)
}

func (p *GossipPhase) readExternalSecret(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, secretKey string) PhaseResult {
	secret := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      cluster.Spec.Gossip.SecretName,
		Namespace: cluster.Namespace,
	}, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return Error(fmt.Errorf("gossip secret %q not found", cluster.Spec.Gossip.SecretName),
				"External gossip secret not found - ensure VSO or external-secrets has created it")
		}
		return Error(err, "Failed to get external gossip secret")
	}

	gossipKey, ok := secret.Data[secretKey]
	if !ok {
		return Error(fmt.Errorf("key %q not found in gossip secret", secretKey),
			"Gossip secret missing required key")
	}

	// Store in context for ConfigMap phase
	p.GossipKey = string(gossipKey)
	p.Log.Info("Using external gossip key secret", "secretName", cluster.Spec.Gossip.SecretName)

	return OK()
}

func (p *GossipPhase) ensureOperatorManagedSecret(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, secretKey string) PhaseResult {
	secretName := cluster.Name + "-gossip"

	// Check if operator-managed secret already exists (preserve across upgrades)
	existing := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, existing)

	if err == nil {
		// Secret exists - read and use existing key
		gossipKey, ok := existing.Data[secretKey]
		if !ok {
			return Error(fmt.Errorf("key %q not found in operator-managed gossip secret", secretKey),
				"Operator-managed gossip secret is corrupted")
		}
		p.GossipKey = string(gossipKey)
		p.Log.V(1).Info("Using existing operator-managed gossip key", "secretName", secretName)
		return OK()
	}

	if !errors.IsNotFound(err) {
		return Error(err, "Failed to check for operator-managed gossip secret")
	}

	// First deploy - generate new gossip key
	gossipKey, err := generateGossipKey()
	if err != nil {
		return Error(err, "Failed to generate gossip key")
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			secretKey: []byte(gossipKey),
		},
	}

	// Set owner reference so it's cleaned up with the cluster
	if err := controllerutil.SetControllerReference(cluster, secret, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on gossip secret")
	}

	p.Log.Info("Creating operator-managed gossip key secret", "name", secretName)
	if err := p.Client.Create(ctx, secret); err != nil {
		return Error(err, "Failed to create gossip secret")
	}

	p.GossipKey = gossipKey
	return OK()
}

// generateGossipKey generates a 32-byte base64-encoded gossip encryption key.
// This matches the format expected by `nomad operator gossip keyring generate`.
func generateGossipKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
