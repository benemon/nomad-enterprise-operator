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
	"fmt"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
)

// SecretsPhase validates required secrets exist.
type SecretsPhase struct {
	*PhaseContext
}

// NewSecretsPhase creates a new SecretsPhase.
func NewSecretsPhase(ctx *PhaseContext) *SecretsPhase {
	return &SecretsPhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *SecretsPhase) Name() string {
	return "Secrets"
}

// Execute validates that all required secrets exist.
func (p *SecretsPhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	// Validate license secret exists
	if result := p.validateLicenseSecret(ctx, cluster); result.Error != nil || result.Requeue {
		return result
	}

	// Validate TLS secret if TLS is enabled
	if cluster.Spec.Server.TLS.Enabled {
		if result := p.validateTLSSecret(ctx, cluster); result.Error != nil || result.Requeue {
			return result
		}
	}

	// Validate S3 credentials if snapshots are enabled
	if cluster.Spec.Server.Snapshot.Enabled && cluster.Spec.Server.Snapshot.S3.CredentialsSecretName != "" {
		if result := p.validateS3CredentialsSecret(ctx, cluster); result.Error != nil || result.Requeue {
			return result
		}
	}

	return OK()
}

func (p *SecretsPhase) validateLicenseSecret(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	secretKey := cluster.Spec.License.SecretKey
	if secretKey == "" {
		secretKey = "license"
	}

	secret := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      cluster.Spec.License.SecretName,
		Namespace: cluster.Namespace,
	}, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return Error(fmt.Errorf("license secret %q not found", cluster.Spec.License.SecretName),
				"License secret not found - create it with your Nomad Enterprise license")
		}
		return Error(err, "Failed to get license secret")
	}

	if _, ok := secret.Data[secretKey]; !ok {
		return Error(fmt.Errorf("key %q not found in license secret", secretKey),
			"License secret missing required key")
	}

	p.Log.V(1).Info("License secret validated", "secretName", cluster.Spec.License.SecretName)
	return OK()
}

func (p *SecretsPhase) validateTLSSecret(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	if cluster.Spec.Server.TLS.SecretName == "" {
		return Error(fmt.Errorf("TLS is enabled but no secretName specified"),
			"TLS secret name required when TLS is enabled")
	}

	secret := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      cluster.Spec.Server.TLS.SecretName,
		Namespace: cluster.Namespace,
	}, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return Error(fmt.Errorf("TLS secret %q not found", cluster.Spec.Server.TLS.SecretName),
				"TLS secret not found - create it with ca.crt, server.crt, and server.key")
		}
		return Error(err, "Failed to get TLS secret")
	}

	// Validate required keys
	requiredKeys := []string{"ca.crt", "server.crt", "server.key"}
	for _, key := range requiredKeys {
		if _, ok := secret.Data[key]; !ok {
			return Error(fmt.Errorf("key %q not found in TLS secret", key),
				"TLS secret missing required key: "+key)
		}
	}

	p.Log.V(1).Info("TLS secret validated", "secretName", cluster.Spec.Server.TLS.SecretName)
	return OK()
}

func (p *SecretsPhase) validateS3CredentialsSecret(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	secretName := cluster.Spec.Server.Snapshot.S3.CredentialsSecretName

	secret := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return Error(fmt.Errorf("S3 credentials secret %q not found", secretName),
				"S3 credentials secret not found for snapshots")
		}
		return Error(err, "Failed to get S3 credentials secret")
	}

	// Validate required keys
	requiredKeys := []string{"access-key-id", "secret-access-key"}
	for _, key := range requiredKeys {
		if _, ok := secret.Data[key]; !ok {
			return Error(fmt.Errorf("key %q not found in S3 credentials secret", key),
				"S3 credentials secret missing required key: "+key)
		}
	}

	p.Log.V(1).Info("S3 credentials secret validated", "secretName", secretName)
	return OK()
}
