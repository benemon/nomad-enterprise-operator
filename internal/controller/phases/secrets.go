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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// SecretsPhase validates and creates required secrets.
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

// Execute validates external secrets and creates managed secrets from inline values.
func (p *SecretsPhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	// Handle license secret (inline or external)
	if result := p.handleLicenseSecret(ctx, cluster); result.Error != nil || result.Requeue {
		return result
	}

	// Handle TLS secret if TLS is enabled (inline or external)
	if cluster.Spec.Server.TLS.Enabled {
		if result := p.handleTLSSecret(ctx, cluster); result.Error != nil || result.Requeue {
			return result
		}
	}

	// Handle S3 credentials if snapshots are enabled (inline or external)
	if cluster.Spec.Server.Snapshot.Enabled {
		if result := p.handleS3CredentialsSecret(ctx, cluster); result.Error != nil || result.Requeue {
			return result
		}
	}

	return OK()
}

// handleLicenseSecret creates or validates the license secret.
func (p *SecretsPhase) handleLicenseSecret(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	// Inline license - create/update managed secret
	if cluster.Spec.License.Value != "" {
		return p.ensureManagedSecret(ctx, cluster, managedSecretConfig{
			name:   cluster.Name + "-license",
			labels: GetLabels(cluster),
			data: map[string]string{
				"license": cluster.Spec.License.Value,
			},
		})
	}

	// External license - validate it exists
	if cluster.Spec.License.SecretName == "" {
		return Error(fmt.Errorf("no license configured"),
			"Either license.secretName or license.value must be specified")
	}

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

// handleTLSSecret creates or validates the TLS secret.
func (p *SecretsPhase) handleTLSSecret(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	tls := cluster.Spec.Server.TLS

	// Inline TLS - create/update managed secret
	if tls.CACert != "" && tls.ServerCert != "" && tls.ServerKey != "" {
		return p.ensureManagedSecret(ctx, cluster, managedSecretConfig{
			name:   cluster.Name + "-tls",
			labels: GetLabels(cluster),
			data: map[string]string{
				"ca.crt":     tls.CACert,
				"server.crt": tls.ServerCert,
				"server.key": tls.ServerKey,
			},
		})
	}

	// External TLS - validate it exists
	if tls.SecretName == "" {
		return Error(fmt.Errorf("TLS is enabled but no certificates specified"),
			"When TLS is enabled, either secretName or inline certificates (caCert, serverCert, serverKey) must be provided")
	}

	secret := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      tls.SecretName,
		Namespace: cluster.Namespace,
	}, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return Error(fmt.Errorf("TLS secret %q not found", tls.SecretName),
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

	p.Log.V(1).Info("TLS secret validated", "secretName", tls.SecretName)
	return OK()
}

// handleS3CredentialsSecret creates or validates the S3 credentials secret.
func (p *SecretsPhase) handleS3CredentialsSecret(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	s3 := cluster.Spec.Server.Snapshot.S3

	// Inline S3 credentials - create/update managed secret
	if s3.AccessKeyID != "" && s3.SecretAccessKey != "" {
		return p.ensureManagedSecret(ctx, cluster, managedSecretConfig{
			name:   cluster.Name + "-s3-credentials",
			labels: GetLabels(cluster),
			data: map[string]string{
				"access-key-id":     s3.AccessKeyID,
				"secret-access-key": s3.SecretAccessKey,
			},
		})
	}

	// External S3 credentials - validate if specified
	if s3.CredentialsSecretName == "" {
		// No credentials specified - might be using IAM roles
		p.Log.V(1).Info("No S3 credentials specified, assuming IAM role authentication")
		return OK()
	}

	secret := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      s3.CredentialsSecretName,
		Namespace: cluster.Namespace,
	}, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return Error(fmt.Errorf("S3 credentials secret %q not found", s3.CredentialsSecretName),
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

	p.Log.V(1).Info("S3 credentials secret validated", "secretName", s3.CredentialsSecretName)
	return OK()
}

// managedSecretConfig defines configuration for a managed secret.
type managedSecretConfig struct {
	name   string
	labels map[string]string
	data   map[string]string
}

// ensureManagedSecret creates or updates a secret managed by the operator.
func (p *SecretsPhase) ensureManagedSecret(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, cfg managedSecretConfig) PhaseResult {
	// Convert string data to byte data
	byteData := make(map[string][]byte, len(cfg.data))
	for k, v := range cfg.data {
		byteData[k] = []byte(v)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cfg.name,
			Namespace: cluster.Namespace,
			Labels:    cfg.labels,
			Annotations: map[string]string{
				"nomad.hashicorp.com/managed": "true",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: byteData,
	}

	if err := controllerutil.SetControllerReference(cluster, secret, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on managed secret")
	}

	// Check if secret exists
	existing := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      cfg.name,
		Namespace: cluster.Namespace,
	}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			// Create new secret
			p.Log.Info("Creating managed secret", "name", cfg.name)
			if err := p.Client.Create(ctx, secret); err != nil {
				return Error(err, "Failed to create managed secret")
			}
			return OK()
		}
		return Error(err, "Failed to check existing secret")
	}

	// Update existing secret if data changed
	needsUpdate := false
	for key, value := range cfg.data {
		if string(existing.Data[key]) != value {
			needsUpdate = true
			break
		}
	}

	if needsUpdate {
		existing.Data = byteData
		p.Log.Info("Updating managed secret", "name", cfg.name)
		if err := p.Client.Update(ctx, existing); err != nil {
			return Error(err, "Failed to update managed secret")
		}
	}

	p.Log.V(1).Info("Managed secret ensured", "name", cfg.name)
	return OK()
}

// GetLicenseSecretName returns the effective license secret name.
func GetLicenseSecretName(cluster *nomadv1alpha1.NomadCluster) string {
	if cluster.Spec.License.Value != "" {
		return cluster.Name + "-license"
	}
	return cluster.Spec.License.SecretName
}

// GetTLSSecretName returns the effective TLS secret name.
func GetTLSSecretName(cluster *nomadv1alpha1.NomadCluster) string {
	if cluster.Spec.Server.TLS.CACert != "" {
		return cluster.Name + "-tls"
	}
	return cluster.Spec.Server.TLS.SecretName
}

// GetS3CredentialsSecretName returns the effective S3 credentials secret name.
func GetS3CredentialsSecretName(cluster *nomadv1alpha1.NomadCluster) string {
	if cluster.Spec.Server.Snapshot.S3.AccessKeyID != "" {
		return cluster.Name + "-s3-credentials"
	}
	return cluster.Spec.Server.Snapshot.S3.CredentialsSecretName
}
