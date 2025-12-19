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
	"errors"
	"fmt"
	"time"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// ACLBootstrapPhase automates ACL bootstrap using the Nomad API client.
type ACLBootstrapPhase struct {
	*PhaseContext
}

// NewACLBootstrapPhase creates a new ACLBootstrapPhase.
func NewACLBootstrapPhase(ctx *PhaseContext) *ACLBootstrapPhase {
	return &ACLBootstrapPhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *ACLBootstrapPhase) Name() string {
	return "ACLBootstrap"
}

// Execute performs ACL bootstrap if enabled and not already done.
func (p *ACLBootstrapPhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	// Skip if ACLs not enabled
	if !cluster.Spec.Server.ACL.Enabled {
		p.Log.V(1).Info("ACLs disabled, skipping bootstrap")
		return OK()
	}

	// Check if already bootstrapped (secret exists)
	bootstrapSecretName := p.getBootstrapSecretName(cluster)
	existingSecret := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      bootstrapSecretName,
		Namespace: cluster.Namespace,
	}, existingSecret)
	if err == nil {
		// Already bootstrapped
		p.Log.V(1).Info("ACL bootstrap secret exists, skipping bootstrap")
		return OK()
	}
	if !k8serrors.IsNotFound(err) {
		return Error(err, "Failed to check for existing bootstrap secret")
	}

	// Wait for at least one pod to be ready before attempting bootstrap
	ready, err := p.checkPodsReady(ctx, cluster)
	if err != nil {
		return Error(err, "Failed to check pod readiness")
	}
	if !ready {
		p.Log.Info("Waiting for Nomad pods to be ready before ACL bootstrap")
		return Requeue(15*time.Second, "Waiting for pods to be ready for ACL bootstrap")
	}

	// Create Nomad API client and perform bootstrap
	result, err := p.executeBootstrap(ctx, cluster)
	if err != nil {
		// Check if already bootstrapped
		if errors.Is(err, nomad.ErrAlreadyBootstrapped) {
			p.Log.Info("ACL already bootstrapped externally")
			// Create marker secret to prevent future attempts
			return p.createMarkerSecret(ctx, cluster, bootstrapSecretName)
		}
		return Error(err, "Failed to execute ACL bootstrap")
	}

	// Create anonymous policy for basic cluster visibility
	if err := p.createAnonymousPolicy(ctx, cluster, result.SecretID); err != nil {
		p.Log.Error(err, "Failed to create anonymous policy, continuing with bootstrap")
		// Don't fail bootstrap if anonymous policy creation fails
	} else {
		p.Log.Info("Created anonymous policy for cluster visibility")
	}

	// Store token in secret
	if phaseResult := p.storeBootstrapToken(ctx, cluster, bootstrapSecretName, result); phaseResult.Error != nil {
		return phaseResult
	}

	p.Log.Info("ACL bootstrap completed successfully", "secretName", bootstrapSecretName)
	return OK()
}

func (p *ACLBootstrapPhase) getBootstrapSecretName(cluster *nomadv1alpha1.NomadCluster) string {
	if cluster.Spec.Server.ACL.BootstrapSecretName != "" {
		return cluster.Spec.Server.ACL.BootstrapSecretName
	}
	return cluster.Name + "-acl-bootstrap"
}

func (p *ACLBootstrapPhase) checkPodsReady(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (bool, error) {
	podList := &corev1.PodList{}
	if err := p.Client.List(ctx, podList,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels(GetSelectorLabels(cluster)),
	); err != nil {
		return false, err
	}

	for _, pod := range podList.Items {
		if pod.Status.Phase == corev1.PodRunning {
			for _, cond := range pod.Status.Conditions {
				if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

func (p *ACLBootstrapPhase) executeBootstrap(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (*nomad.ACLBootstrapResult, error) {
	tlsEnabled := cluster.Spec.Server.TLS.Enabled

	// Build base client config
	cfg := nomad.ClientConfig{
		TLSEnabled: tlsEnabled,
		Timeout:    30 * time.Second,
	}

	// If TLS is enabled, get the CA cert from the TLS secret
	if tlsEnabled && cluster.Spec.Server.TLS.SecretName != "" {
		tlsSecret := &corev1.Secret{}
		err := p.Client.Get(ctx, types.NamespacedName{
			Name:      cluster.Spec.Server.TLS.SecretName,
			Namespace: cluster.Namespace,
		}, tlsSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to get TLS secret for bootstrap: %w", err)
		}
		cfg.CACert = tlsSecret.Data["ca.crt"]
	}

	// Try internal service first (operator typically runs in-cluster)
	internalAddress := nomad.InternalServiceAddress(cluster.Name, cluster.Namespace, tlsEnabled)
	cfg.Address = internalAddress

	p.Log.Info("Attempting ACL bootstrap via internal service", "address", internalAddress)

	nomadClient, err := nomad.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nomad client: %w", err)
	}

	result, err := nomadClient.BootstrapACL()
	if err == nil {
		p.Log.Info("ACL bootstrap succeeded via internal service")
		return result, nil
	}

	// Check if it's a network error (internal service not reachable)
	if !nomad.IsNetworkError(err) {
		// Not a network error - return the actual error (e.g., already bootstrapped)
		return nil, err
	}

	p.Log.Info("Internal service not reachable, falling back to LoadBalancer address",
		"internalError", err.Error(),
		"loadBalancerAddress", p.AdvertiseAddress)

	// Fall back to LoadBalancer address
	loadBalancerAddress := nomad.LoadBalancerAddress(p.AdvertiseAddress, tlsEnabled)
	if loadBalancerAddress == "" {
		return nil, fmt.Errorf("ACL bootstrap failed: internal service not reachable (%v) and no LoadBalancer address available. "+
			"Ensure the operator is running in-cluster, or that the LoadBalancer service has an external IP assigned", err)
	}

	cfg.Address = loadBalancerAddress

	p.Log.Info("Attempting ACL bootstrap via LoadBalancer", "address", loadBalancerAddress)

	nomadClient, err = nomad.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nomad client for LoadBalancer: %w", err)
	}

	result, err = nomadClient.BootstrapACL()
	if err != nil {
		if nomad.IsNetworkError(err) {
			return nil, fmt.Errorf("ACL bootstrap failed: neither internal service nor LoadBalancer address reachable. "+
				"Internal service error: DNS/network issue. LoadBalancer error: %v. "+
				"To resolve: 1) Ensure pods are running and healthy, 2) Check LoadBalancer has external IP, "+
				"3) Verify network policies allow traffic on port 4646", err)
		}
		return nil, err
	}

	p.Log.Info("ACL bootstrap succeeded via LoadBalancer")
	return result, nil
}

func (p *ACLBootstrapPhase) storeBootstrapToken(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, secretName string, result *nomad.ACLBootstrapResult) PhaseResult {
	secretData := map[string]string{
		"accessor-id": result.AccessorID,
		"secret-id":   result.SecretID,
		"name":        result.Name,
		"type":        result.Type,
		"create-time": result.CreateTime.Format(time.RFC3339),
	}

	// Only include expiration-time if set (bootstrap tokens typically don't expire)
	if result.ExpirationTime != nil {
		secretData["expiration-time"] = result.ExpirationTime.Format(time.RFC3339)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Type:       corev1.SecretTypeOpaque,
		StringData: secretData,
	}

	if err := controllerutil.SetControllerReference(cluster, secret, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on bootstrap secret")
	}

	p.Log.Info("Creating ACL bootstrap secret", "name", secretName)
	if err := p.Client.Create(ctx, secret); err != nil {
		return Error(err, "Failed to create bootstrap secret")
	}

	return OK()
}

func (p *ACLBootstrapPhase) createAnonymousPolicy(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, token string) error {
	tlsEnabled := cluster.Spec.Server.TLS.Enabled

	cfg := nomad.ClientConfig{
		Token:      token,
		TLSEnabled: tlsEnabled,
		Timeout:    30 * time.Second,
	}

	// If TLS is enabled, get the CA cert
	if tlsEnabled && cluster.Spec.Server.TLS.SecretName != "" {
		tlsSecret := &corev1.Secret{}
		err := p.Client.Get(ctx, types.NamespacedName{
			Name:      cluster.Spec.Server.TLS.SecretName,
			Namespace: cluster.Namespace,
		}, tlsSecret)
		if err != nil {
			return fmt.Errorf("failed to get TLS secret: %w", err)
		}
		cfg.CACert = tlsSecret.Data["ca.crt"]
	}

	// Try internal service first, fall back to LoadBalancer
	cfg.Address = nomad.InternalServiceAddress(cluster.Name, cluster.Namespace, tlsEnabled)

	nomadClient, err := nomad.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Nomad client: %w", err)
	}

	err = nomadClient.CreateACLPolicy(token, "anonymous", "Allow anonymous read access for cluster visibility", nomad.AnonymousPolicyRules)
	if err != nil && !nomad.IsNetworkError(err) {
		return err
	}

	// If internal service failed with network error, try LoadBalancer
	loadBalancerAddress := nomad.LoadBalancerAddress(p.AdvertiseAddress, tlsEnabled)
	if err != nil && loadBalancerAddress != "" {
		cfg.Address = loadBalancerAddress
		nomadClient, err = nomad.NewClient(cfg)
		if err != nil {
			return fmt.Errorf("failed to create Nomad client for LoadBalancer: %w", err)
		}
		return nomadClient.CreateACLPolicy(token, "anonymous", "Allow anonymous read access for cluster visibility", nomad.AnonymousPolicyRules)
	}

	return err
}

func (p *ACLBootstrapPhase) createMarkerSecret(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, secretName string) PhaseResult {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
			Annotations: map[string]string{
				"nomad.hashicorp.com/bootstrap-external": "true",
			},
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"note": "ACL was bootstrapped externally. This secret is a marker to prevent re-bootstrap attempts.",
		},
	}

	if err := controllerutil.SetControllerReference(cluster, secret, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on marker secret")
	}

	if err := p.Client.Create(ctx, secret); err != nil && !k8serrors.IsAlreadyExists(err) {
		return Error(err, "Failed to create marker secret")
	}

	return OK()
}
