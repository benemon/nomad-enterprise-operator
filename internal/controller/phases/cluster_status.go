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
	"time"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClusterStatusPhase queries the Nomad API to enrich cluster status.
type ClusterStatusPhase struct {
	*PhaseContext
}

// NewClusterStatusPhase creates a new ClusterStatusPhase.
func NewClusterStatusPhase(ctx *PhaseContext) *ClusterStatusPhase {
	return &ClusterStatusPhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *ClusterStatusPhase) Name() string {
	return "ClusterStatus"
}

// Execute queries the Nomad API for cluster status information.
func (p *ClusterStatusPhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	// Only run status check if we have ready pods
	ready, err := p.checkPodsReady(ctx, cluster)
	if err != nil {
		// Don't fail reconciliation for status check errors
		p.Log.V(1).Info("Failed to check pod readiness for status", "error", err)
		return OK()
	}
	if !ready {
		// No ready pods yet, skip status enrichment
		return OK()
	}

	// Create Nomad client
	nomadClient, err := p.createNomadClient(ctx, cluster)
	if err != nil {
		// Don't fail reconciliation for status check errors
		p.Log.V(1).Info("Failed to create Nomad client for status check", "error", err)
		return OK()
	}

	// Get ACL token for authenticated API calls
	var aclToken string
	if cluster.Spec.Server.ACL.Enabled {
		aclToken, _ = p.getACLToken(ctx, cluster)
	}

	// Get leader information
	leader, err := nomadClient.GetLeader()
	if err != nil {
		p.Log.V(1).Info("Failed to get leader info", "error", err)
	} else {
		p.LeaderAddress = leader
		p.Log.V(1).Info("Got leader address", "leader", leader)
	}

	// Get server health
	health, err := nomadClient.CheckHealth()
	if err != nil {
		p.Log.V(1).Info("Failed to get cluster health", "error", err)
	} else {
		p.ClusterHealthy = health.Server.OK
		p.Log.V(1).Info("Got cluster health", "healthy", health.Server.OK)
	}

	// Get peer count
	peers, err := nomadClient.GetPeers()
	if err != nil {
		p.Log.V(1).Info("Failed to get peers", "error", err)
	} else {
		p.PeerCount = len(peers)
		p.Log.V(1).Info("Got peer count", "count", len(peers))
	}

	// Get license information
	license, err := nomadClient.GetLicense(ctx, aclToken)
	if err != nil {
		p.Log.V(1).Info("Failed to get license info", "error", err)
		p.LicenseError = err
	} else {
		p.License = &nomadv1alpha1.LicenseStatus{
			Valid:           true, // If we got a response, it's valid
			LicenseID:       license.LicenseID,
			ExpirationTime:  license.ExpirationTime,
			TerminationTime: license.TerminationTime,
			Features:        license.Features,
		}
		p.Log.V(1).Info("Got license info", "licenseId", license.LicenseID, "expiration", license.ExpirationTime)
	}

	// Get autopilot health information
	autopilot, err := nomadClient.GetAutopilotHealth(ctx, aclToken)
	if err != nil {
		p.Log.V(1).Info("Failed to get autopilot health", "error", err)
		p.AutopilotError = err
	} else {
		servers := make([]nomadv1alpha1.ServerStatus, 0, len(autopilot.Servers))
		for _, s := range autopilot.Servers {
			servers = append(servers, nomadv1alpha1.ServerStatus{
				Name:        s.Name,
				ID:          s.ID,
				Address:     s.Address,
				Healthy:     s.Healthy,
				Voter:       s.Voter,
				Leader:      s.Leader,
				StableSince: s.StableSince,
				LastContact: s.LastContact,
			})
		}
		p.Autopilot = &nomadv1alpha1.AutopilotStatus{
			Healthy:          autopilot.Healthy,
			FailureTolerance: autopilot.FailureTolerance,
			Voters:           autopilot.Voters,
			Servers:          servers,
		}
		p.Log.V(1).Info("Got autopilot health", "healthy", autopilot.Healthy, "failureTolerance", autopilot.FailureTolerance)
	}

	return OK()
}

func (p *ClusterStatusPhase) checkPodsReady(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (bool, error) {
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

func (p *ClusterStatusPhase) createNomadClient(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (*nomad.Client, error) {
	tlsEnabled := cluster.Spec.Server.TLS.Enabled

	cfg := nomad.ClientConfig{
		TLSEnabled: tlsEnabled,
		Timeout:    10 * time.Second, // Short timeout for status checks
	}

	// If ACL is enabled and bootstrapped, use the token
	if cluster.Spec.Server.ACL.Enabled {
		token, err := p.getACLToken(ctx, cluster)
		if err == nil && token != "" {
			cfg.Token = token
		}
	}

	// If TLS is enabled, get CA cert
	if tlsEnabled && cluster.Spec.Server.TLS.SecretName != "" {
		tlsSecret := &corev1.Secret{}
		err := p.Client.Get(ctx, types.NamespacedName{
			Name:      cluster.Spec.Server.TLS.SecretName,
			Namespace: cluster.Namespace,
		}, tlsSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to get TLS secret: %w", err)
		}
		cfg.CACert = tlsSecret.Data["ca.crt"]
	}

	// Try internal service first (operator typically runs in-cluster)
	internalAddress := nomad.InternalServiceAddress(cluster.Name, cluster.Namespace, tlsEnabled)
	cfg.Address = internalAddress

	nomadClient, err := nomad.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	// Test connectivity with a quick health check
	_, err = nomadClient.GetLeader()
	if err == nil {
		return nomadClient, nil
	}

	// If internal service failed with network error, try LoadBalancer
	loadBalancerAddress := nomad.LoadBalancerAddress(p.AdvertiseAddress, tlsEnabled)
	if nomad.IsNetworkError(err) && loadBalancerAddress != "" {
		cfg.Address = loadBalancerAddress
		p.Log.V(1).Info("Internal service not reachable, using LoadBalancer for status",
			"loadBalancerAddress", loadBalancerAddress)
		return nomad.NewClient(cfg)
	}

	// Return the original client even if connectivity test failed
	// The caller will handle errors from individual API calls
	return nomadClient, nil
}

func (p *ClusterStatusPhase) getACLToken(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (string, error) {
	secretName := cluster.Name + "-acl-bootstrap"
	if cluster.Spec.Server.ACL.BootstrapSecretName != "" {
		secretName = cluster.Spec.Server.ACL.BootstrapSecretName
	}

	secret := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, secret)
	if err != nil {
		return "", err
	}

	return string(secret.Data["secret-id"]), nil
}
