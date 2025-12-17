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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// AdvertisePhase resolves the LoadBalancer IP for advertise addresses.
type AdvertisePhase struct {
	*PhaseContext
}

// NewAdvertisePhase creates a new AdvertisePhase.
func NewAdvertisePhase(ctx *PhaseContext) *AdvertisePhase {
	return &AdvertisePhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *AdvertisePhase) Name() string {
	return "AdvertiseResolver"
}

// Execute resolves the advertise address from LoadBalancer or configured IP.
func (p *AdvertisePhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	// If user specified a fixed LoadBalancer IP, use it directly
	if cluster.Spec.Services.External.LoadBalancerIP != "" {
		p.AdvertiseAddress = cluster.Spec.Services.External.LoadBalancerIP
		p.Log.Info("Using configured LoadBalancer IP for advertise address",
			"address", p.AdvertiseAddress)
		return OK()
	}

	// Otherwise, we need to wait for the LoadBalancer to be assigned
	externalSvc := &corev1.Service{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      cluster.Name + "-external",
		Namespace: cluster.Namespace,
	}, externalSvc)
	if err != nil {
		return Error(err, "Failed to get external service")
	}

	// Check if LoadBalancer has been assigned
	if len(externalSvc.Status.LoadBalancer.Ingress) == 0 {
		p.Log.Info("Waiting for LoadBalancer IP assignment",
			"service", externalSvc.Name)
		return Requeue(15*time.Second, "Waiting for LoadBalancer IP assignment")
	}

	// Extract IP or hostname from LoadBalancer ingress
	ingress := externalSvc.Status.LoadBalancer.Ingress[0]
	if ingress.IP != "" {
		p.AdvertiseAddress = ingress.IP
	} else if ingress.Hostname != "" {
		p.AdvertiseAddress = ingress.Hostname
	} else {
		return Error(fmt.Errorf("LoadBalancer ingress has neither IP nor hostname"),
			"Invalid LoadBalancer ingress")
	}

	p.Log.Info("Resolved LoadBalancer address for advertise",
		"address", p.AdvertiseAddress)

	return OK()
}
