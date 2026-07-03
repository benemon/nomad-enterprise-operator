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
	"github.com/hashicorp/nomad-enterprise-operator/internal/metrics"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// SecretKeyAccessorID is the data key under which a Nomad ACL token's accessor
// ID is stored in Kubernetes Secrets owned by this operator.
const SecretKeyAccessorID = "accessor-id"

// Operator-owned ACL policy names and descriptions. The description is
// part of the desired state compared by reconcileOperatorPolicies, so
// it must be defined once and shared by every write site.
const (
	anonymousPolicyName             = "anonymous"
	anonymousPolicyDescription      = "Allow anonymous read access for cluster visibility"
	operatorStatusPolicyDescription = "Operator day-2 status API access (operator:read, agent:read)"
)

// OperatorManagementSecretName returns the deterministic name of the
// Secret (and Nomad token) for the cluster's operator management token
// (C4). The name is the durable truth for cleanup on deletion;
// status.operatorManagementSecretName is cache only. There is no
// matching Nomad policy: the token is management-type, because Nomad
// has no ACL-management policy grammar (see nomad.CreateManagementACLToken).
func OperatorManagementSecretName(clusterName string) string {
	return clusterName + "-operator-management"
}

// BootstrapSecretClusterLabel marks the bootstrap-token Secret with its
// owning cluster (C3 / AC-2.4.1). The Secret deliberately has no
// ownerReference — see bootstrapSecretLabels — so this label is the only
// machine-readable link back to the NomadCluster, used for the orphan
// cleanup documented in the README threat model.
const BootstrapSecretClusterLabel = "nomad.hashicorp.com/cluster"

// bootstrapSecretLabels returns the labels for the bootstrap-token
// Secret: the standard set plus the cluster back-link label. Shared by
// the token-store and external-bootstrap-marker creation sites and the
// pre-C3 retrofit so the label set cannot drift between them.
func bootstrapSecretLabels(cluster *nomadv1alpha1.NomadCluster) map[string]string {
	labels := GetLabels(cluster)
	labels[BootstrapSecretClusterLabel] = cluster.Name
	return labels
}

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
	bootstrapSecretName := BootstrapSecretName(cluster.Name)
	existingSecret := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      bootstrapSecretName,
		Namespace: cluster.Namespace,
	}, existingSecret)
	if err == nil {
		// Already bootstrapped — still ensure the operator status token exists.
		// This handles clusters bootstrapped before the operator status token
		// feature was deployed. ensureOperatorStatusToken is idempotent.
		bootstrapToken := string(existingSecret.Data[SecretKeySecretID])
		if bootstrapToken != "" {
			// C4 (AC-2.4.4/2.4.5): ensure the dedicated management
			// token exists, then use IT — never the bootstrap token — for
			// every downstream Nomad-side write. The bootstrap token's
			// only remaining jobs are minting the management token and
			// finalizer cleanup.
			managementToken, err := p.ensureOperatorManagementToken(ctx, cluster, bootstrapToken)
			if err != nil {
				p.Log.Error(err, "Failed to ensure operator management token; skipping dependent ACL reconciliation until next reconcile")
				return OK()
			}
			if phaseResult := p.ensureOperatorStatusToken(ctx, cluster, managementToken); phaseResult.Error != nil {
				p.Log.Error(phaseResult.Error, "Failed to create operator status token, continuing")
			}
			// C2 (AC-2.5.1–3): reconcile the operator-owned policies via
			// GET-then-write-on-diff each reconcile, so manual edits are
			// reverted. Non-fatal, consistent with the surrounding calls.
			if err := p.reconcileOperatorPolicies(cluster, managementToken); err != nil {
				p.Log.Error(err, "Failed to reconcile operator ACL policies, continuing")
			}
		} else {
			p.Log.V(1).Info("ACL bootstrap secret exists but has no secret-id, skipping operator status token")
		}
		return OK()
	}
	if !k8serrors.IsNotFound(err) {
		return Error(err, "Failed to check for existing bootstrap secret")
	}

	// Wait for at least one pod to be ready before attempting bootstrap
	ready, err := p.CheckPodsReady(ctx, cluster)
	if err != nil {
		return Error(err, "Failed to check pod readiness")
	}
	if !ready {
		p.Log.Info("Waiting for Nomad pods to be ready before ACL bootstrap")
		return Requeue(15*time.Second, "Waiting for pods to be ready for ACL bootstrap")
	}

	// Create Nomad API client and perform bootstrap
	result, err := p.executeBootstrap(cluster)
	if err != nil {
		// Check if already bootstrapped
		if errors.Is(err, nomad.ErrAlreadyBootstrapped) {
			p.Log.Info("ACL already bootstrapped externally")
			// Create marker secret to prevent future attempts
			return p.createMarkerSecret(ctx, cluster, bootstrapSecretName)
		}
		// D4e / AC-8.1.5: count genuine bootstrap failures (external
		// bootstrap above is not a failure; pod-not-ready never reaches
		// this point).
		metrics.ACLBootstrapFailures.WithLabelValues(cluster.Name, cluster.Namespace).Inc()
		return Error(err, "Failed to execute ACL bootstrap")
	}

	// Store the bootstrap token FIRST — BootstrapACL is one-shot, so a
	// failure after this point must never lose the token.
	if phaseResult := p.storeBootstrapToken(ctx, cluster, bootstrapSecretName, result); phaseResult.Error != nil {
		return phaseResult
	}

	// C4 (AC-2.4.4): mint the dedicated management token — the only
	// write the bootstrap token performs. Everything below authenticates
	// with the management token. On failure, the already-bootstrapped
	// branch retries on the next reconcile.
	managementToken, err := p.ensureOperatorManagementToken(ctx, cluster, result.SecretID)
	if err != nil {
		p.Log.Error(err, "Failed to create operator management token; deferring dependent ACL setup to next reconcile")
		return OK()
	}

	// Create the operator-owned policies (anonymous for basic cluster
	// visibility; operator-status ahead of its token below). First
	// reconcile after bootstrap, so the GETs miss and the policies are
	// written.
	if err := p.reconcileOperatorPolicies(cluster, managementToken); err != nil {
		p.Log.Error(err, "Failed to create operator ACL policies, continuing with bootstrap")
		// Don't fail bootstrap if policy creation fails
	}

	// Create narrow-scope operator status token for day-2 API calls
	if phaseResult := p.ensureOperatorStatusToken(ctx, cluster, managementToken); phaseResult.Error != nil {
		p.Log.Error(phaseResult.Error, "Failed to create operator status token, continuing with bootstrap")
		// Don't fail bootstrap if operator status token creation fails
	}

	p.Log.Info("ACL bootstrap completed successfully", "secretName", bootstrapSecretName)
	return OK()
}

func (p *ACLBootstrapPhase) executeBootstrap(cluster *nomadv1alpha1.NomadCluster) (*nomad.ACLBootstrapResult, error) {
	cfg := p.BuildClientConfig(30*time.Second, "")

	// Try internal service first (operator typically runs in-cluster)
	internalAddress := nomad.InternalServiceAddress(cluster.Name, cluster.Namespace, true)
	cfg.Address = internalAddress

	p.Log.Info("Attempting ACL bootstrap via internal service", "address", internalAddress)

	nomadClient, err := p.NewNomadClient(cfg)
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
	loadBalancerAddress := nomad.LoadBalancerAddress(p.AdvertiseAddress, true)
	if loadBalancerAddress == "" {
		return nil, fmt.Errorf("ACL bootstrap failed: internal service not reachable (%v) and no LoadBalancer address available. "+
			"Ensure the operator is running in-cluster, or that the LoadBalancer service has an external IP assigned", err)
	}

	cfg.Address = loadBalancerAddress

	p.Log.Info("Attempting ACL bootstrap via LoadBalancer", "address", loadBalancerAddress)

	nomadClient, err = p.NewNomadClient(cfg)
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
		SecretKeyAccessorID: result.AccessorID,
		SecretKeySecretID:   result.SecretID,
		"name":              result.Name,
		"type":              result.Type,
		"create-time":       result.CreateTime.Format(time.RFC3339),
	}

	// Only include expiration-time if set (bootstrap tokens typically don't expire)
	if result.ExpirationTime != nil {
		secretData["expiration-time"] = result.ExpirationTime.Format(time.RFC3339)
	}

	// C3 / AC-2.4.1: intentionally NO ownerReference. The bootstrap token
	// must outlive Kubernetes GC so the deletion finalizer can use it for
	// Nomad-side ACL cleanup; handleDeletion deletes this Secret
	// explicitly, last. The cluster label is the link back to the owner.
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels:    bootstrapSecretLabels(cluster),
		},
		Type:       corev1.SecretTypeOpaque,
		StringData: secretData,
	}

	p.Log.Info("Creating ACL bootstrap secret", "name", secretName)
	if err := p.Client.Create(ctx, secret); err != nil {
		return Error(err, "Failed to create bootstrap secret")
	}

	return OK()
}

// reconcileOperatorPolicies enforces observed-state diff semantics
// (C2 / AC-2.5.1–3) for the operator-owned ACL policies: GET each
// policy and write only when it is missing or its description/rules
// have drifted from desired. Manual edits are reverted on the next
// reconcile; when observed matches desired, no write call is made.
func (p *ACLBootstrapPhase) reconcileOperatorPolicies(cluster *nomadv1alpha1.NomadCluster, token string) error {
	desired := []nomad.ACLPolicyResult{
		{
			Name:        anonymousPolicyName,
			Description: anonymousPolicyDescription,
			Rules:       nomad.AnonymousPolicyRules,
		},
		{
			Name:        OperatorStatusName(cluster.Name),
			Description: operatorStatusPolicyDescription,
			Rules:       nomad.OperatorStatusPolicyRules,
		},
	}

	return p.runNomadWithFallback(cluster, 30*time.Second, token, func(nomadClient nomad.NomadAPI) error {
		for _, want := range desired {
			observed, err := nomadClient.GetACLPolicy(token, want.Name)
			if err != nil {
				return err
			}

			// AC-2.5.1: observed matches desired — no write.
			if observed != nil && observed.Description == want.Description && observed.Rules == want.Rules {
				continue
			}

			// AC-2.5.2 / 2.5.3: missing or drifted — upsert back to desired.
			if err := nomadClient.CreateACLPolicy(token, want.Name, want.Description, want.Rules); err != nil {
				return err
			}
			p.Log.Info("Reconciled operator ACL policy", "policy", want.Name, "created", observed == nil)
		}
		return nil
	})
}

// ensureOperatorManagementToken ensures the C4 dedicated management
// token exists and returns its secret-id. The bootstrap
// token authenticates the policy and token creation (its only remaining
// write); all downstream Nomad-side writes use the returned token
// (AC-2.4.5). Idempotent via the deterministic Secret name — if the
// Secret exists its stored token is returned, and the status cache
// field is (re)persisted when missing.
func (p *ACLBootstrapPhase) ensureOperatorManagementToken(
	ctx context.Context,
	cluster *nomadv1alpha1.NomadCluster,
	bootstrapToken string,
) (string, error) {
	secretName := OperatorManagementSecretName(cluster.Name)

	existing := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, existing)
	if err == nil {
		token := string(existing.Data[SecretKeySecretID])
		if token == "" {
			return "", fmt.Errorf("management token secret %q has empty secret-id", secretName)
		}
		if cluster.Status.OperatorManagementSecretName == "" {
			patchBase := cluster.DeepCopy()
			cluster.Status.OperatorManagementSecretName = secretName
			if patchErr := p.Client.Status().Patch(ctx, cluster, client.MergeFrom(patchBase)); patchErr != nil {
				return "", fmt.Errorf("failed to persist management token status field: %w", patchErr)
			}
		}
		return token, nil
	}
	if !k8serrors.IsNotFound(err) {
		return "", fmt.Errorf("failed to check for management token secret: %w", err)
	}

	// Management-type token: Nomad's only mechanism for ACL-write
	// capability (no policy exists or is needed — see
	// nomad.CreateManagementACLToken for why).
	var newToken *nomad.ACLTokenResult
	if err := p.runNomadWithFallback(cluster, 30*time.Second, bootstrapToken, func(nomadClient nomad.NomadAPI) error {
		t, terr := nomadClient.CreateManagementACLToken(bootstrapToken, secretName)
		if terr == nil {
			newToken = t
		}
		return terr
	}); err != nil {
		return "", fmt.Errorf("failed to create operator management ACL token: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			SecretKeyAccessorID: newToken.AccessorID,
			SecretKeySecretID:   newToken.SecretID,
		},
	}
	if err := controllerutil.SetControllerReference(cluster, secret, p.Scheme); err != nil {
		return "", fmt.Errorf("failed to set owner reference on management token secret: %w", err)
	}
	p.Log.Info("Creating operator management token secret", "name", secretName)
	if err := p.Client.Create(ctx, secret); err != nil {
		return "", fmt.Errorf("failed to create management token secret: %w", err)
	}

	patchBase := cluster.DeepCopy()
	cluster.Status.OperatorManagementSecretName = secretName
	if err := p.Client.Status().Patch(ctx, cluster, client.MergeFrom(patchBase)); err != nil {
		return "", fmt.Errorf("failed to patch cluster status with management token info: %w", err)
	}

	p.Log.Info("Operator management token created successfully", "secret", secretName)
	return newToken.SecretID, nil
}

func (p *ACLBootstrapPhase) ensureOperatorStatusToken(
	ctx context.Context,
	cluster *nomadv1alpha1.NomadCluster,
	authToken string,
) PhaseResult {
	// Idempotent: if already set and the Secret exists, nothing to do
	if cluster.Status.OperatorStatusSecretName != "" {
		existing := &corev1.Secret{}
		err := p.Client.Get(ctx, types.NamespacedName{
			Name:      cluster.Status.OperatorStatusSecretName,
			Namespace: cluster.Namespace,
		}, existing)
		if err == nil {
			p.Log.V(1).Info("Operator status token already exists, skipping creation")
			return OK()
		}
	}

	// Policy, token, and Secret share the deterministic name (ADR 0003).
	credName := OperatorStatusName(cluster.Name)
	policyName, tokenName, secretName := credName, credName, credName

	// Secondary idempotency guard: Secret exists by deterministic name but
	// status was never persisted (e.g. status update failed on a prior run).
	// Skip token creation and only retry the status update, avoiding a
	// leaked Nomad token per reconcile. Checked before any Nomad call —
	// the policy itself is kept in desired state every reconcile by
	// reconcileOperatorPolicies (C2), so nothing is lost by returning here.
	existingOpSecret := &corev1.Secret{}
	if err := p.Client.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, existingOpSecret); err == nil {
		p.Log.V(1).Info("Operator status secret exists but status not persisted, retrying status update",
			"secret", secretName)
		patchBase := cluster.DeepCopy()
		cluster.Status.OperatorStatusSecretName = secretName
		cluster.Status.OperatorStatusPolicyName = policyName
		if patchErr := p.Client.Status().Patch(ctx, cluster, client.MergeFrom(patchBase)); patchErr != nil {
			return Error(patchErr, "Failed to persist operator status token fields")
		}
		return OK()
	} else if !k8serrors.IsNotFound(err) {
		return Error(err, "Failed to check for existing operator status secret")
	}
	// Secret does not exist — create policy then a token bound to it.

	var newToken *nomad.ACLTokenResult
	if err := p.runNomadWithFallback(cluster, 30*time.Second, authToken, func(nomadClient nomad.NomadAPI) error {
		if err := nomadClient.CreateACLPolicy(authToken, policyName, operatorStatusPolicyDescription, nomad.OperatorStatusPolicyRules); err != nil {
			return err
		}
		t, terr := nomadClient.CreateACLTokenWithPolicies(authToken, tokenName, []string{policyName})
		if terr == nil {
			newToken = t
		}
		return terr
	}); err != nil {
		return Error(err, "Failed to create operator status ACL policy/token")
	}

	// Store in a Secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			SecretKeyAccessorID: newToken.AccessorID,
			SecretKeySecretID:   newToken.SecretID,
		},
	}

	if err := controllerutil.SetControllerReference(cluster, secret, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on operator status secret")
	}

	p.Log.Info("Creating operator status token secret", "name", secretName)
	if err := p.Client.Create(ctx, secret); err != nil {
		return Error(err, "Failed to create operator status secret")
	}

	// Update cluster status with the secret and policy names
	patchBase := cluster.DeepCopy()
	cluster.Status.OperatorStatusSecretName = secretName
	cluster.Status.OperatorStatusPolicyName = policyName
	if err := p.Client.Status().Patch(ctx, cluster, client.MergeFrom(patchBase)); err != nil {
		return Error(err, "Failed to patch cluster status with operator status token info")
	}

	p.Log.Info("Operator status token created successfully", "secret", secretName, "policy", policyName)
	return OK()
}

func (p *ACLBootstrapPhase) createMarkerSecret(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, secretName string) PhaseResult {
	// Same C3 treatment as the token-bearing bootstrap Secret: no
	// ownerReference, cluster label; deleted explicitly by the finalizer.
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels:    bootstrapSecretLabels(cluster),
			Annotations: map[string]string{
				"nomad.hashicorp.com/bootstrap-external": "true",
			},
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"note": "ACL was bootstrapped externally. This secret is a marker to prevent re-bootstrap attempts.",
		},
	}

	if err := p.Client.Create(ctx, secret); err != nil && !k8serrors.IsAlreadyExists(err) {
		return Error(err, "Failed to create marker secret")
	}

	return OK()
}
