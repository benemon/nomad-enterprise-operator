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
	"strings"
	"time"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// OIDCPhase configures OIDC authentication for the Nomad cluster via Keycloak.
type OIDCPhase struct {
	*PhaseContext
}

// NewOIDCPhase creates a new OIDCPhase.
func NewOIDCPhase(ctx *PhaseContext) *OIDCPhase {
	return &OIDCPhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *OIDCPhase) Name() string {
	return "OIDC"
}

// Execute configures OIDC authentication if enabled.
func (p *OIDCPhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	if cluster.Spec.OIDC == nil || !cluster.Spec.OIDC.Enabled {
		return OK()
	}

	// Already fully configured — nothing to do
	if cluster.Status.OIDC.Ready {
		p.Log.V(1).Info("OIDC already configured, skipping")
		return OK()
	}

	// Ensure the Route host is available before creating the one-shot realm import.
	// RouteHost is now populated by RoutePhase, so it will be set by the time we get here.
	if cluster.Spec.OpenShift.Route.Enabled && cluster.Status.RouteHost == "" {
		p.Log.Info("Waiting for OpenShift Route host before creating OIDC realm import")
		return Requeue(10*time.Second, "Waiting for Route host to be available for OIDC redirect URIs")
	}

	// Step 4a — Client secret
	clientSecret, result := p.ensureClientSecret(ctx, cluster)
	if result.Error != nil || result.Requeue {
		return result
	}

	// Step 4b — Redirect URIs
	redirectURIs := p.buildRedirectURIs(cluster)

	// Step 4c — KeycloakRealmImport
	if result := p.reconcileRealmImport(ctx, cluster, redirectURIs, clientSecret); result.Error != nil || result.Requeue {
		return result
	}

	// Step 4e — Configure Nomad
	if result := p.configureNomad(ctx, cluster, clientSecret, redirectURIs); result.Error != nil || result.Requeue {
		return result
	}

	return OK()
}

func (p *OIDCPhase) ensureClientSecret(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (string, PhaseResult) {
	secretName := cluster.Name + "-oidc-client-secret"

	// Check if the secret already exists
	if cluster.Status.OIDC.ClientSecretName != "" {
		existing := &corev1.Secret{}
		err := p.Client.Get(ctx, types.NamespacedName{
			Name:      cluster.Status.OIDC.ClientSecretName,
			Namespace: cluster.Namespace,
		}, existing)
		if err == nil {
			return string(existing.Data["client-secret"]), OK()
		}
		if !k8serrors.IsNotFound(err) {
			return "", Error(err, "Failed to get OIDC client secret")
		}
	}

	// Check if the secret exists but status wasn't persisted
	existing := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, existing)
	if err == nil {
		cluster.Status.OIDC.ClientSecretName = secretName
		if err := p.Client.Status().Update(ctx, cluster); err != nil {
			return "", Error(err, "Failed to update cluster status with client secret name")
		}
		return string(existing.Data["client-secret"]), OK()
	}
	if !k8serrors.IsNotFound(err) {
		return "", Error(err, "Failed to check for existing OIDC client secret")
	}

	// Generate new client secret
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", Error(err, "Failed to generate random client secret")
	}
	clientSecretValue := base64.StdEncoding.EncodeToString(randomBytes)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"client-secret": clientSecretValue,
		},
	}

	if err := controllerutil.SetControllerReference(cluster, secret, p.Scheme); err != nil {
		return "", Error(err, "Failed to set owner reference on OIDC client secret")
	}

	p.Log.Info("Creating OIDC client secret", "name", secretName)
	if err := p.Client.Create(ctx, secret); err != nil {
		return "", Error(err, "Failed to create OIDC client secret")
	}

	cluster.Status.OIDC.ClientSecretName = secretName
	if err := p.Client.Status().Update(ctx, cluster); err != nil {
		return "", Error(err, "Failed to update cluster status with client secret name")
	}

	return clientSecretValue, OK()
}

func (p *OIDCPhase) buildRedirectURIs(cluster *nomadv1alpha1.NomadCluster) []string {
	uris := []string{
		"http://localhost:4649/oidc/callback",
		"https://localhost:4646/ui/settings/tokens",
	}

	if cluster.Spec.OpenShift.Route.Enabled && cluster.Status.RouteHost != "" {
		uris = append(uris, "https://"+cluster.Status.RouteHost+"/ui/settings/tokens")
	}

	if p.AdvertiseAddress != "" {
		uris = append(uris, "https://"+p.AdvertiseAddress+":4646/ui/settings/tokens")
	}

	return uris
}

func (p *OIDCPhase) reconcileRealmImport(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, redirectURIs []string, clientSecret string) PhaseResult {
	// CRD presence check
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "k8s.keycloak.org",
		Version: "v2alpha1",
		Kind:    "KeycloakRealmImportList",
	})
	if err := p.Client.List(ctx, list); err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "no kind is registered") || strings.Contains(errMsg, "no matches for kind") {
			p.Log.Info("Keycloak operator CRDs not yet available, will retry")
			return Requeue(30*time.Second, "Keycloak operator CRDs not yet available")
		}
		return Error(err, "Failed to check for Keycloak CRDs")
	}

	realmImport := &unstructured.Unstructured{}
	realmImport.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "k8s.keycloak.org",
		Version: "v2alpha1",
		Kind:    "KeycloakRealmImport",
	})
	realmImport.SetName(cluster.Name + "-oidc-realm")
	realmImport.SetNamespace(cluster.Namespace)

	result, err := controllerutil.CreateOrUpdate(ctx, p.Client, realmImport, func() error {
		if err := controllerutil.SetControllerReference(cluster, realmImport, p.Scheme); err != nil {
			return err
		}

		if err := unstructured.SetNestedField(realmImport.Object, cluster.Spec.OIDC.KeycloakRef.Name, "spec", "keycloakCRName"); err != nil {
			return err
		}

		realm := buildRealmRepresentation(cluster, redirectURIs, clientSecret)
		return unstructured.SetNestedField(realmImport.Object, realm, "spec", "realm")
	})
	if err != nil {
		return Error(err, "Failed to reconcile KeycloakRealmImport")
	}

	if result != controllerutil.OperationResultNone {
		p.Log.Info("Reconciled KeycloakRealmImport", "name", realmImport.GetName(), "operation", result)
	}

	// Update status
	cluster.Status.OIDC.RealmImportName = realmImport.GetName()
	if err := p.Client.Status().Update(ctx, cluster); err != nil {
		return Error(err, "Failed to update cluster status with realm import name")
	}

	// Step 4d — Wait for realm import readiness
	current := &unstructured.Unstructured{}
	current.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "k8s.keycloak.org",
		Version: "v2alpha1",
		Kind:    "KeycloakRealmImport",
	})
	if err := p.Client.Get(ctx, types.NamespacedName{
		Name:      realmImport.GetName(),
		Namespace: realmImport.GetNamespace(),
	}, current); err != nil {
		return Error(err, "Failed to get KeycloakRealmImport status")
	}

	conditions, _, _ := unstructured.NestedSlice(current.Object, "status", "conditions")
	for _, c := range conditions {
		cond, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		condType, _, _ := unstructured.NestedString(cond, "type")
		condStatus, _, _ := unstructured.NestedString(cond, "status")
		if condType == "Done" && condStatus == "True" {
			return OK()
		}
	}

	return Requeue(10*time.Second, "Waiting for KeycloakRealmImport to complete")
}

func buildRealmRepresentation(cluster *nomadv1alpha1.NomadCluster, redirectURIs []string, clientSecret string) map[string]interface{} {
	redirectURIsList := make([]interface{}, 0, len(redirectURIs))
	for _, uri := range redirectURIs {
		redirectURIsList = append(redirectURIsList, uri)
	}

	realmName := cluster.Spec.OIDC.RealmName(cluster.Name)

	clusterDescription := fmt.Sprintf("Nomad cluster %s/%s", cluster.Namespace, cluster.Name)

	return map[string]interface{}{
		"id":          realmName,
		"realm":       realmName,
		"displayName": fmt.Sprintf("Nomad - %s", cluster.Name),
		"enabled":     true,
		"clients": []interface{}{
			map[string]interface{}{
				"clientId":                  "nomad-oidc",
				"name":                      "Nomad OIDC Client",
				"description":               fmt.Sprintf("OIDC client for %s, managed by the nomad-enterprise-operator", clusterDescription),
				"enabled":                   true,
				"publicClient":              false,
				"protocol":                  "openid-connect",
				"standardFlowEnabled":       true,
				"directAccessGrantsEnabled": false,
				"clientAuthenticatorType":   "client-secret",
				"secret":                    clientSecret,
				"redirectUris":              redirectURIsList,
				"attributes":                map[string]interface{}{"pkce.code.challenge.method": "S256"},
				"defaultClientScopes":       []interface{}{"openid", "email", "profile", "roles", "web-origins", "scope-for-nomad"},
			},
		},
		"clientScopes": []interface{}{
			map[string]interface{}{
				"name":        "scope-for-nomad",
				"description": "Maps Keycloak group membership into Nomad token claims",
				"protocol":    "openid-connect",
				"attributes": map[string]interface{}{
					"include.in.token.scope":    "true",
					"display.on.consent.screen": "false",
				},
				"protocolMappers": []interface{}{
					map[string]interface{}{
						"name":            "nomad-group-mapper",
						"protocol":        "openid-connect",
						"protocolMapper":  "oidc-group-membership-mapper",
						"consentRequired": false,
						"config": map[string]interface{}{
							"claim.name":           "kc-groups",
							"full.path":            "true",
							"multivalued":          "true",
							"id.token.claim":       "true",
							"access.token.claim":   "true",
							"userinfo.token.claim": "true",
						},
					},
				},
			},
		},
	}
}

func (p *OIDCPhase) configureNomad(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, clientSecret string, redirectURIs []string) PhaseResult {
	// Get the Keycloak hostname
	keycloak := &unstructured.Unstructured{}
	keycloak.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "k8s.keycloak.org",
		Version: "v2alpha1",
		Kind:    "Keycloak",
	})
	if err := p.Client.Get(ctx, types.NamespacedName{
		Name:      cluster.Spec.OIDC.KeycloakRef.Name,
		Namespace: cluster.Namespace,
	}, keycloak); err != nil {
		return Error(err, "Failed to get Keycloak CR")
	}

	hostname, _, err := unstructured.NestedString(keycloak.Object, "spec", "hostname", "hostname")
	if err != nil || hostname == "" {
		return Error(fmt.Errorf("keycloak CR has no spec.hostname.hostname"), "Failed to determine Keycloak hostname")
	}

	discoveryURL := "https://" + hostname + "/realms/" + cluster.Spec.OIDC.RealmName(cluster.Name)

	// Load discovery CA if configured
	var discoveryCAPem []string
	if cluster.Spec.OIDC.DiscoveryCA != nil {
		caPEM, caResult := p.loadDiscoveryCA(ctx, cluster)
		if caResult.Error != nil {
			return caResult
		}
		discoveryCAPem = []string{caPEM}
	}

	// Get bootstrap token for management-level operations
	bootstrapToken, result := p.getBootstrapToken(ctx, cluster)
	if result.Error != nil {
		return result
	}

	// Build auth method config
	authMethodConfig := nomad.ACLAuthMethodConfig{
		OIDCDiscoveryURL:    discoveryURL,
		DiscoveryCAPem:      discoveryCAPem,
		OIDCClientID:        "nomad-oidc",
		OIDCClientSecret:    clientSecret,
		OIDCEnablePKCE:      true,
		BoundAudiences:      []string{"nomad-oidc"},
		AllowedRedirectURIs: redirectURIs,
		OIDCScopes:          []string{"openid", "scope-for-nomad"},
		ListClaimMappings:   map[string]string{"kc-groups": "keycloak_groups"},
	}

	// Upsert auth method with internal-then-LoadBalancer fallback
	if err := p.upsertAuthMethodWithFallback(cluster, bootstrapToken, authMethodConfig); err != nil {
		return Error(err, "Failed to upsert OIDC auth method")
	}

	// Determine binding rules
	bindingRules := cluster.Spec.OIDC.BindingRules
	if len(bindingRules) == 0 {
		bindingRules = buildDefaultBindingRules()
	}

	// Create Nomad client for policy/role/binding rule operations
	nomadClient, err := p.createNomadClientWithFallback(cluster, bootstrapToken)
	if err != nil {
		return Error(err, "Failed to create Nomad client for OIDC configuration")
	}

	for _, rule := range bindingRules {
		policyName := rule.NomadRole + "-policy"

		if err := nomadClient.CreateACLPolicy(bootstrapToken, policyName, "OIDC group policy", rule.PolicyRules); err != nil {
			return Error(err, fmt.Sprintf("Failed to create ACL policy %s", policyName))
		}

		if _, err := nomadClient.UpsertACLRole(bootstrapToken, rule.NomadRole, []string{policyName}); err != nil {
			return Error(err, fmt.Sprintf("Failed to upsert ACL role %s", rule.NomadRole))
		}

		selector := "`" + rule.KeycloakGroup + "` in list.keycloak_groups"
		if _, err := nomadClient.UpsertACLBindingRule(bootstrapToken, nomad.ACLBindingRuleStub{
			AuthMethod: "keycloak",
			BindType:   "role",
			BindName:   rule.NomadRole,
			Selector:   selector,
		}); err != nil {
			return Error(err, fmt.Sprintf("Failed to upsert binding rule for %s", rule.NomadRole))
		}
	}

	cluster.Status.OIDC.AuthMethodName = "keycloak"
	cluster.Status.OIDC.Ready = true
	if err := p.Client.Status().Update(ctx, cluster); err != nil {
		return Error(err, "Failed to update cluster status with OIDC ready state")
	}

	p.Log.Info("OIDC configuration completed successfully")
	return OK()
}

func buildDefaultBindingRules() []nomadv1alpha1.OIDCBindingRule {
	return []nomadv1alpha1.OIDCBindingRule{
		{
			KeycloakGroup: "/nomad-admins",
			NomadRole:     "nomad-admins",
			PolicyRules:   nomad.OIDCDefaultPolicyRules,
		},
	}
}

func (p *OIDCPhase) loadDiscoveryCA(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (string, PhaseResult) {
	caSpec := cluster.Spec.OIDC.DiscoveryCA
	secretKey := caSpec.SecretKey
	if secretKey == "" {
		secretKey = defaultTLSCertKey
	}

	secret := &corev1.Secret{}
	if err := p.Client.Get(ctx, types.NamespacedName{
		Name:      caSpec.SecretName,
		Namespace: cluster.Namespace,
	}, secret); err != nil {
		return "", Error(err, fmt.Sprintf("Failed to get OIDC discovery CA secret %q", caSpec.SecretName))
	}

	caPEM, ok := secret.Data[secretKey]
	if !ok {
		return "", Error(
			fmt.Errorf("key %q not found in secret %q", secretKey, caSpec.SecretName),
			"OIDC discovery CA secret missing certificate key",
		)
	}

	return string(caPEM), OK()
}

func (p *OIDCPhase) getBootstrapToken(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (string, PhaseResult) {
	secretName := cluster.Name + "-acl-bootstrap"
	if cluster.Spec.Server.ACL.BootstrapSecretName != "" {
		secretName = cluster.Spec.Server.ACL.BootstrapSecretName
	}

	secret := &corev1.Secret{}
	if err := p.Client.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, secret); err != nil {
		return "", Error(err, "Failed to get bootstrap secret for OIDC configuration")
	}

	token := string(secret.Data["secret-id"])
	if token == "" {
		return "", Error(fmt.Errorf("bootstrap secret has empty secret-id"), "Bootstrap secret missing token")
	}

	return token, OK()
}

func (p *OIDCPhase) upsertAuthMethodWithFallback(cluster *nomadv1alpha1.NomadCluster, bootstrapToken string, config nomad.ACLAuthMethodConfig) error {
	cfg := p.BuildClientConfig(cluster, 30*time.Second, bootstrapToken)
	cfg.Address = nomad.InternalServiceAddress(cluster.Name, cluster.Namespace, true)

	nomadClient, err := nomad.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Nomad client: %w", err)
	}

	err = nomadClient.UpsertACLAuthMethod(bootstrapToken, "keycloak", "OIDC", "10m", config)
	if err == nil {
		return nil
	}

	if !nomad.IsNetworkError(err) {
		return err
	}

	loadBalancerAddress := nomad.LoadBalancerAddress(p.AdvertiseAddress, true)
	if loadBalancerAddress == "" {
		return fmt.Errorf("internal service not reachable and no LoadBalancer address: %w", err)
	}

	cfg.Address = loadBalancerAddress
	nomadClient, err = nomad.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Nomad client for LoadBalancer: %w", err)
	}

	return nomadClient.UpsertACLAuthMethod(bootstrapToken, "keycloak", "OIDC", "10m", config)
}

func (p *OIDCPhase) createNomadClientWithFallback(cluster *nomadv1alpha1.NomadCluster, bootstrapToken string) (*nomad.Client, error) {
	cfg := p.BuildClientConfig(cluster, 30*time.Second, bootstrapToken)
	cfg.Address = nomad.InternalServiceAddress(cluster.Name, cluster.Namespace, true)

	nomadClient, err := nomad.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nomad client: %w", err)
	}

	// Test connectivity
	_, testErr := nomadClient.GetLeader()
	if testErr == nil {
		return nomadClient, nil
	}

	if !nomad.IsNetworkError(testErr) {
		return nomadClient, nil
	}

	loadBalancerAddress := nomad.LoadBalancerAddress(p.AdvertiseAddress, true)
	if loadBalancerAddress == "" {
		return nomadClient, nil
	}

	cfg.Address = loadBalancerAddress
	return nomad.NewClient(cfg)
}
