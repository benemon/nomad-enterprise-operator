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

// Package nomad provides a client wrapper for the HashiCorp Nomad API,
// tailored for use by the Nomad Enterprise Operator.
package nomad

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	nomadapi "github.com/hashicorp/nomad/api"
)

// ClientConfig holds configuration for creating a Nomad API client.
type ClientConfig struct {
	// Address is the Nomad cluster address (e.g., "http://nomad-internal.namespace.svc:4646").
	Address string

	// Token is the ACL token for authenticated requests (optional for bootstrap).
	Token string

	// TLSEnabled indicates if TLS is enabled.
	TLSEnabled bool

	// CACert is the CA certificate for TLS verification.
	CACert []byte

	// Timeout is the timeout for API requests.
	Timeout time.Duration
}

// Client wraps the Nomad API client with operator-specific functionality.
type Client struct {
	api        *nomadapi.Client
	httpClient *http.Client
}

// NewClient creates a new Nomad API client.
func NewClient(cfg ClientConfig) (*Client, error) {
	nomadCfg := nomadapi.DefaultConfig()
	nomadCfg.Address = cfg.Address

	if cfg.Token != "" {
		nomadCfg.SecretID = cfg.Token
	}

	// Ensure HttpClient is initialized (DefaultConfig can return nil HttpClient)
	if nomadCfg.HttpClient == nil {
		nomadCfg.HttpClient = &http.Client{}
	}

	if cfg.Timeout > 0 {
		nomadCfg.HttpClient.Timeout = cfg.Timeout
	} else {
		nomadCfg.HttpClient.Timeout = 30 * time.Second
	}

	// Configure TLS if enabled
	if cfg.TLSEnabled {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		// Add CA cert for server verification
		if len(cfg.CACert) > 0 {
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(cfg.CACert) {
				return nil, fmt.Errorf("failed to parse CA certificate")
			}
			tlsConfig.RootCAs = caCertPool
		}

		nomadCfg.HttpClient.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	client, err := nomadapi.NewClient(nomadCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nomad client: %w", err)
	}

	return &Client{
		api:        client,
		httpClient: nomadCfg.HttpClient,
	}, nil
}

// BootstrapACL performs ACL bootstrap and returns the management token.
// This endpoint does not require authentication.
func (c *Client) BootstrapACL() (*ACLBootstrapResult, error) {
	token, _, err := c.api.ACLTokens().Bootstrap(nil)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "ACL bootstrap already done") ||
			strings.Contains(errMsg, "already bootstrapped") {
			return nil, ErrAlreadyBootstrapped
		}
		return nil, fmt.Errorf("ACL bootstrap failed: %w", err)
	}

	return &ACLBootstrapResult{
		AccessorID:     token.AccessorID,
		SecretID:       token.SecretID,
		Name:           token.Name,
		Type:           token.Type,
		CreateTime:     token.CreateTime,
		ExpirationTime: token.ExpirationTime,
	}, nil
}

// CreateACLPolicy creates or updates an ACL policy.
// Requires a management token for authentication.
func (c *Client) CreateACLPolicy(authToken, name, description, rules string) error {
	policy := &nomadapi.ACLPolicy{
		Name:        name,
		Description: description,
		Rules:       rules,
	}

	_, err := c.api.ACLPolicies().Upsert(policy, &nomadapi.WriteOptions{
		AuthToken: authToken,
	})
	if err != nil {
		return fmt.Errorf("failed to create ACL policy: %w", err)
	}

	return nil
}

// ACLTokenResult contains the result of ACL token operations.
type ACLTokenResult struct {
	AccessorID     string
	SecretID       string
	Name           string
	Type           string
	CreateTime     time.Time
	ExpirationTime *time.Time
}

// CreateACLToken creates a new ACL token.
// Requires a management token for authentication.
func (c *Client) CreateACLToken(authToken, name, tokenType string) (*ACLTokenResult, error) {
	token := &nomadapi.ACLToken{
		Name: name,
		Type: tokenType,
	}

	result, _, err := c.api.ACLTokens().Create(token, &nomadapi.WriteOptions{
		AuthToken: authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create ACL token: %w", err)
	}

	return &ACLTokenResult{
		AccessorID:     result.AccessorID,
		SecretID:       result.SecretID,
		Name:           result.Name,
		Type:           result.Type,
		CreateTime:     result.CreateTime,
		ExpirationTime: result.ExpirationTime,
	}, nil
}

// CreateACLTokenWithPolicies creates a new client ACL token bound to the named policies.
// Requires a management token for authentication.
func (c *Client) CreateACLTokenWithPolicies(authToken, name string, policies []string) (*ACLTokenResult, error) {
	token := &nomadapi.ACLToken{
		Name:     name,
		Type:     "client",
		Policies: policies,
	}

	result, _, err := c.api.ACLTokens().Create(token, &nomadapi.WriteOptions{
		AuthToken: authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create ACL token with policies: %w", err)
	}

	return &ACLTokenResult{
		AccessorID:     result.AccessorID,
		SecretID:       result.SecretID,
		Name:           result.Name,
		Type:           result.Type,
		CreateTime:     result.CreateTime,
		ExpirationTime: result.ExpirationTime,
	}, nil
}

// GetACLToken retrieves an ACL token by accessor ID.
// Requires a management token for authentication.
func (c *Client) GetACLToken(authToken, accessorID string) (*ACLTokenResult, error) {
	token, _, err := c.api.ACLTokens().Info(accessorID, &nomadapi.QueryOptions{
		AuthToken: authToken,
	})
	if err != nil {
		// Check if token not found
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get ACL token: %w", err)
	}

	return &ACLTokenResult{
		AccessorID:     token.AccessorID,
		SecretID:       token.SecretID,
		Name:           token.Name,
		Type:           token.Type,
		CreateTime:     token.CreateTime,
		ExpirationTime: token.ExpirationTime,
	}, nil
}

// DeleteACLToken deletes an ACL token by accessor ID.
// Requires a management token for authentication.
func (c *Client) DeleteACLToken(authToken, accessorID string) error {
	_, err := c.api.ACLTokens().Delete(accessorID, &nomadapi.WriteOptions{
		AuthToken: authToken,
	})
	if err != nil {
		return fmt.Errorf("failed to delete ACL token: %w", err)
	}

	return nil
}

// DeleteACLPolicy deletes an ACL policy by name.
// Requires a management token for authentication.
func (c *Client) DeleteACLPolicy(authToken, name string) error {
	_, err := c.api.ACLPolicies().Delete(name, &nomadapi.WriteOptions{
		AuthToken: authToken,
	})
	if err != nil {
		return fmt.Errorf("failed to delete ACL policy: %w", err)
	}

	return nil
}

// GetLeader returns the current Raft leader address.
func (c *Client) GetLeader() (string, error) {
	leader, err := c.api.Status().Leader()
	if err != nil {
		return "", fmt.Errorf("failed to get leader: %w", err)
	}
	return leader, nil
}

// GetPeers returns the list of Raft peer addresses.
func (c *Client) GetPeers() ([]string, error) {
	peers, err := c.api.Status().Peers()
	if err != nil {
		return nil, fmt.Errorf("failed to get peers: %w", err)
	}
	return peers, nil
}

// CheckHealth performs a health check against the Nomad server.
func (c *Client) CheckHealth() (*HealthResult, error) {
	health, err := c.api.Agent().Health()
	if err != nil {
		return nil, fmt.Errorf("health check failed: %w", err)
	}

	return &HealthResult{
		Server: HealthStatus{
			OK:      health.Server.Ok,
			Message: health.Server.Message,
		},
	}, nil
}

// GetLicense retrieves the current Nomad Enterprise license information.
// Requires an ACL token with operator:read capability.
func (c *Client) GetLicense(ctx context.Context, token string) (*LicenseResult, error) {
	addr := c.api.Address()

	req, err := http.NewRequestWithContext(ctx, "GET", addr+"/v1/operator/license", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create license request: %w", err)
	}
	if token != "" {
		req.Header.Set("X-Nomad-Token", token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get license: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read license response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("license request failed (status %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		License struct {
			LicenseID       string   `json:"LicenseID"`
			ExpirationTime  string   `json:"ExpirationTime"`
			TerminationTime string   `json:"TerminationTime"`
			Features        []string `json:"Features"`
		} `json:"License"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse license response: %w", err)
	}

	return &LicenseResult{
		LicenseID:       result.License.LicenseID,
		ExpirationTime:  result.License.ExpirationTime,
		TerminationTime: result.License.TerminationTime,
		Features:        result.License.Features,
	}, nil
}

// GetAutopilotHealth retrieves the Raft autopilot health information.
// Requires an ACL token with operator:read capability.
func (c *Client) GetAutopilotHealth(ctx context.Context, token string) (*AutopilotHealthResult, error) {
	addr := c.api.Address()

	req, err := http.NewRequestWithContext(ctx, "GET", addr+"/v1/operator/autopilot/health", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create autopilot health request: %w", err)
	}
	if token != "" {
		req.Header.Set("X-Nomad-Token", token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get autopilot health: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read autopilot health response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("autopilot health request failed (status %d): %s", resp.StatusCode, string(body))
	}

	var apiResult struct {
		Healthy          bool `json:"Healthy"`
		FailureTolerance int  `json:"FailureTolerance"`
		Servers          []struct {
			ID          string `json:"ID"`
			Name        string `json:"Name"`
			Address     string `json:"Address"`
			SerfStatus  string `json:"SerfStatus"`
			Version     string `json:"Version"`
			Leader      bool   `json:"Leader"`
			Voter       bool   `json:"Voter"`
			LastContact string `json:"LastContact"`
			LastTerm    uint64 `json:"LastTerm"`
			LastIndex   uint64 `json:"LastIndex"`
			Healthy     bool   `json:"Healthy"`
			StableSince string `json:"StableSince"`
		} `json:"Servers"`
	}

	if err := json.Unmarshal(body, &apiResult); err != nil {
		return nil, fmt.Errorf("failed to parse autopilot health response: %w", err)
	}

	result := &AutopilotHealthResult{
		Healthy:          apiResult.Healthy,
		FailureTolerance: apiResult.FailureTolerance,
		Servers:          make([]AutopilotServer, 0, len(apiResult.Servers)),
	}

	voters := 0
	for _, s := range apiResult.Servers {
		if s.Voter {
			voters++
		}
		result.Servers = append(result.Servers, AutopilotServer{
			ID:          s.ID,
			Name:        s.Name,
			Address:     s.Address,
			Leader:      s.Leader,
			Voter:       s.Voter,
			Healthy:     s.Healthy,
			StableSince: s.StableSince,
			LastContact: s.LastContact,
		})
	}
	result.Voters = voters

	return result, nil
}

// ACLBootstrapResult contains the result of ACL bootstrap.
type ACLBootstrapResult struct {
	AccessorID     string
	SecretID       string
	Name           string
	Type           string
	CreateTime     time.Time
	ExpirationTime *time.Time
}

// HealthResult contains health check results.
type HealthResult struct {
	Server HealthStatus
}

// HealthStatus represents a component's health status.
type HealthStatus struct {
	OK      bool
	Message string
}

// ErrAlreadyBootstrapped is returned when ACL bootstrap has already been performed.
var ErrAlreadyBootstrapped = errors.New("ACL already bootstrapped")

// LicenseResult contains Nomad Enterprise license information.
type LicenseResult struct {
	LicenseID       string
	ExpirationTime  string
	TerminationTime string
	Features        []string
}

// AutopilotHealthResult contains Raft autopilot health information.
type AutopilotHealthResult struct {
	Healthy          bool
	FailureTolerance int
	Voters           int
	Servers          []AutopilotServer
}

// AutopilotServer represents a single server in the autopilot health response.
type AutopilotServer struct {
	ID          string
	Name        string
	Address     string
	Leader      bool
	Voter       bool
	Healthy     bool
	StableSince string
	LastContact string
}

// OperatorStatusPolicyRules defines the minimal permissions required by the
// operator for day-2 status API calls (autopilot health, license, leader).
// operator:read covers all three endpoints used by ClusterStatusPhase.
// /v1/status/leader requires no token at all; the others require operator:read.
// No agent rule is needed. The bootstrap token is not used after initial ACL
// bootstrap completes.
const OperatorStatusPolicyRules = `
operator {
  policy = "read"
}
`

// AnonymousPolicyRules is the recommended anonymous policy for basic cluster visibility.
// This provides read-only access to common resources for unauthenticated requests.
const AnonymousPolicyRules = `
namespace "default" {
  policy       = "read"
  capabilities = ["list-jobs", "read-job"]
}

agent {
  policy = "read"
}

operator {
  policy = "read"
}

quota {
  policy = "read"
}

node {
  policy = "read"
}

host_volume "*" {
  policy = "read"
}
`

// OIDCDefaultPolicyRules is the default Nomad ACL policy applied to the nomad-admins group
// when no explicit binding rules are specified in spec.oidc.bindingRules.
const OIDCDefaultPolicyRules = `
namespace "default" {
  capabilities = ["list-jobs", "read-job", "submit-job"]
}
operator {
  policy = "read"
}
`

// ACLAuthMethodConfig is the JSON configuration body for a Nomad OIDC auth method.
type ACLAuthMethodConfig struct {
	OIDCDiscoveryURL    string            `json:"OIDCDiscoveryURL"`
	DiscoveryCAPem      []string          `json:"DiscoveryCAPem,omitempty"`
	OIDCClientID        string            `json:"OIDCClientID"`
	OIDCClientSecret    string            `json:"OIDCClientSecret"`
	OIDCEnablePKCE      bool              `json:"OIDCEnablePKCE"`
	BoundAudiences      []string          `json:"BoundAudiences"`
	AllowedRedirectURIs []string          `json:"AllowedRedirectURIs"`
	OIDCScopes          []string          `json:"OIDCScopes"`
	ListClaimMappings   map[string]string `json:"ListClaimMappings"`
}

// ACLBindingRuleStub is a summary of an ACL binding rule returned from the list API.
type ACLBindingRuleStub struct {
	ID         string
	AuthMethod string
	Selector   string
	BindType   string
	BindName   string
}

// UpsertACLAuthMethod creates or updates an OIDC auth method in Nomad.
func (c *Client) UpsertACLAuthMethod(
	authToken, name, methodType, maxTokenTTL string,
	config ACLAuthMethodConfig,
) error {
	addr := c.api.Address()

	// Check if the auth method already exists
	checkReq, err := http.NewRequest("GET", addr+"/v1/acl/auth-method/"+name, nil)
	if err != nil {
		return fmt.Errorf("failed to create auth method check request: %w", err)
	}
	checkReq.Header.Set("X-Nomad-Token", authToken)

	checkResp, err := c.httpClient.Do(checkReq)
	if err != nil {
		return fmt.Errorf("failed to check auth method: %w", err)
	}
	_ = checkResp.Body.Close()

	httpMethod := http.MethodPost
	url := addr + "/v1/acl/auth-method"
	if checkResp.StatusCode == http.StatusOK {
		httpMethod = http.MethodPut
		url = addr + "/v1/acl/auth-method/" + name
	}

	body := map[string]interface{}{
		"Name":          name,
		"Type":          methodType,
		"MaxTokenTTL":   maxTokenTTL,
		"TokenLocality": "local",
		"Default":       true,
		"Config":        config,
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal auth method: %w", err)
	}

	req, err := http.NewRequest(httpMethod, url, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return fmt.Errorf("failed to create auth method request: %w", err)
	}
	req.Header.Set("X-Nomad-Token", authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upsert auth method: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auth method upsert failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// ListACLBindingRules lists all ACL binding rules for the given auth method.
func (c *Client) ListACLBindingRules(authToken, authMethodName string) ([]ACLBindingRuleStub, error) {
	addr := c.api.Address()

	req, err := http.NewRequest("GET", addr+"/v1/acl/binding-rules?auth_method="+authMethodName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create binding rules list request: %w", err)
	}
	req.Header.Set("X-Nomad-Token", authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list binding rules: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read binding rules response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("binding rules list failed (status %d): %s", resp.StatusCode, string(body))
	}

	var rules []ACLBindingRuleStub
	if err := json.Unmarshal(body, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse binding rules response: %w", err)
	}
	if rules == nil {
		rules = []ACLBindingRuleStub{}
	}

	return rules, nil
}

// UpsertACLRole creates or updates an ACL role in Nomad and returns the role ID.
func (c *Client) UpsertACLRole(authToken, name string, policyNames []string) (string, error) {
	addr := c.api.Address()

	// Check if the role already exists by listing and matching by name
	existingID, err := c.findACLRoleIDByName(authToken, name)
	if err != nil {
		return "", fmt.Errorf("failed to look up existing ACL role: %w", err)
	}

	policies := make([]map[string]string, 0, len(policyNames))
	for _, p := range policyNames {
		policies = append(policies, map[string]string{"Name": p})
	}

	body := map[string]interface{}{
		"Name":     name,
		"Policies": policies,
	}

	url := addr + "/v1/acl/role"
	if existingID != "" {
		body["ID"] = existingID
		url = addr + "/v1/acl/role/" + existingID
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("failed to marshal ACL role: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return "", fmt.Errorf("failed to create ACL role request: %w", err)
	}
	req.Header.Set("X-Nomad-Token", authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to upsert ACL role: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read ACL role response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ACL role upsert failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ID string `json:"ID"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse ACL role response: %w", err)
	}

	return result.ID, nil
}

func (c *Client) findACLRoleIDByName(authToken, name string) (string, error) {
	addr := c.api.Address()

	req, err := http.NewRequest("GET", addr+"/v1/acl/roles", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create ACL roles list request: %w", err)
	}
	req.Header.Set("X-Nomad-Token", authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to list ACL roles: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read ACL roles response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ACL roles list failed (status %d): %s", resp.StatusCode, string(body))
	}

	var roles []struct {
		ID   string `json:"ID"`
		Name string `json:"Name"`
	}
	if err := json.Unmarshal(body, &roles); err != nil {
		return "", fmt.Errorf("failed to parse ACL roles response: %w", err)
	}

	for _, r := range roles {
		if r.Name == name {
			return r.ID, nil
		}
	}

	return "", nil
}

// UpsertACLBindingRule creates or updates an ACL binding rule in Nomad and returns the rule ID.
func (c *Client) UpsertACLBindingRule(authToken string, rule ACLBindingRuleStub) (string, error) {
	// Check for existing rule with the same auth method and bind name
	existing, err := c.ListACLBindingRules(authToken, rule.AuthMethod)
	if err != nil {
		return "", fmt.Errorf("failed to list existing binding rules: %w", err)
	}
	for _, r := range existing {
		if r.BindName == rule.BindName && r.BindType == rule.BindType {
			return r.ID, nil
		}
	}

	addr := c.api.Address()

	body := map[string]interface{}{
		"AuthMethod": rule.AuthMethod,
		"Selector":   rule.Selector,
		"BindType":   rule.BindType,
		"BindName":   rule.BindName,
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("failed to marshal binding rule: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, addr+"/v1/acl/binding-rule", strings.NewReader(string(bodyJSON)))
	if err != nil {
		return "", fmt.Errorf("failed to create binding rule request: %w", err)
	}
	req.Header.Set("X-Nomad-Token", authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to upsert binding rule: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read binding rule response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("binding rule upsert failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ID string `json:"ID"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse binding rule response: %w", err)
	}

	return result.ID, nil
}

// DeleteACLAuthMethod deletes an ACL auth method by name. Non-error on 404.
func (c *Client) DeleteACLAuthMethod(authToken, name string) error {
	addr := c.api.Address()

	req, err := http.NewRequest("DELETE", addr+"/v1/acl/auth-method/"+name, nil)
	if err != nil {
		return fmt.Errorf("failed to create auth method delete request: %w", err)
	}
	req.Header.Set("X-Nomad-Token", authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete auth method: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auth method delete failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// DeleteACLRole deletes an ACL role by ID. Non-error on 404.
func (c *Client) DeleteACLRole(authToken, id string) error {
	addr := c.api.Address()

	req, err := http.NewRequest("DELETE", addr+"/v1/acl/role/"+id, nil)
	if err != nil {
		return fmt.Errorf("failed to create ACL role delete request: %w", err)
	}
	req.Header.Set("X-Nomad-Token", authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete ACL role: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ACL role delete failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// DeleteACLBindingRule deletes an ACL binding rule by ID. Non-error on 404.
func (c *Client) DeleteACLBindingRule(authToken, id string) error {
	addr := c.api.Address()

	req, err := http.NewRequest("DELETE", addr+"/v1/acl/binding-rule/"+id, nil)
	if err != nil {
		return fmt.Errorf("failed to create binding rule delete request: %w", err)
	}
	req.Header.Set("X-Nomad-Token", authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete binding rule: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("binding rule delete failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// InternalServiceAddress returns the internal K8s service address for a Nomad cluster.
// This address is only resolvable from within the Kubernetes cluster.
func InternalServiceAddress(clusterName, namespace string, tlsEnabled bool) string {
	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s-internal.%s.svc:4646", scheme, clusterName, namespace)
}

// LoadBalancerAddress returns the LoadBalancer address for a Nomad cluster.
// Returns empty string if advertiseAddress is empty.
func LoadBalancerAddress(advertiseAddress string, tlsEnabled bool) string {
	if advertiseAddress == "" {
		return ""
	}
	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:4646", scheme, advertiseAddress)
}

// IsNetworkError checks if the error is a network connectivity error
// (DNS lookup failure, connection refused, timeout, etc.)
func IsNetworkError(err error) bool {
	if err == nil {
		return false
	}

	// Check for DNS lookup errors
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}

	// Check for connection refused or timeout
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}

	// Check error message for common network issues
	errMsg := strings.ToLower(err.Error())
	networkErrors := []string{
		"no such host",
		"connection refused",
		"connection reset",
		"i/o timeout",
		"network is unreachable",
		"no route to host",
	}
	for _, netErr := range networkErrors {
		if strings.Contains(errMsg, netErr) {
			return true
		}
	}

	return false
}
