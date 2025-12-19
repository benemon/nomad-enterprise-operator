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

	// ClientCert is the client certificate for mTLS.
	ClientCert []byte

	// ClientKey is the client key for mTLS.
	ClientKey []byte

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

		// Add client cert for mTLS
		if len(cfg.ClientCert) > 0 && len(cfg.ClientKey) > 0 {
			cert, err := tls.X509KeyPair(cfg.ClientCert, cfg.ClientKey)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
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

// GetServerMembers returns information about the server members.
func (c *Client) GetServerMembers() (*ServerMembersResult, error) {
	members, err := c.api.Agent().Members()
	if err != nil {
		return nil, fmt.Errorf("failed to get server members: %w", err)
	}

	result := &ServerMembersResult{
		ServerName:   members.ServerName,
		ServerRegion: members.ServerRegion,
		ServerDC:     members.ServerDC,
		Members:      make([]ServerMember, 0, len(members.Members)),
	}

	for _, m := range members.Members {
		result.Members = append(result.Members, ServerMember{
			Name:   m.Name,
			Addr:   m.Addr,
			Port:   m.Port,
			Status: m.Status,
			Region: m.Tags["region"],
			DC:     m.Tags["dc"],
		})
	}

	return result, nil
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
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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

// ServerMembersResult contains server membership information.
type ServerMembersResult struct {
	ServerName   string
	ServerRegion string
	ServerDC     string
	Members      []ServerMember
}

// ServerMember represents a single server member.
type ServerMember struct {
	Name   string
	Addr   string
	Port   uint16
	Status string
	Region string
	DC     string
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
var ErrAlreadyBootstrapped = fmt.Errorf("ACL already bootstrapped")

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
