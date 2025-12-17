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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
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
// Note: We use a raw HTTP request instead of the Nomad Go client because
// the client has issues parsing ExpirationTTL as time.Duration in newer Nomad versions.
func (c *Client) BootstrapACL() (*ACLBootstrapResult, error) {
	// Get the address from the client config
	addr := c.api.Address()

	// Make raw HTTP POST request to bootstrap endpoint
	req, err := http.NewRequest("POST", addr+"/v1/acl/bootstrap", bytes.NewReader(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to create bootstrap request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ACL bootstrap failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read bootstrap response: %w", err)
	}

	// Check for error responses
	if resp.StatusCode != http.StatusOK {
		bodyStr := string(body)
		if strings.Contains(bodyStr, "ACL bootstrap already done") ||
			strings.Contains(bodyStr, "already bootstrapped") {
			return nil, ErrAlreadyBootstrapped
		}
		return nil, fmt.Errorf("ACL bootstrap failed (status %d): %s", resp.StatusCode, bodyStr)
	}

	// Parse response manually to handle duration fields as strings
	var result struct {
		AccessorID string `json:"AccessorID"`
		SecretID   string `json:"SecretID"`
		Name       string `json:"Name"`
		Type       string `json:"Type"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse bootstrap response: %w", err)
	}

	return &ACLBootstrapResult{
		AccessorID: result.AccessorID,
		SecretID:   result.SecretID,
		Name:       result.Name,
		Type:       result.Type,
	}, nil
}

// CreateACLPolicy creates or updates an ACL policy.
// Requires a management token for authentication.
func (c *Client) CreateACLPolicy(token, name, description, rules string) error {
	addr := c.api.Address()

	policy := map[string]string{
		"Name":        name,
		"Description": description,
		"Rules":       rules,
	}

	body, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	req, err := http.NewRequest("POST", addr+"/v1/acl/policy/"+name, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create policy request: %w", err)
	}
	req.Header.Set("X-Nomad-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create ACL policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create ACL policy (status %d): %s", resp.StatusCode, string(respBody))
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
func (c *Client) GetLicense(token string) (*LicenseResult, error) {
	addr := c.api.Address()

	req, err := http.NewRequest("GET", addr+"/v1/operator/license", nil)
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
func (c *Client) GetAutopilotHealth(token string) (*AutopilotHealthResult, error) {
	addr := c.api.Address()

	req, err := http.NewRequest("GET", addr+"/v1/operator/autopilot/health", nil)
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
	AccessorID string
	SecretID   string
	Name       string
	Type       string
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
