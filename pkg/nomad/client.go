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
	"errors"
	"fmt"
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

// ACLPolicyResult contains the observed state of an ACL policy.
type ACLPolicyResult struct {
	Name        string
	Description string
	Rules       string
}

// GetACLPolicy retrieves an ACL policy by name. Returns (nil, nil) if the
// policy does not exist. Requires a management token for authentication.
func (c *Client) GetACLPolicy(authToken, name string) (*ACLPolicyResult, error) {
	policy, _, err := c.api.ACLPolicies().Info(name, &nomadapi.QueryOptions{
		AuthToken: authToken,
	})
	if err != nil {
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get ACL policy: %w", err)
	}

	return &ACLPolicyResult{
		Name:        policy.Name,
		Description: policy.Description,
		Rules:       policy.Rules,
	}, nil
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
	q := (&nomadapi.QueryOptions{AuthToken: token}).WithContext(ctx)

	reply, _, err := c.api.Operator().LicenseGet(q)
	if err != nil {
		return nil, fmt.Errorf("failed to get license: %w", err)
	}
	if reply == nil || reply.License == nil {
		return nil, fmt.Errorf("license response contained no license")
	}

	return &LicenseResult{
		LicenseID:       reply.License.LicenseID,
		ExpirationTime:  reply.License.ExpirationTime.Format(time.RFC3339),
		TerminationTime: reply.License.TerminationTime.Format(time.RFC3339),
		Features:        reply.License.Features,
	}, nil
}

// AgentSelf queries /v1/agent/self for the Nomad agent's reported
// version. Requires the client's configured token (SecretID) to hold
// `agent:read` capability — see OperatorStatusPolicyRules.
//
// The Nomad SDK call (Agent().Self()) does not accept QueryOptions, so
// the token cannot be overridden per-call here as it can for license
// and autopilot probes.
func (c *Client) AgentSelf(_ context.Context) (*AgentSelfResult, error) {
	self, err := c.api.Agent().Self()
	if err != nil {
		return nil, fmt.Errorf("failed to query agent self: %w", err)
	}
	if self == nil {
		return nil, fmt.Errorf("agent self response was empty")
	}
	return &AgentSelfResult{Version: extractNomadVersion(self)}, nil
}

// extractNomadVersion pulls the agent version from the AgentSelf
// response, trying the two well-known locations in the wire format:
// `stats.nomad.version` (the values surfaced by the Nomad UI status
// banner) and `member.tags.build` (the serf gossip tag). Returns "" if
// neither is present; callers treat empty as a probe miss, not an
// error, per AC-4.7.2.
func extractNomadVersion(self *nomadapi.AgentSelf) string {
	if nomadStats, ok := self.Stats["nomad"]; ok {
		if v := nomadStats["version"]; v != "" {
			return v
		}
	}
	if v := self.Member.Tags["build"]; v != "" {
		return v
	}
	return ""
}

// GetAutopilotHealth retrieves the Raft autopilot health information.
// Requires an ACL token with operator:read capability.
func (c *Client) GetAutopilotHealth(ctx context.Context, token string) (*AutopilotHealthResult, error) {
	q := (&nomadapi.QueryOptions{AuthToken: token}).WithContext(ctx)

	reply, _, err := c.api.Operator().AutopilotServerHealth(q)
	if err != nil {
		return nil, fmt.Errorf("failed to get autopilot health: %w", err)
	}

	result := &AutopilotHealthResult{
		Healthy:          reply.Healthy,
		FailureTolerance: reply.FailureTolerance,
		Servers:          make([]AutopilotServer, 0, len(reply.Servers)),
	}

	voters := 0
	for _, s := range reply.Servers {
		if s.Voter {
			voters++
		}
		result.Servers = append(result.Servers, AutopilotServer{
			ID:      s.ID,
			Name:    s.Name,
			Address: s.Address,
			Leader:  s.Leader,
			Voter:   s.Voter,
			Healthy: s.Healthy,
			// The SDK parses these from the wire; format back to the
			// string shapes the hand-rolled JSON previously passed
			// through verbatim (RFC3339 timestamp, Go duration string).
			StableSince: s.StableSince.Format(time.RFC3339),
			LastContact: s.LastContact.String(),
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

// AgentSelfResult holds the fields the operator currently extracts from
// /v1/agent/self. Only Version is populated for C7; the struct shape
// matches the sibling result types so future agent fields can be added
// without changing call-site signatures.
type AgentSelfResult struct {
	Version string
}

// RaftPeer is the projection of nomadapi.RaftServer used by the
// operator's scale-down phase (D2 / neo-1ve). Fields are kept to what
// the loop actually consumes today; expand with caution.
//
// Node carries the Nomad server's node name (the pod hostname for
// StatefulSet-managed servers — e.g. "<cluster>-2"). This is the
// per-replica identifier the scale-down loop uses to map peers to
// ordinals; Address is shared across all replicas because the
// operator's HCL template advertises the cluster's LoadBalancer IP
// as advertise.rpc (see pkg/hcl/generator.go).
type RaftPeer struct {
	ID      string
	Node    string
	Address string
	Leader  bool
	Voter   bool
}

// RaftListPeers queries the current Raft configuration. Requires a
// token with operator:read capability.
func (c *Client) RaftListPeers(ctx context.Context, token string) ([]*RaftPeer, error) {
	q := (&nomadapi.QueryOptions{AuthToken: token}).WithContext(ctx)
	cfg, err := c.api.Operator().RaftGetConfiguration(q)
	if err != nil {
		return nil, fmt.Errorf("failed to get Raft configuration: %w", err)
	}
	if cfg == nil {
		return nil, nil
	}
	peers := make([]*RaftPeer, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		peers = append(peers, &RaftPeer{
			ID:      s.ID,
			Node:    s.Node,
			Address: s.Address,
			Leader:  s.Leader,
			Voter:   s.Voter,
		})
	}
	return peers, nil
}

// RaftRemovePeer removes a peer from the Raft quorum by server ID.
// Requires a token with operator:write capability. Used by D2b's
// scale-down loop; do not call from other code paths without
// re-evaluating the safety story (peer removal is irreversible
// within a single Raft generation).
func (c *Client) RaftRemovePeer(ctx context.Context, token, id string) error {
	w := (&nomadapi.WriteOptions{AuthToken: token}).WithContext(ctx)
	if err := c.api.Operator().RaftRemovePeerByID(id, w); err != nil {
		return fmt.Errorf("failed to remove Raft peer %s: %w", id, err)
	}
	return nil
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
// operator for day-2 status API calls (autopilot health, license, leader,
// and the C7 agent-self version probe). operator:read covers autopilot,
// license, and CheckHealth; /v1/status/leader needs no token; agent:read
// is the new addition required by /v1/agent/self.
//
// Since C2 (neo-95g), edits to this constant propagate to EXISTING
// clusters too: the observed-state diff in reconcileOperatorPolicies
// rewrites any policy whose rules drift from this text on the next
// reconcile.
const OperatorStatusPolicyRules = `
operator {
  policy = "read"
}

agent {
  policy = "read"
}
`

// OperatorManagementPolicyRules is the least-privilege write policy for
// the operator's long-lived management token (C4 / AC-2.4.6): ACL
// policy/token management (C2 drift reconciliation, derived-token
// provisioning) plus operator writes (D2 Raft peer removal). Exactly
// these two blocks — AC-2.4.6 pins the text; extending it requires
// updating that AC and TestManagementTokenPolicyText.
const OperatorManagementPolicyRules = `
acl {
  policy = "write"
}

operator {
  policy = "write"
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
