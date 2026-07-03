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

package nomad

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ClientConfig
		wantErr bool
	}{
		{
			name: "basic HTTP client",
			cfg: ClientConfig{
				Address: "http://localhost:4646",
			},
			wantErr: false,
		},
		{
			name: "client with token",
			cfg: ClientConfig{
				Address: "http://localhost:4646",
				Token:   "test-token-123",
			},
			wantErr: false,
		},
		{
			name: "client with custom timeout",
			cfg: ClientConfig{
				Address: "http://localhost:4646",
				Timeout: 60 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "TLS enabled without certs",
			cfg: ClientConfig{
				Address:    "https://localhost:4646",
				TLSEnabled: true,
			},
			wantErr: false,
		},
		{
			name: "TLS with invalid CA cert",
			cfg: ClientConfig{
				Address:    "https://localhost:4646",
				TLSEnabled: true,
				CACert:     []byte("invalid-cert"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("NewClient() returned nil client without error")
			}
		})
	}
}

func TestInternalServiceAddress(t *testing.T) {
	tests := []struct {
		name        string
		clusterName string
		namespace   string
		tlsEnabled  bool
		want        string
	}{
		{
			name:        "HTTP address",
			clusterName: "nomad",
			namespace:   "default",
			tlsEnabled:  false,
			want:        "http://nomad-internal.default.svc:4646",
		},
		{
			name:        "HTTPS address",
			clusterName: "nomad",
			namespace:   "default",
			tlsEnabled:  true,
			want:        "https://nomad-internal.default.svc:4646",
		},
		{
			name:        "custom namespace",
			clusterName: "my-cluster",
			namespace:   "nomad-system",
			tlsEnabled:  false,
			want:        "http://my-cluster-internal.nomad-system.svc:4646",
		},
		{
			name:        "custom namespace with TLS",
			clusterName: "prod-nomad",
			namespace:   "production",
			tlsEnabled:  true,
			want:        "https://prod-nomad-internal.production.svc:4646",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InternalServiceAddress(tt.clusterName, tt.namespace, tt.tlsEnabled)
			if got != tt.want {
				t.Errorf("InternalServiceAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadBalancerAddress(t *testing.T) {
	tests := []struct {
		name             string
		advertiseAddress string
		tlsEnabled       bool
		want             string
	}{
		{
			name:             "empty address returns empty",
			advertiseAddress: "",
			tlsEnabled:       false,
			want:             "",
		},
		{
			name:             "HTTP address",
			advertiseAddress: "10.0.0.1",
			tlsEnabled:       false,
			want:             "http://10.0.0.1:4646",
		},
		{
			name:             "HTTPS address",
			advertiseAddress: "10.0.0.1",
			tlsEnabled:       true,
			want:             "https://10.0.0.1:4646",
		},
		{
			name:             "hostname address",
			advertiseAddress: "nomad.example.com",
			tlsEnabled:       false,
			want:             "http://nomad.example.com:4646",
		},
		{
			name:             "hostname with TLS",
			advertiseAddress: "nomad.example.com",
			tlsEnabled:       true,
			want:             "https://nomad.example.com:4646",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LoadBalancerAddress(tt.advertiseAddress, tt.tlsEnabled)
			if got != tt.want {
				t.Errorf("LoadBalancerAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsNetworkError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "generic error",
			err:  errors.New("some random error"),
			want: false,
		},
		{
			name: "connection refused message",
			err:  errors.New("connection refused"),
			want: true,
		},
		{
			name: "no such host message",
			err:  errors.New("no such host"),
			want: true,
		},
		{
			name: "connection reset message",
			err:  errors.New("connection reset by peer"),
			want: true,
		},
		{
			name: "i/o timeout message",
			err:  errors.New("i/o timeout"),
			want: true,
		},
		{
			name: "network unreachable message",
			err:  errors.New("network is unreachable"),
			want: true,
		},
		{
			name: "no route message",
			err:  errors.New("no route to host"),
			want: true,
		},
		{
			name: "DNS error",
			err:  &net.DNSError{Err: "no such host", Name: "nomad.local"},
			want: true,
		},
		{
			name: "OpError",
			err:  &net.OpError{Op: "dial", Err: errors.New("connection refused")},
			want: true,
		},
		{
			name: "wrapped DNS error",
			err:  errors.Join(errors.New("failed to connect"), &net.DNSError{Err: "no such host", Name: "nomad.local"}),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsNetworkError(tt.err)
			if got != tt.want {
				t.Errorf("IsNetworkError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetLicense(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		token      string
		wantErr    bool
		wantResult *LicenseResult
	}{
		{
			name: "successful license retrieval",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Nomad-Token") != "test-token" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				resp := map[string]interface{}{
					"License": map[string]interface{}{
						"LicenseID":       "license-123",
						"ExpirationTime":  "2025-12-31T00:00:00Z",
						"TerminationTime": "2026-01-31T00:00:00Z",
						"Features":        []string{"Namespaces", "Sentinel"},
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
			},
			token:   "test-token",
			wantErr: false,
			wantResult: &LicenseResult{
				LicenseID:       "license-123",
				ExpirationTime:  "2025-12-31T00:00:00Z",
				TerminationTime: "2026-01-31T00:00:00Z",
				Features:        []string{"Namespaces", "Sentinel"},
			},
		},
		{
			name: "unauthorized",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("unauthorized"))
			},
			token:   "bad-token",
			wantErr: true,
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("internal error"))
			},
			token:   "test-token",
			wantErr: true,
		},
		{
			name: "invalid JSON response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("not json"))
			},
			token:   "test-token",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client, err := NewClient(ClientConfig{
				Address: server.URL,
			})
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			ctx := context.Background()
			result, err := client.GetLicense(ctx, tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetLicense() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.wantResult != nil {
				if result.LicenseID != tt.wantResult.LicenseID {
					t.Errorf("LicenseID = %v, want %v", result.LicenseID, tt.wantResult.LicenseID)
				}
				if result.ExpirationTime != tt.wantResult.ExpirationTime {
					t.Errorf("ExpirationTime = %v, want %v", result.ExpirationTime, tt.wantResult.ExpirationTime)
				}
			}
		})
	}
}

func TestGetLicenseContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(5 * time.Second)
		resp := map[string]interface{}{
			"License": map[string]interface{}{
				"LicenseID": "license-123",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		Address: server.URL,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = client.GetLicense(ctx, "token")
	if err == nil {
		t.Error("Expected context cancellation error, got nil")
	}
}

func TestGetAutopilotHealth(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		token      string
		wantErr    bool
		wantResult *AutopilotHealthResult
	}{
		{
			name: "healthy cluster",
			handler: func(w http.ResponseWriter, r *http.Request) {
				resp := map[string]interface{}{
					"Healthy":          true,
					"FailureTolerance": 1,
					"Servers": []map[string]interface{}{
						{
							"ID":          "server-1",
							"Name":        "nomad-0",
							"Address":     "10.0.0.1:4647",
							"Leader":      true,
							"Voter":       true,
							"Healthy":     true,
							"StableSince": "2025-01-01T00:00:00Z",
							"LastContact": "0s",
						},
						{
							"ID":          "server-2",
							"Name":        "nomad-1",
							"Address":     "10.0.0.2:4647",
							"Leader":      false,
							"Voter":       true,
							"Healthy":     true,
							"StableSince": "2025-01-01T00:00:00Z",
							"LastContact": "10ms",
						},
						{
							"ID":          "server-3",
							"Name":        "nomad-2",
							"Address":     "10.0.0.3:4647",
							"Leader":      false,
							"Voter":       true,
							"Healthy":     true,
							"StableSince": "2025-01-01T00:00:00Z",
							"LastContact": "15ms",
						},
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
			},
			token:   "test-token",
			wantErr: false,
			wantResult: &AutopilotHealthResult{
				Healthy:          true,
				FailureTolerance: 1,
				Voters:           3,
			},
		},
		{
			name: "unhealthy cluster",
			handler: func(w http.ResponseWriter, r *http.Request) {
				resp := map[string]interface{}{
					"Healthy":          false,
					"FailureTolerance": 0,
					"Servers": []map[string]interface{}{
						{
							"ID":      "server-1",
							"Leader":  true,
							"Voter":   true,
							"Healthy": true,
						},
						{
							"ID":      "server-2",
							"Leader":  false,
							"Voter":   true,
							"Healthy": false,
						},
					},
				}
				_ = json.NewEncoder(w).Encode(resp)
			},
			token:   "test-token",
			wantErr: false,
			wantResult: &AutopilotHealthResult{
				Healthy:          false,
				FailureTolerance: 0,
				Voters:           2,
			},
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("service unavailable"))
			},
			token:   "test-token",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client, err := NewClient(ClientConfig{
				Address: server.URL,
			})
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			ctx := context.Background()
			result, err := client.GetAutopilotHealth(ctx, tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAutopilotHealth() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.wantResult != nil {
				if result.Healthy != tt.wantResult.Healthy {
					t.Errorf("Healthy = %v, want %v", result.Healthy, tt.wantResult.Healthy)
				}
				if result.FailureTolerance != tt.wantResult.FailureTolerance {
					t.Errorf("FailureTolerance = %v, want %v", result.FailureTolerance, tt.wantResult.FailureTolerance)
				}
				if result.Voters != tt.wantResult.Voters {
					t.Errorf("Voters = %v, want %v", result.Voters, tt.wantResult.Voters)
				}
			}
		})
	}
}

func TestGetAutopilotHealthContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(5 * time.Second)
		resp := map[string]interface{}{
			"Healthy": true,
			"Servers": []map[string]interface{}{},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		Address: server.URL,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = client.GetAutopilotHealth(ctx, "token")
	if err == nil {
		t.Error("Expected context cancellation error, got nil")
	}
}

func TestErrAlreadyBootstrapped(t *testing.T) {
	// Verify error message
	if ErrAlreadyBootstrapped.Error() != "ACL already bootstrapped" {
		t.Errorf("ErrAlreadyBootstrapped = %v, want 'ACL already bootstrapped'", ErrAlreadyBootstrapped)
	}

	// Verify it can be matched with errors.Is
	wrapped := errors.Join(errors.New("wrapped"), ErrAlreadyBootstrapped)
	if !errors.Is(wrapped, ErrAlreadyBootstrapped) {
		t.Error("Expected errors.Is to match ErrAlreadyBootstrapped")
	}
}

func TestAnonymousPolicyRules(t *testing.T) {
	// Verify the anonymous policy contains expected sections
	expectedSections := []string{
		"namespace",
		"agent",
		"operator",
		"quota",
		"node",
		"host_volume",
	}

	for _, section := range expectedSections {
		if !strings.Contains(AnonymousPolicyRules, section) {
			t.Errorf("AnonymousPolicyRules missing expected section: %s", section)
		}
	}
}

// newACLTestServer fakes the Nomad API routes the ACL and status client
// methods hit, so each method's request formation and response mapping is
// exercised through the real SDK plumbing.
func newACLTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	tokenJSON := map[string]interface{}{
		"AccessorID": "accessor-1",
		"SecretID":   "secret-1",
		"Name":       "test-token",
		"Type":       "client",
		"CreateTime": "2025-01-01T00:00:00Z",
	}

	mux.HandleFunc("/v1/acl/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		mgmt := map[string]interface{}{
			"AccessorID": "boot-accessor",
			"SecretID":   "boot-secret",
			"Name":       "Bootstrap Token",
			"Type":       "management",
			"CreateTime": "2025-01-01T00:00:00Z",
		}
		_ = json.NewEncoder(w).Encode(mgmt)
	})
	mux.HandleFunc("/v1/acl/policy/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v1/acl/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(tokenJSON)
	})
	mux.HandleFunc("/v1/acl/token/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/missing") {
			http.Error(w, "ACL token not found", http.StatusNotFound)
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		_ = json.NewEncoder(w).Encode(tokenJSON)
	})
	mux.HandleFunc("/v1/status/leader", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode("10.0.0.1:4647")
	})
	mux.HandleFunc("/v1/status/peers", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]string{"10.0.0.1:4647", "10.0.0.2:4647"})
	})
	mux.HandleFunc("/v1/agent/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"server": map[string]interface{}{"ok": true, "message": "ok"},
		})
	})

	return httptest.NewServer(mux)
}

func newACLTestClient(t *testing.T, addr string) *Client {
	t.Helper()
	client, err := NewClient(ClientConfig{Address: addr})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	return client
}

func TestBootstrapACL(t *testing.T) {
	server := newACLTestServer(t)
	defer server.Close()
	client := newACLTestClient(t, server.URL)

	result, err := client.BootstrapACL()
	if err != nil {
		t.Fatalf("BootstrapACL() error = %v", err)
	}
	if result.AccessorID != "boot-accessor" || result.SecretID != "boot-secret" {
		t.Errorf("BootstrapACL() = %+v, want boot-accessor/boot-secret", result)
	}
	if result.Type != "management" {
		t.Errorf("Type = %q, want management", result.Type)
	}
}

func TestBootstrapACLAlreadyBootstrapped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "ACL bootstrap already done (reset index: 1)", http.StatusBadRequest)
	}))
	defer server.Close()
	client := newACLTestClient(t, server.URL)

	_, err := client.BootstrapACL()
	if !errors.Is(err, ErrAlreadyBootstrapped) {
		t.Errorf("BootstrapACL() error = %v, want ErrAlreadyBootstrapped", err)
	}
}

func TestCreateACLPolicy(t *testing.T) {
	server := newACLTestServer(t)
	defer server.Close()
	client := newACLTestClient(t, server.URL)

	if err := client.CreateACLPolicy("mgmt-token", "test-policy", "desc", `operator { policy = "read" }`); err != nil {
		t.Errorf("CreateACLPolicy() error = %v", err)
	}
}

func TestCreateACLTokenWithPolicies(t *testing.T) {
	server := newACLTestServer(t)
	defer server.Close()
	client := newACLTestClient(t, server.URL)

	result, err := client.CreateACLTokenWithPolicies("mgmt-token", "test-token", []string{"p1"})
	if err != nil {
		t.Fatalf("CreateACLTokenWithPolicies() error = %v", err)
	}
	if result.AccessorID != "accessor-1" || result.Type != "client" {
		t.Errorf("CreateACLTokenWithPolicies() = %+v, want accessor-1/client", result)
	}
}

func TestGetACLToken(t *testing.T) {
	server := newACLTestServer(t)
	defer server.Close()
	client := newACLTestClient(t, server.URL)

	result, err := client.GetACLToken("mgmt-token", "accessor-1")
	if err != nil {
		t.Fatalf("GetACLToken() error = %v", err)
	}
	if result == nil || result.AccessorID != "accessor-1" {
		t.Errorf("GetACLToken() = %+v, want accessor-1", result)
	}
}

func TestGetACLTokenNotFound(t *testing.T) {
	server := newACLTestServer(t)
	defer server.Close()
	client := newACLTestClient(t, server.URL)

	result, err := client.GetACLToken("mgmt-token", "missing")
	if err != nil {
		t.Fatalf("GetACLToken() error = %v, want nil for not-found", err)
	}
	if result != nil {
		t.Errorf("GetACLToken() = %+v, want nil for not-found", result)
	}
}

func TestDeleteACLToken(t *testing.T) {
	server := newACLTestServer(t)
	defer server.Close()
	client := newACLTestClient(t, server.URL)

	if err := client.DeleteACLToken("mgmt-token", "accessor-1"); err != nil {
		t.Errorf("DeleteACLToken() error = %v", err)
	}
}

func TestDeleteACLPolicy(t *testing.T) {
	server := newACLTestServer(t)
	defer server.Close()
	client := newACLTestClient(t, server.URL)

	if err := client.DeleteACLPolicy("mgmt-token", "test-policy"); err != nil {
		t.Errorf("DeleteACLPolicy() error = %v", err)
	}
}

func TestGetLeader(t *testing.T) {
	server := newACLTestServer(t)
	defer server.Close()
	client := newACLTestClient(t, server.URL)

	leader, err := client.GetLeader()
	if err != nil {
		t.Fatalf("GetLeader() error = %v", err)
	}
	if leader != "10.0.0.1:4647" {
		t.Errorf("GetLeader() = %q, want 10.0.0.1:4647", leader)
	}
}

// TestGetACLPolicy pins the C2 observed-state read: policy fields come
// back verbatim, a 404 maps to (nil, nil) — "policy absent" is data,
// not an error — and other failures surface as errors.
func TestGetACLPolicy(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantErr    bool
		wantResult *ACLPolicyResult
	}{
		{
			name: "existing policy",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/acl/policy/anonymous" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"Name":        "anonymous",
					"Description": "desc",
					"Rules":       `agent { policy = "read" }`,
				})
			},
			wantResult: &ACLPolicyResult{
				Name:        "anonymous",
				Description: "desc",
				Rules:       `agent { policy = "read" }`,
			},
		},
		{
			name: "missing policy returns nil, nil",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("ACL policy not found"))
			},
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client, err := NewClient(ClientConfig{Address: server.URL})
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			result, err := client.GetACLPolicy("token", "anonymous")
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetACLPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantResult == nil {
				if result != nil && !tt.wantErr {
					t.Errorf("GetACLPolicy() = %+v, want nil", result)
				}
				return
			}
			if result == nil || *result != *tt.wantResult {
				t.Errorf("GetACLPolicy() = %+v, want %+v", result, tt.wantResult)
			}
		})
	}
}

// TestAgentSelf pins the C7 version probe: the version is read from
// stats.nomad.version first, falls back to the serf build tag, and an
// absent version is an empty string (probe miss), not an error.
func TestAgentSelf(t *testing.T) {
	tests := []struct {
		name        string
		body        map[string]interface{}
		status      int
		wantErr     bool
		wantVersion string
	}{
		{
			name: "version from stats",
			body: map[string]interface{}{
				"stats":  map[string]interface{}{"nomad": map[string]string{"version": "1.11.0+ent"}},
				"member": map[string]interface{}{"Tags": map[string]string{}},
			},
			wantVersion: "1.11.0+ent",
		},
		{
			name: "version from serf build tag",
			body: map[string]interface{}{
				"stats":  map[string]interface{}{},
				"member": map[string]interface{}{"Tags": map[string]string{"build": "1.11.1+ent"}},
			},
			wantVersion: "1.11.1+ent",
		},
		{
			name: "no version anywhere is a probe miss, not an error",
			body: map[string]interface{}{
				"stats":  map[string]interface{}{},
				"member": map[string]interface{}{"Tags": map[string]string{}},
			},
			wantVersion: "",
		},
		{
			name:    "server error",
			status:  http.StatusInternalServerError,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.status != 0 {
					w.WriteHeader(tt.status)
					return
				}
				_ = json.NewEncoder(w).Encode(tt.body)
			}))
			defer server.Close()

			client, err := NewClient(ClientConfig{Address: server.URL})
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			result, err := client.AgentSelf(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("AgentSelf() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if result.Version != tt.wantVersion {
				t.Errorf("AgentSelf().Version = %q, want %q", result.Version, tt.wantVersion)
			}
		})
	}
}

// TestRaftListPeers pins the D2 peer-list read used by scale-down.
func TestRaftListPeers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/operator/raft/configuration" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"Servers": []map[string]interface{}{
				{"ID": "id-1", "Node": "nomad-0.global", "Address": "10.0.0.1:4647", "Leader": true, "Voter": true},
				{"ID": "id-2", "Node": "nomad-1.global", "Address": "10.0.0.2:4647", "Leader": false, "Voter": true},
			},
			"Index": 7,
		})
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	peers, err := client.RaftListPeers(context.Background(), "token")
	if err != nil {
		t.Fatalf("RaftListPeers() error = %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("RaftListPeers() returned %d peers, want 2", len(peers))
	}
	if peers[0].ID != "id-1" || peers[0].Address != "10.0.0.1:4647" || peers[1].Node != "nomad-1.global" {
		t.Errorf("peer fields not mapped: %+v", peers)
	}

	errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer errServer.Close()
	errClient, _ := NewClient(ClientConfig{Address: errServer.URL})
	if _, err := errClient.RaftListPeers(context.Background(), "token"); err == nil {
		t.Error("RaftListPeers() expected error on 403")
	}
}

// TestRaftRemovePeer pins the D2 peer-removal write used by scale-down.
func TestRaftRemovePeer(t *testing.T) {
	var gotID, gotToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/operator/raft/peer" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotID = r.URL.Query().Get("id")
		gotToken = r.Header.Get("X-Nomad-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if err := client.RaftRemovePeer(context.Background(), "mgmt-token", "id-2"); err != nil {
		t.Fatalf("RaftRemovePeer() error = %v", err)
	}
	if gotID != "id-2" || gotToken != "mgmt-token" {
		t.Errorf("request carried id=%q token=%q, want id-2/mgmt-token", gotID, gotToken)
	}

	errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer errServer.Close()
	errClient, _ := NewClient(ClientConfig{Address: errServer.URL})
	if err := errClient.RaftRemovePeer(context.Background(), "token", "id-2"); err == nil {
		t.Error("RaftRemovePeer() expected error on 403")
	}
}

// TestCreateManagementACLToken pins the C4 management-token mint: the
// request carries Type=management and NO policies — Nomad rejects
// management tokens with policies, and only management-type tokens can
// write ACL state (there is no acl{} policy grammar in Nomad).
func TestCreateManagementACLToken(t *testing.T) {
	var gotBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/acl/token" || r.Method != http.MethodPut {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"AccessorID": "mgmt-acc",
			"SecretID":   "mgmt-secret",
			"Name":       "test-operator-management",
			"Type":       "management",
		})
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{Address: server.URL})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	result, err := client.CreateManagementACLToken("boot-token", "test-operator-management")
	if err != nil {
		t.Fatalf("CreateManagementACLToken() error = %v", err)
	}
	if result.Type != "management" || result.SecretID != "mgmt-secret" {
		t.Errorf("result = %+v, want management/mgmt-secret", result)
	}
	if gotBody["Type"] != "management" {
		t.Errorf("request Type = %v, want management", gotBody["Type"])
	}
	if policies, ok := gotBody["Policies"]; ok && policies != nil {
		t.Errorf("request carried Policies = %v, want none for a management token", policies)
	}
}
