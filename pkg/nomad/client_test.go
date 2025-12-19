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
		{
			name: "TLS with invalid client cert pair",
			cfg: ClientConfig{
				Address:    "https://localhost:4646",
				TLSEnabled: true,
				ClientCert: []byte("invalid-cert"),
				ClientKey:  []byte("invalid-key"),
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
		if !containsString(AnonymousPolicyRules, section) {
			t.Errorf("AnonymousPolicyRules missing expected section: %s", section)
		}
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStringHelper(s, substr))
}

func containsStringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
