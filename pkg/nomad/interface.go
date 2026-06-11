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

import "context"

// NomadAPI is the subset of *Client methods used by the operator's
// controllers and phases. It exists so call sites can depend on an interface
// (and be unit tested via a generated mock) instead of the concrete *Client.
//
// Only methods actually invoked from internal/ are included. Adding a method
// here without a current caller is forbidden by the project's code quality
// rules.
type NomadAPI interface {
	// ACL bootstrap and tokens
	BootstrapACL() (*ACLBootstrapResult, error)
	CreateACLPolicy(authToken, name, description, rules string) error
	CreateACLTokenWithPolicies(authToken, name string, policies []string) (*ACLTokenResult, error)
	GetACLToken(authToken, accessorID string) (*ACLTokenResult, error)
	DeleteACLToken(authToken, accessorID string) error
	DeleteACLPolicy(authToken, name string) error

	// Cluster status
	GetLeader() (string, error)
	GetPeers() ([]string, error)
	CheckHealth() (*HealthResult, error)
	GetLicense(ctx context.Context, token string) (*LicenseResult, error)
	GetAutopilotHealth(ctx context.Context, token string) (*AutopilotHealthResult, error)
	// AgentSelf queries /v1/agent/self for agent-reported runtime info
	// (currently just the Nomad version). The SDK call does not accept
	// per-request QueryOptions, so the auth token is taken from the
	// client's configured SecretID; callers must construct the client
	// with a token holding `agent:read` capability (C7 / AC-4.7.1).
	AgentSelf(ctx context.Context) (*AgentSelfResult, error)
}

// Compile-time assertion that *Client satisfies NomadAPI.
var _ NomadAPI = (*Client)(nil)
