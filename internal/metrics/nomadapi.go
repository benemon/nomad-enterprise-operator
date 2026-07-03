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

package metrics

import (
	"context"

	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
)

// instrumentedNomadAPI decorates a NomadAPI, counting every call on the
// nomad_operator_nomad_api_requests_total counter by method and outcome
// (D4b / AC-8.1.2). Pure delegation otherwise.
type instrumentedNomadAPI struct {
	inner nomad.NomadAPI
}

// InstrumentNomadAPI wraps the given client with request counting.
func InstrumentNomadAPI(inner nomad.NomadAPI) nomad.NomadAPI {
	return &instrumentedNomadAPI{inner: inner}
}

// count records one API call. Outcome is "success" or "error" — a 404
// mapped to a nil result by the client (e.g. GetACLPolicy) counts as
// success, since the request itself succeeded.
func count(method string, err error) {
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	NomadAPIRequests.WithLabelValues(method, outcome).Inc()
}

func (i *instrumentedNomadAPI) BootstrapACL() (*nomad.ACLBootstrapResult, error) {
	result, err := i.inner.BootstrapACL()
	count("BootstrapACL", err)
	return result, err
}

func (i *instrumentedNomadAPI) CreateACLPolicy(authToken, name, description, rules string) error {
	err := i.inner.CreateACLPolicy(authToken, name, description, rules)
	count("CreateACLPolicy", err)
	return err
}

func (i *instrumentedNomadAPI) GetACLPolicy(authToken, name string) (*nomad.ACLPolicyResult, error) {
	result, err := i.inner.GetACLPolicy(authToken, name)
	count("GetACLPolicy", err)
	return result, err
}

func (i *instrumentedNomadAPI) CreateManagementACLToken(authToken, name string) (*nomad.ACLTokenResult, error) {
	result, err := i.inner.CreateManagementACLToken(authToken, name)
	count("CreateManagementACLToken", err)
	return result, err
}

func (i *instrumentedNomadAPI) CreateACLTokenWithPolicies(authToken, name string, policies []string) (*nomad.ACLTokenResult, error) {
	result, err := i.inner.CreateACLTokenWithPolicies(authToken, name, policies)
	count("CreateACLTokenWithPolicies", err)
	return result, err
}

func (i *instrumentedNomadAPI) GetACLToken(authToken, accessorID string) (*nomad.ACLTokenResult, error) {
	result, err := i.inner.GetACLToken(authToken, accessorID)
	count("GetACLToken", err)
	return result, err
}

func (i *instrumentedNomadAPI) DeleteACLToken(authToken, accessorID string) error {
	err := i.inner.DeleteACLToken(authToken, accessorID)
	count("DeleteACLToken", err)
	return err
}

func (i *instrumentedNomadAPI) DeleteACLPolicy(authToken, name string) error {
	err := i.inner.DeleteACLPolicy(authToken, name)
	count("DeleteACLPolicy", err)
	return err
}

func (i *instrumentedNomadAPI) GetLeader() (string, error) {
	result, err := i.inner.GetLeader()
	count("GetLeader", err)
	return result, err
}

func (i *instrumentedNomadAPI) GetLicense(ctx context.Context, token string) (*nomad.LicenseResult, error) {
	result, err := i.inner.GetLicense(ctx, token)
	count("GetLicense", err)
	return result, err
}

func (i *instrumentedNomadAPI) GetAutopilotHealth(ctx context.Context, token string) (*nomad.AutopilotHealthResult, error) {
	result, err := i.inner.GetAutopilotHealth(ctx, token)
	count("GetAutopilotHealth", err)
	return result, err
}

func (i *instrumentedNomadAPI) AgentSelf(ctx context.Context) (*nomad.AgentSelfResult, error) {
	result, err := i.inner.AgentSelf(ctx)
	count("AgentSelf", err)
	return result, err
}

func (i *instrumentedNomadAPI) RaftListPeers(ctx context.Context, token string) ([]*nomad.RaftPeer, error) {
	result, err := i.inner.RaftListPeers(ctx, token)
	count("RaftListPeers", err)
	return result, err
}

func (i *instrumentedNomadAPI) RaftRemovePeer(ctx context.Context, token, id string) error {
	err := i.inner.RaftRemovePeer(ctx, token, id)
	count("RaftRemovePeer", err)
	return err
}

// Compile-time assertion that the decorator satisfies NomadAPI, so an
// interface change fails the build here rather than at the wrap site.
var _ nomad.NomadAPI = (*instrumentedNomadAPI)(nil)
