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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad/mocks"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// tokenFixture builds a KeyringPhase whose TokenRequest subresource
// returns a fixed JWT and whose Vault calls are the given fakes.
func tokenFixture(t *testing.T, login VaultLoginFunc, renew VaultRenewFunc) (*KeyringPhase, *nomadv1alpha1.NomadCluster) {
	t.Helper()
	cluster := newTestCluster("kt-ns", "kt")
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "kt", Namespace: "kt-ns"},
		Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To(int32(1))},
		Status: appsv1.StatefulSetStatus{
			UpdatedReplicas: 1, ReadyReplicas: 1,
			CurrentRevision: "r1", UpdateRevision: "r1",
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(sts).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceCreate: func(ctx context.Context, cl client.Client, subResource string, obj client.Object, sub client.Object, opts ...client.SubResourceCreateOption) error {
				if subResource != "token" {
					return fmt.Errorf("unexpected subresource %q", subResource)
				}
				tr := sub.(*authenticationv1.TokenRequest)
				tr.Status.Token = "sa-jwt-ephemeral"
				return nil
			},
		}).Build()
	mock := mocks.NewMockNomadAPI(t)
	phase := &KeyringPhase{PhaseContext: &PhaseContext{
		Client:   c,
		Scheme:   scheme.Scheme,
		Log:      zap.New(zap.UseDevMode(true)),
		Recorder: record.NewFakeRecorder(20),
		NomadClientFactory: func(cfg nomad.ClientConfig) (nomad.NomadAPI, error) {
			return mock, nil
		},
		VaultLogin: login,
		VaultRenew: renew,
	}}
	return phase, cluster
}

func authTransitEntry() nomadv1alpha1.KeyringEntry {
	return nomadv1alpha1.KeyringEntry{
		Name: "primary",
		Transit: &nomadv1alpha1.TransitKeyring{
			Address: "https://vault:8200", KeyName: "nk", MountPath: "transit/",
			Auth: &nomadv1alpha1.TransitAuth{
				Method: "kubernetes", Mount: "kubernetes",
				Kubernetes: &nomadv1alpha1.TransitAuthKubernetes{Role: "nomad"},
			},
		},
	}
}

// TestKeyringTokenMint: first reconcile with an auth entry mints a
// token from an ephemeral TokenRequest JWT, publishes the managed
// Secret, mirrors expiry to status, and schedules a benign revisit.
func TestKeyringTokenMint(t *testing.T) {
	logins := 0
	phase, cluster := tokenFixture(t,
		func(ctx context.Context, cfg VaultCallConfig, mount, role, jwt string) (*vaultAuthResult, error) {
			logins++
			if mount != "kubernetes" || role != "nomad" || jwt != "sa-jwt-ephemeral" {
				t.Fatalf("login args: mount=%q role=%q jwt=%q", mount, role, jwt)
			}
			return &vaultAuthResult{Token: "hvs.token1", LeaseDuration: time.Hour, Renewable: true}, nil
		}, nil)
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{authTransitEntry()}

	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if logins != 1 {
		t.Fatalf("logins = %d, want 1", logins)
	}
	secret := &corev1.Secret{}
	if err := phase.Client.Get(context.Background(),
		types.NamespacedName{Name: "kt-keyring-token", Namespace: "kt-ns"}, secret); err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["VAULT_TOKEN"]) != "hvs.token1" {
		t.Fatalf("secret token = %q", secret.Data["VAULT_TOKEN"])
	}
	if cluster.Status.Keyring.TokenExpiry == nil {
		t.Fatal("status.keyring.tokenExpiry not set")
	}
	if phase.RevisitAfter <= 0 || phase.RevisitAfter > time.Hour {
		t.Fatalf("RevisitAfter = %s", phase.RevisitAfter)
	}

	// Steady state: fresh token means NO further login.
	phase.RevisitAfter = 0
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if logins != 1 {
		t.Fatalf("steady-state pass logged in again (logins=%d)", logins)
	}
	if phase.RevisitAfter <= 0 {
		t.Fatal("steady state must keep a renewal revisit scheduled")
	}
}

// TestKeyringTokenRenewAndRemint: inside the renewal window the token
// is renewed in place (same string, no pod roll); when renewal fails
// the operator re-mints and the Secret value changes.
func TestKeyringTokenRenewAndRemint(t *testing.T) {
	logins, renews := 0, 0
	renewErr := error(nil)
	phase, cluster := tokenFixture(t,
		func(ctx context.Context, cfg VaultCallConfig, mount, role, jwt string) (*vaultAuthResult, error) {
			logins++
			return &vaultAuthResult{Token: fmt.Sprintf("hvs.mint%d", logins), LeaseDuration: time.Hour, Renewable: true}, nil
		},
		func(ctx context.Context, cfg VaultCallConfig, token string) (*vaultAuthResult, error) {
			renews++
			if renewErr != nil {
				return nil, renewErr
			}
			return &vaultAuthResult{Token: token, LeaseDuration: time.Hour, Renewable: true}, nil
		})
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{authTransitEntry()}

	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}

	// Force the state into the renewal window.
	stateCM := &corev1.ConfigMap{}
	if err := phase.Client.Get(context.Background(),
		types.NamespacedName{Name: "kt-keyring-state", Namespace: "kt-ns"}, stateCM); err != nil {
		t.Fatal(err)
	}
	shortenExpiry := func() {
		state := &keyringState{}
		mustUnmarshalState(t, stateCM, state)
		state.Token.ExpiresAt = metav1.NewTime(time.Now().Add(20 * time.Second))
		mustMarshalState(t, phase, stateCM, state)
	}
	shortenExpiry()

	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if renews != 1 || logins != 1 {
		t.Fatalf("renew path: renews=%d logins=%d, want 1/1", renews, logins)
	}
	secret := &corev1.Secret{}
	_ = phase.Client.Get(context.Background(),
		types.NamespacedName{Name: "kt-keyring-token", Namespace: "kt-ns"}, secret)
	if string(secret.Data["VAULT_TOKEN"]) != "hvs.mint1" {
		t.Fatalf("renewal must keep the token string, got %q", secret.Data["VAULT_TOKEN"])
	}

	// Renewal failure: re-mint, secret value changes.
	renewErr = fmt.Errorf("token revoked")
	if err := phase.Client.Get(context.Background(),
		types.NamespacedName{Name: "kt-keyring-state", Namespace: "kt-ns"}, stateCM); err != nil {
		t.Fatal(err)
	}
	shortenExpiry()
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if logins != 2 {
		t.Fatalf("re-mint expected after renewal failure (logins=%d)", logins)
	}
	_ = phase.Client.Get(context.Background(),
		types.NamespacedName{Name: "kt-keyring-token", Namespace: "kt-ns"}, secret)
	if string(secret.Data["VAULT_TOKEN"]) != "hvs.mint2" {
		t.Fatalf("re-mint must rotate the secret, got %q", secret.Data["VAULT_TOKEN"])
	}
}

// TestKeyringTokenReviewerDenied: TokenReview permission failures get
// the distinct legible reason with the remediation matrix hint.
func TestKeyringTokenReviewerDenied(t *testing.T) {
	phase, cluster := tokenFixture(t,
		func(ctx context.Context, cfg VaultCallConfig, mount, role, jwt string) (*vaultAuthResult, error) {
			return nil, fmt.Errorf("vault returned 500: permission denied: tokenreviews.authentication.k8s.io is forbidden")
		}, nil)
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{authTransitEntry()}

	result := phase.Execute(context.Background(), cluster)
	if result.Error == nil || result.Reason != "KeyringVaultReviewerDenied" {
		t.Fatalf("want KeyringVaultReviewerDenied, got %+v", result)
	}
}

// TestKeyringTokenLongLivedSource: serviceAccountTokenSecretRef swaps
// the ephemeral TokenRequest for a user-managed JWT Secret.
func TestKeyringTokenLongLivedSource(t *testing.T) {
	phase, cluster := tokenFixture(t,
		func(ctx context.Context, cfg VaultCallConfig, mount, role, jwt string) (*vaultAuthResult, error) {
			if jwt != "long-lived-jwt" {
				t.Fatalf("jwt = %q, want the Secret-sourced one", jwt)
			}
			return &vaultAuthResult{Token: "hvs.ll", LeaseDuration: time.Hour, Renewable: true}, nil
		}, nil)
	entry := authTransitEntry()
	entry.Transit.Auth.Kubernetes.ServiceAccountTokenSecretRef = &corev1.LocalObjectReference{Name: "sa-jwt"}
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{entry}
	if err := phase.Client.Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "sa-jwt", Namespace: "kt-ns"},
		Data:       map[string][]byte{"token": []byte("long-lived-jwt")},
	}); err != nil {
		t.Fatal(err)
	}

	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
}

// TestKeyringTokenSourcesMutuallyExclusive: auth on one entry and
// credentialsSecretRef on another still collide on VAULT_TOKEN.
func TestKeyringTokenSourcesMutuallyExclusive(t *testing.T) {
	phase, cluster := tokenFixture(t, nil, nil)
	static := nomadv1alpha1.KeyringEntry{
		Name: "static",
		Transit: &nomadv1alpha1.TransitKeyring{
			Address: "https://vault2:8200", KeyName: "nk", MountPath: "transit/",
			Auth: &nomadv1alpha1.TransitAuth{
				Method: "token",
				Token:  &nomadv1alpha1.TransitAuthToken{SecretRef: corev1.LocalObjectReference{Name: "tok"}},
			},
		},
	}
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{authTransitEntry(), static}

	result := phase.Execute(context.Background(), cluster)
	if result.Error == nil || result.Reason != "KeyringInvalid" {
		t.Fatalf("want KeyringInvalid, got %+v", result)
	}
}

// TestVaultCallHTTP exercises the real HTTP layer against httptest:
// login payload/headers, renew token header, and error surfacing.
func TestVaultCallHTTP(t *testing.T) {
	var gotNS, gotToken, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotNS = r.Header.Get("X-Vault-Namespace")
		gotToken = r.Header.Get("X-Vault-Token")
		gotPath = r.URL.Path
		if r.URL.Path == "/v1/auth/kubernetes/login" {
			_, _ = fmt.Fprintf(w, `{"auth":{"client_token":"hvs.abc","lease_duration":3600,"renewable":true}}`)
			return
		}
		if r.URL.Path == "/v1/auth/token/renew-self" {
			_, _ = fmt.Fprintf(w, `{"auth":{"client_token":"","lease_duration":1800,"renewable":true}}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintf(w, `{"errors":["permission denied"]}`)
	}))
	defer srv.Close()

	cfg := VaultCallConfig{Address: srv.URL, Namespace: "team-a"}
	res, err := vaultLogin(context.Background(), cfg, "kubernetes", "nomad", "jwt123")
	if err != nil || res.Token != "hvs.abc" || res.LeaseDuration != time.Hour || !res.Renewable {
		t.Fatalf("login: res=%+v err=%v", res, err)
	}
	if gotNS != "team-a" || gotPath != "/v1/auth/kubernetes/login" {
		t.Fatalf("ns=%q path=%q", gotNS, gotPath)
	}

	res, err = vaultRenewSelf(context.Background(), cfg, "hvs.abc")
	if err != nil || res.Token != "hvs.abc" || res.LeaseDuration != 30*time.Minute {
		t.Fatalf("renew: res=%+v err=%v", res, err)
	}
	if gotToken != "hvs.abc" {
		t.Fatalf("renew token header = %q", gotToken)
	}

	if _, err = vaultLogin(context.Background(), cfg, "denied", "nomad", "jwt123"); err == nil {
		t.Fatal("non-200 must error")
	}
}

func mustUnmarshalState(t *testing.T, cm *corev1.ConfigMap, state *keyringState) {
	t.Helper()
	if err := json.Unmarshal([]byte(cm.Data["state"]), state); err != nil {
		t.Fatal(err)
	}
}

func mustMarshalState(t *testing.T, p *KeyringPhase, cm *corev1.ConfigMap, state *keyringState) {
	t.Helper()
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	cm.Data["state"] = string(raw)
	if err := p.Client.Update(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
}
