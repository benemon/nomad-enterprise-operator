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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/nomad-enterprise-operator/internal/metrics"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/hcl"
	vaultapi "github.com/hashicorp/vault/api"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// KeyringTokenSecretName is the operator-managed Secret carrying the
// Vault token for an auth-mode transit entry (key VAULT_TOKEN).
func KeyringTokenSecretName(clusterName string) string {
	return clusterName + "-keyring-token"
}

// tokenMeta is the persisted lifecycle state for the managed token,
// stored alongside the migration state in the keyring-state ConfigMap.
type tokenMeta struct {
	ExpiresAt metav1.Time `json:"expiresAt"`
	Renewable bool        `json:"renewable"`
	// AuthHash detects auth-config changes that force a re-mint.
	AuthHash string `json:"authHash"`
}

// vaultAuthResult is the subset of Vault's auth response we consume.
type vaultAuthResult struct {
	Token         string
	LeaseDuration time.Duration
	Renewable     bool
}

// VaultLoginFunc performs a JWT login against a Vault auth mount.
// Injectable for tests; the default is vaultLogin.
type VaultLoginFunc func(ctx context.Context, cfg VaultCallConfig, mount, role, jwt string) (*vaultAuthResult, error)

// VaultRenewFunc renews the given token against Vault.
// Injectable for tests; the default is vaultRenewSelf.
type VaultRenewFunc func(ctx context.Context, cfg VaultCallConfig, token string) (*vaultAuthResult, error)

// VaultCallConfig carries the connection parameters shared by login and
// renew calls.
type VaultCallConfig struct {
	Address   string
	Namespace string
	CACert    []byte
}

// vaultHTTPClient builds a one-shot-connection client (see the nomad
// client transport note: keep-alives leak against per-IP limits).
func vaultHTTPClient(caCert []byte) (*http.Client, error) {
	transport := &http.Transport{DisableKeepAlives: true}
	if len(caCert) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse Vault CA certificate")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

// vaultAPIClient builds a vault/api client over our one-shot-connection
// transport (see the nomad client transport note).
func vaultAPIClient(cfg VaultCallConfig, token string) (*vaultapi.Client, error) {
	httpClient, err := vaultHTTPClient(cfg.CACert)
	if err != nil {
		return nil, err
	}
	apiCfg := vaultapi.DefaultConfig()
	apiCfg.Address = cfg.Address
	apiCfg.HttpClient = httpClient
	client, err := vaultapi.NewClient(apiCfg)
	if err != nil {
		return nil, err
	}
	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}
	if token != "" {
		client.SetToken(token)
	}
	return client, nil
}

func authResult(secret *vaultapi.Secret, fallbackToken string) (*vaultAuthResult, error) {
	if secret == nil || secret.Auth == nil {
		return nil, fmt.Errorf("vault response carried no auth data")
	}
	token := secret.Auth.ClientToken
	if token == "" {
		token = fallbackToken // renew-self may not echo the token
	}
	if token == "" {
		return nil, fmt.Errorf("vault login returned no token")
	}
	return &vaultAuthResult{
		Token:         token,
		LeaseDuration: time.Duration(secret.Auth.LeaseDuration) * time.Second,
		Renewable:     secret.Auth.Renewable,
	}, nil
}

func vaultLogin(ctx context.Context, cfg VaultCallConfig, mount, role, jwt string) (*vaultAuthResult, error) {
	client, err := vaultAPIClient(cfg, "")
	if err != nil {
		return nil, err
	}
	secret, err := client.Logical().WriteWithContext(ctx,
		"auth/"+strings.Trim(mount, "/")+"/login",
		map[string]interface{}{"role": role, "jwt": jwt})
	if err != nil {
		return nil, err
	}
	return authResult(secret, "")
}

func vaultRenewSelf(ctx context.Context, cfg VaultCallConfig, token string) (*vaultAuthResult, error) {
	client, err := vaultAPIClient(cfg, token)
	if err != nil {
		return nil, err
	}
	secret, err := client.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return nil, err
	}
	return authResult(secret, token)
}

// authEntries returns the transit entries in the pod-wiring union,
// each of which carries its own credential (per-entry Vaults are
// supported: one entry per Vault cluster).
func authEntries(entries []nomadv1alpha1.KeyringEntry) []*nomadv1alpha1.KeyringEntry {
	var out []*nomadv1alpha1.KeyringEntry
	for i := range entries {
		if entries[i].Transit != nil && entries[i].Transit.Auth != nil {
			out = append(out, &entries[i])
		}
	}
	return out
}

// saAuthBlock returns the ServiceAccount-JWT config for the entry's
// method (the kubernetes and jwt blocks share a shape).
func saAuthBlock(auth *nomadv1alpha1.TransitAuth) *nomadv1alpha1.TransitAuthKubernetes {
	if auth.Method == "jwt" {
		return auth.JWT
	}
	return auth.Kubernetes
}

// resolveCloudArgs reads each cloud entry's static credentials (when
// credentialsSecretRef is set) and returns per-entry inline block
// arguments. Process-global env delivery is not used: same-type HA
// pairs with distinct credentials would collide. Ambient identity
// (no secretRef) contributes nothing here and nothing in the pod.
func (p *KeyringPhase) resolveCloudArgs(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, state *keyringState) (map[string][]hcl.KeyringArg, PhaseResult) {
	out := map[string][]hcl.KeyringArg{}
	read := func(entryName, secretName string, keys map[string]string, optional map[string]string) PhaseResult {
		secret := &corev1.Secret{}
		if err := p.Client.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, secret); err != nil {
			return ErrorWithReason(err, "KeyringCredentialsUnavailable",
				fmt.Sprintf("entry %q: credentials Secret %q: %v", entryName, secretName, err))
		}
		var args []hcl.KeyringArg
		for k, param := range keys {
			v := string(secret.Data[k])
			if v == "" {
				return ErrorWithReason(
					fmt.Errorf("secret %q has no %s key", secretName, k),
					"KeyringCredentialsUnavailable",
					fmt.Sprintf("entry %q: credentials Secret %q has no %s key", entryName, secretName, k))
			}
			args = append(args, hcl.KeyringArg{Key: param, Value: v})
		}
		for k, param := range optional {
			if v := string(secret.Data[k]); v != "" {
				args = append(args, hcl.KeyringArg{Key: param, Value: v})
			}
		}
		sort.Slice(args, func(i, j int) bool { return args[i].Key < args[j].Key })
		out[entryName] = args
		return OK()
	}
	for _, sk := range append(append([]storedKeyring{}, state.Active...), state.Retiring...) {
		if sk.Entry == nil {
			continue
		}
		e := sk.Entry
		switch {
		case e.AWSKMS != nil && e.AWSKMS.CredentialsSecretRef != nil:
			if r := read(e.Name, e.AWSKMS.CredentialsSecretRef.Name,
				map[string]string{"AWS_ACCESS_KEY_ID": "access_key", "AWS_SECRET_ACCESS_KEY": "secret_key"},
				map[string]string{"AWS_SESSION_TOKEN": "session_token"}); r.Error != nil {
				return out, r
			}
		case e.AzureKeyVault != nil && e.AzureKeyVault.CredentialsSecretRef != nil:
			if r := read(e.Name, e.AzureKeyVault.CredentialsSecretRef.Name,
				map[string]string{"AZURE_CLIENT_ID": "client_id", "AZURE_CLIENT_SECRET": "client_secret"},
				nil); r.Error != nil {
				return out, r
			}
		}
	}
	return out, OK()
}

// ensureVaultTokens resolves every transit entry's token: method=token
// reads the user's Secret (user-owned lifecycle); login methods run the
// per-entry mint/renew/re-mint machinery. Returns the resolved token
// values (rendered inline into the keyring blocks), the earliest
// renewal revisit, and the first error.
func (p *KeyringPhase) ensureVaultTokens(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, state *keyringState, cm *corev1.ConfigMap) (map[string]string, time.Duration, []string) {
	tokens := map[string]string{}
	var revisit time.Duration
	// Failures are collected, never returned early: one entry's dead
	// credential (a retiring mount, a stale token) must not block the
	// others' resolution or the phase chain behind them.
	var failures []string
	for _, entry := range authEntries(entriesUnion(state)) {
		auth := entry.Transit.Auth
		if auth.Method == "token" {
			secret := &corev1.Secret{}
			if err := p.Client.Get(ctx, types.NamespacedName{
				Name: auth.Token.SecretRef.Name, Namespace: cluster.Namespace}, secret); err != nil {
				failures = append(failures, fmt.Sprintf("entry %q: token Secret %q: %v", entry.Name, auth.Token.SecretRef.Name, err))
				continue
			}
			tok := string(secret.Data["VAULT_TOKEN"])
			if tok == "" {
				failures = append(failures, fmt.Sprintf("entry %q: token Secret %q has no VAULT_TOKEN key", entry.Name, auth.Token.SecretRef.Name))
				continue
			}
			tokens[entry.Name] = tok
			continue
		}
		tok, entryRevisit, result := p.ensureManagedToken(ctx, cluster, state, cm, entry)
		if result.Error != nil {
			failures = append(failures, fmt.Sprintf("entry %q: %s", entry.Name, result.Message))
			continue
		}
		tokens[entry.Name] = tok
		if entryRevisit > 0 && (revisit == 0 || entryRevisit < revisit) {
			revisit = entryRevisit
		}
	}
	return tokens, revisit, failures
}

// ensureManagedToken runs one entry's lifecycle: mint when absent or
// stale-config, renew inside the renewal window, re-mint when renewal
// fails. The minted token's canonical store is the multi-key managed
// Secret <cluster>-keyring-token (key = entry name).
func (p *KeyringPhase) ensureManagedToken(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, state *keyringState, cm *corev1.ConfigMap, entry *nomadv1alpha1.KeyringEntry) (string, time.Duration, PhaseResult) {
	auth := entry.Transit.Auth

	cfg, err := p.vaultCallConfig(ctx, cluster, entry)
	if err != nil {
		return "", 0, ErrorWithReason(err, "KeyringVaultLoginFailed",
			fmt.Sprintf("entry %q: Vault connection config: %v", entry.Name, err))
	}

	authHash := hashAny(auth)
	store := &corev1.Secret{}
	storeAbsent := false
	if err := p.Client.Get(ctx, types.NamespacedName{
		Name: KeyringTokenSecretName(cluster.Name), Namespace: cluster.Namespace}, store); err != nil {
		if !errors.IsNotFound(err) {
			return "", 0, Error(err, "Failed to read managed keyring token Secret")
		}
		storeAbsent = true
	}
	current := ""
	if !storeAbsent {
		current = string(store.Data[entry.Name])
	}

	if state.Tokens == nil {
		state.Tokens = map[string]*tokenMeta{}
	}
	meta := state.Tokens[entry.Name]
	now := time.Now()

	// Renew path: token exists, config unchanged, inside its lease.
	if current != "" && meta != nil && meta.AuthHash == authHash && now.Before(meta.ExpiresAt.Time) {
		remaining := meta.ExpiresAt.Sub(now)
		if remaining > renewalWindow(meta) {
			return current, remaining - renewalWindow(meta), OK()
		}
		if meta.Renewable {
			renewed, rerr := p.renewFunc()(ctx, cfg, current)
			if rerr == nil {
				metrics.KeyringTokenRenewals.WithLabelValues(cluster.Name, cluster.Namespace, entry.Name).Inc()
				state.Tokens[entry.Name] = &tokenMeta{
					ExpiresAt: metav1.NewTime(now.Add(renewed.LeaseDuration)),
					Renewable: renewed.Renewable,
					AuthHash:  authHash,
				}
				if serr := p.saveState(ctx, cm, state); serr != nil {
					return "", 0, Error(serr, "Failed to persist keyring token state")
				}
				return current, renewed.LeaseDuration - renewalWindow(state.Tokens[entry.Name]), OK()
			}
			// Fall through to re-mint on renewal failure.
		}
	}

	// Mint path.
	jwt, jerr := p.serviceAccountJWT(ctx, cluster, auth)
	if jerr != nil {
		return "", 0, ErrorWithReason(jerr, "KeyringVaultLoginFailed",
			fmt.Sprintf("entry %q: ServiceAccount JWT source: %v", entry.Name, jerr))
	}
	result, lerr := p.loginFunc()(ctx, cfg, auth.Mount, saAuthBlock(auth).Role, jwt)
	if lerr != nil {
		reason := "KeyringVaultLoginFailed"
		msg := fmt.Sprintf("entry %q: Vault login at mount %q: %v", entry.Name, auth.Mount, lerr)
		// TokenReview permission failures have a distinct remediation
		// (the Vault-side reviewer matrix) — make them legible.
		if strings.Contains(lerr.Error(), "tokenreview") || strings.Contains(lerr.Error(), "TokenReview") {
			reason = "KeyringVaultReviewerDenied"
			msg = fmt.Sprintf("entry %q: Vault cannot validate ServiceAccount tokens (TokenReview denied): "+
				"grant system:auth-delegator per the auth-mode matrix, or configure the mount "+
				"with a token_reviewer_jwt: %v", entry.Name, lerr)
		}
		return "", 0, ErrorWithReason(lerr, reason, msg)
	}
	metrics.KeyringTokenMints.WithLabelValues(cluster.Name, cluster.Namespace, entry.Name).Inc()

	if err := p.writeTokenStore(ctx, cluster, store, storeAbsent, entry.Name, result.Token); err != nil {
		return "", 0, Error(err, "Failed to write managed keyring token Secret")
	}
	state.Tokens[entry.Name] = &tokenMeta{
		ExpiresAt: metav1.NewTime(now.Add(result.LeaseDuration)),
		Renewable: result.Renewable,
		AuthHash:  authHash,
	}
	if serr := p.saveState(ctx, cm, state); serr != nil {
		return "", 0, Error(serr, "Failed to persist keyring token state")
	}
	if p.Recorder != nil {
		p.Recorder.Event(cluster, corev1.EventTypeNormal, "KeyringVaultTokenMinted",
			fmt.Sprintf("Vault token minted for entry %q at mount %q (lease %s)", entry.Name, auth.Mount, result.LeaseDuration))
	}
	return result.Token, result.LeaseDuration - renewalWindow(state.Tokens[entry.Name]), OK()
}

// renewalWindow is how far before expiry renewal begins: a third of the
// lease, clamped to [30s, 1h].
func renewalWindow(meta *tokenMeta) time.Duration {
	lease := time.Until(meta.ExpiresAt.Time)
	w := lease / 3
	if w < 30*time.Second {
		w = 30 * time.Second
	}
	if w > time.Hour {
		w = time.Hour
	}
	return w
}

// serviceAccountJWT obtains the login JWT: a user-managed long-lived
// token when serviceAccountTokenSecretRef is set, otherwise an
// ephemeral audience-bound TokenRequest token for the CLUSTER's
// ServiceAccount — used once, immediately, never stored.
func (p *KeyringPhase) serviceAccountJWT(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, auth *nomadv1alpha1.TransitAuth) (string, error) {
	sa := saAuthBlock(auth)
	if sa == nil {
		return "", fmt.Errorf("auth method %q has no matching configuration block", auth.Method)
	}
	if sa.ServiceAccountTokenSecretRef != nil {
		secret := &corev1.Secret{}
		if err := p.Client.Get(ctx, types.NamespacedName{
			Name: sa.ServiceAccountTokenSecretRef.Name, Namespace: cluster.Namespace}, secret); err != nil {
			return "", err
		}
		jwt := string(secret.Data["token"])
		if jwt == "" {
			return "", fmt.Errorf("secret %q has no token key", sa.ServiceAccountTokenSecretRef.Name)
		}
		return jwt, nil
	}

	expiration := sa.TokenExpirationSeconds
	if expiration == 0 {
		expiration = 600
	}
	audiences := sa.Audiences
	if len(audiences) == 0 {
		audiences = []string{"vault"}
	}
	tr := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         audiences,
			ExpirationSeconds: &expiration,
		},
	}
	account := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
		Name: cluster.Name, Namespace: cluster.Namespace}}
	if err := p.Client.SubResource("token").Create(ctx, account, tr); err != nil {
		return "", fmt.Errorf("TokenRequest for ServiceAccount %q: %w", cluster.Name, err)
	}
	return tr.Status.Token, nil
}

// vaultCallConfig assembles address/namespace/CA for the entry's Vault.
func (p *KeyringPhase) vaultCallConfig(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, entry *nomadv1alpha1.KeyringEntry) (VaultCallConfig, error) {
	t := entry.Transit
	ns := t.Auth.Namespace
	if ns == "" {
		ns = t.Namespace
	}
	cfg := VaultCallConfig{Address: t.Address, Namespace: ns}
	if t.CASecretRef != nil {
		secret := &corev1.Secret{}
		if err := p.Client.Get(ctx, types.NamespacedName{
			Name: t.CASecretRef.Name, Namespace: cluster.Namespace}, secret); err != nil {
			return cfg, err
		}
		cfg.CACert = secret.Data["ca.crt"]
	}
	return cfg, nil
}

// writeTokenStore creates or updates the multi-key managed Secret
// (key = entry name). It is the canonical store the renewal loop
// re-reads; pods consume tokens via the rendered config, not this
// Secret.
func (p *KeyringPhase) writeTokenStore(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, existing *corev1.Secret, absent bool, entryName, token string) error {
	if absent {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      KeyringTokenSecretName(cluster.Name),
				Namespace: cluster.Namespace,
				Labels:    GetLabels(cluster),
			},
			Data: map[string][]byte{entryName: []byte(token)},
		}
		if err := controllerutil.SetControllerReference(cluster, secret, p.Scheme); err != nil {
			return err
		}
		return p.Client.Create(ctx, secret)
	}
	if string(existing.Data[entryName]) == token {
		return nil
	}
	if existing.Data == nil {
		existing.Data = map[string][]byte{}
	}
	existing.Data[entryName] = []byte(token)
	return p.Client.Update(ctx, existing)
}

// entriesUnion is the active+retiring entry union (nil aead skipped).
func entriesUnion(state *keyringState) []nomadv1alpha1.KeyringEntry {
	var entries []nomadv1alpha1.KeyringEntry
	for _, sk := range append(append([]storedKeyring{}, state.Active...), state.Retiring...) {
		if sk.Entry != nil {
			entries = append(entries, *sk.Entry)
		}
	}
	return entries
}

func hashAny(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

func (p *KeyringPhase) loginFunc() VaultLoginFunc {
	if p.VaultLogin != nil {
		return p.VaultLogin
	}
	return vaultLogin
}

func (p *KeyringPhase) renewFunc() VaultRenewFunc {
	if p.VaultRenew != nil {
		return p.VaultRenew
	}
	return vaultRenewSelf
}
