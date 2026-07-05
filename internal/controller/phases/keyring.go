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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/hcl"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// KeyringPhase reconciles the cluster's keyring set: which KMS
// providers wrap Nomad's root keys. Migration between sets (enable,
// disable, provider change, HA expand/contract) is a three-step cycle:
// introduce (render union, roll), rotate (full rotation + old-key
// removal), retire (drop demoted blocks, final roll). State lives in
// the <cluster>-keyring-state ConfigMap so a restarted operator
// resumes mid-migration; status.keyring mirrors it for users.
type KeyringPhase struct {
	*PhaseContext

	// probeDegraded marks a Ready state machine whose Nomad-side
	// keyring failed the operational probe; publish() reports it.
	probeDegraded bool
}

// NewKeyringPhase creates a new KeyringPhase.
func NewKeyringPhase(ctx *PhaseContext) *KeyringPhase {
	return &KeyringPhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *KeyringPhase) Name() string { return "Keyring" }

// keyringState is the persisted migration state. Full spec ENTRIES are
// stored, not rendered blocks: a retiring wrapper still needs its
// credentials wired into the pods until its keys are removed, and by
// then the spec no longer carries the entry — the state is the only
// place its secretRefs survive.
type keyringState struct {
	// Active entries wrap new keys. Empty means the implicit aead
	// default. A nil Entry represents the explicit aead block.
	Active []storedKeyring `json:"active"`
	// Retiring entries render active=false until their keys are gone.
	Retiring []storedKeyring `json:"retiring,omitempty"`
	// Phase: Ready | Introducing | Rotating | Retiring.
	Phase string `json:"phase"`
	// Tokens is the per-entry managed Vault token lifecycle state,
	// keyed by entry name (login methods only).
	Tokens map[string]*tokenMeta `json:"tokens,omitempty"`

	// LastDegraded dedupes degraded-cause events across revisits.
	LastDegraded string `json:"lastDegraded,omitempty"`
}

// storedKeyring is one persisted keyring: the full spec entry, or nil
// for the explicit aead block.
type storedKeyring struct {
	Entry *nomadv1alpha1.KeyringEntry `json:"entry,omitempty"`
}

const (
	keyringPhaseReady       = "Ready"
	keyringPhaseIntroducing = "Introducing"
	keyringPhaseRotating    = "Rotating"
	keyringPhaseRetiring    = "Retiring"
)

// serverConfigKey is the rendered-HCL key in <cluster>-config; shared
// with the ConfigMap phase so the delivered-config gate cannot drift.
const serverConfigKey = "server.hcl"

func keyringStateName(cluster *nomadv1alpha1.NomadCluster) string {
	return cluster.Name + "-keyring-state"
}

// Execute reconciles the keyring set and publishes the render set
// (PhaseContext.Keyrings) and the pod-wiring entry union
// (PhaseContext.KeyringEntries) for the downstream phases.
func (p *KeyringPhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	desired, err := desiredKeyrings(cluster)
	if err != nil {
		return ErrorWithReason(err, "KeyringInvalid", err.Error())
	}

	state, cm, result := p.loadState(ctx, cluster, desired)
	if result.Error != nil {
		return result
	}

	// Spec changes are absorbed BEFORE credential work: a stale entry
	// whose login fails must never block the state update that
	// replaces it (an early return here deadlocked a live migration —
	// the failing credential gated its own cure).
	if result := p.absorbSpecChanges(ctx, cluster, state, cm, desired); result.Error != nil {
		return result
	}

	// Credential failures are tolerated per entry: the render proceeds
	// with the tokens that resolved, the cause is surfaced, and the
	// phase chain keeps flowing so config delivery can heal drift.
	tokens, tokenRequeue, tokenFailures := p.ensureVaultTokens(ctx, cluster, state, cm)
	if len(tokenFailures) > 0 {
		p.surfaceDegraded(ctx, cluster, state, cm, "KeyringVaultLoginFailed", strings.Join(tokenFailures, "; "))
		if p.RevisitAfter == 0 || p.RevisitAfter > 30*time.Second {
			p.RevisitAfter = 30 * time.Second
		}
	}
	cloudArgs, cloudResult := p.resolveCloudArgs(ctx, cluster, state)
	if cloudResult.Error != nil {
		p.publish(cluster, state, tokens, cloudArgs)
		return cloudResult
	}

	switch state.Phase {
	case keyringPhaseIntroducing:
		// Wait for every pod to run the union config, then rotate so
		// all keys are wrapped by the new active set.
		if p.statefulSetFullyRolled(ctx, cluster) && p.keyringConfigDelivered(ctx, cluster, state) {
			token, terr := getManagementToken(ctx, p.Client, cluster)
			if terr != nil {
				// Pending, not fatal: a Requeue here stops the phase
				// chain and freezes the config Secret — the exact
				// deadlock when the rendered token has gone stale.
				p.surfaceDegraded(ctx, cluster, state, cm, "KeyringRotationPending",
					"Keyring rotation waiting for the management token")
				p.RevisitAfter = 15 * time.Second
				break
			}
			if rerr := p.rotate(ctx, cluster, token); rerr != nil {
				p.surfaceDegraded(ctx, cluster, state, cm, "KeyringRotationPending",
					fmt.Sprintf("Keyring rotation pending: %v", rerr))
				p.RevisitAfter = 15 * time.Second
				break
			}
			state.Phase = keyringPhaseRotating
			if err := p.saveState(ctx, cm, state); err != nil {
				return Error(err, "Failed to persist keyring state")
			}
		}

	case keyringPhaseRotating:
		// Remove keys no longer wrapped by the active set; when only
		// active keys remain, drop the demoted entries.
		token, terr := getManagementToken(ctx, p.Client, cluster)
		if terr == nil {
			done, kerr := p.removeInactiveKeys(ctx, cluster, token)
			if kerr != nil {
				p.surfaceDegraded(ctx, cluster, state, cm, "KeyringRotationPending",
					fmt.Sprintf("Keyring cleanup pending: %v", kerr))
				p.RevisitAfter = 15 * time.Second
				break
			}
			if done {
				state.Retiring = nil
				state.Phase = keyringPhaseRetiring
				if err := p.saveState(ctx, cm, state); err != nil {
					return Error(err, "Failed to persist keyring state")
				}
			}
		}

	case keyringPhaseReady:
		p.probeSteadyState(ctx, cluster, state, cm)

	case keyringPhaseRetiring:
		// Final roll delivers the retire render; then steady state.
		if p.statefulSetFullyRolled(ctx, cluster) && p.keyringConfigDelivered(ctx, cluster, state) {
			state.Phase = keyringPhaseReady
			if err := p.saveState(ctx, cm, state); err != nil {
				return Error(err, "Failed to persist keyring state")
			}
			if p.Recorder != nil {
				p.Recorder.Event(cluster, corev1.EventTypeNormal, "KeyringMigrationCompleted",
					fmt.Sprintf("Keyring set is [%s]", storedNames(state.Active)))
			}
		}
	}

	p.publish(cluster, state, tokens, cloudArgs)
	if tokenRequeue > 0 {
		p.RevisitAfter = tokenRequeue
	}
	return OK()
}

// publish exposes the render set and the pod-wiring entry union on the
// PhaseContext and mirrors names/phase into status. Each transit block
// carries its resolved token INLINE (Nomad's per-block token parameter
// — the config artifact is a Secret, so custody class holds); the
// VAULT_TOKEN env is not used.
func (p *KeyringPhase) publish(cluster *nomadv1alpha1.NomadCluster, state *keyringState, tokens map[string]string, cloudArgs map[string][]hcl.KeyringArg) {
	blocks := renderBlocks(state)
	for i := range blocks {
		if tok, ok := tokens[blocks[i].Name]; ok && tok != "" {
			blocks[i].Args = append(blocks[i].Args, hcl.KeyringArg{Key: "token", Value: tok})
		}
		blocks[i].Args = append(blocks[i].Args, cloudArgs[blocks[i].Name]...)
	}
	p.Keyrings = blocks

	var entries []nomadv1alpha1.KeyringEntry
	for _, sk := range append(append([]storedKeyring{}, state.Active...), state.Retiring...) {
		if sk.Entry != nil {
			entries = append(entries, *sk.Entry)
		}
	}
	p.KeyringEntries = entries

	displayPhase := state.Phase
	if p.probeDegraded {
		displayPhase = "Degraded"
	}
	st := &nomadv1alpha1.KeyringStatus{Phase: displayPhase}
	for _, sk := range state.Active {
		st.Active = append(st.Active, storedName(sk))
	}
	if len(st.Active) == 0 {
		st.Active = []string{"aead"}
	}
	for _, sk := range state.Retiring {
		st.Retiring = append(st.Retiring, storedName(sk))
	}
	for _, meta := range state.Tokens {
		if st.TokenExpiry == nil || meta.ExpiresAt.Before(st.TokenExpiry) {
			st.TokenExpiry = meta.ExpiresAt.DeepCopy()
		}
	}
	cluster.Status.Keyring = st
}

// renderBlocks derives the HCL render set: active entries active=true,
// retiring entries active=false.
func renderBlocks(state *keyringState) []hcl.KeyringBlock {
	out := make([]hcl.KeyringBlock, 0, len(state.Active)+len(state.Retiring))
	for _, sk := range state.Active {
		out = append(out, entryBlock(sk, true))
	}
	for _, sk := range state.Retiring {
		out = append(out, entryBlock(sk, false))
	}
	return out
}

// entryBlock renders one stored keyring. The aead block (nil Entry) is
// NAMELESS: implicit-default-wrapped keys only match the unnamed aead
// identity — a named block cannot load them (verified empirically).
func entryBlock(sk storedKeyring, active bool) hcl.KeyringBlock {
	if sk.Entry == nil {
		return hcl.KeyringBlock{Type: "aead", Active: active}
	}
	e := sk.Entry
	b := hcl.KeyringBlock{Name: e.Name, Active: active}
	switch {
	case e.AWSKMS != nil:
		b.Type = "awskms"
		b.Args = kvs("kms_key_id", e.AWSKMS.KMSKeyID, "region", e.AWSKMS.Region, "endpoint", e.AWSKMS.Endpoint)
	case e.AzureKeyVault != nil:
		b.Type = "azurekeyvault"
		b.Args = kvs("vault_name", e.AzureKeyVault.VaultName, "key_name", e.AzureKeyVault.KeyName,
			"tenant_id", e.AzureKeyVault.TenantID, "environment", e.AzureKeyVault.Environment,
			"resource", e.AzureKeyVault.Resource)
	case e.GCPCKMS != nil:
		b.Type = "gcpckms"
		b.Args = kvs("project", e.GCPCKMS.Project, "region", e.GCPCKMS.Region,
			"key_ring", e.GCPCKMS.KeyRing, "crypto_key", e.GCPCKMS.CryptoKey)
		if e.GCPCKMS.CredentialsSecretRef != nil {
			b.Args = append(b.Args, hcl.KeyringArg{Key: "credentials", Value: KeyringGCPCredentialsPath(e.Name)})
		}
	case e.Transit != nil:
		b.Type = "transit"
		b.Args = kvs("address", e.Transit.Address, "key_name", e.Transit.KeyName,
			"mount_path", e.Transit.MountPath, "namespace", e.Transit.Namespace,
			"key_id_prefix", e.Transit.KeyIDPrefix, "tls_server_name", e.Transit.TLSServerName)
		if e.Transit.CASecretRef != nil {
			b.Args = append(b.Args, hcl.KeyringArg{Key: "tls_ca_cert", Value: keyringTLSPath(e.Name) + "/ca.crt"})
		}
		if e.Transit.ClientCertSecretRef != nil {
			b.Args = append(b.Args,
				hcl.KeyringArg{Key: "tls_client_cert", Value: keyringTLSPath(e.Name) + "-client/tls.crt"},
				hcl.KeyringArg{Key: "tls_client_key", Value: keyringTLSPath(e.Name) + "-client/tls.key"})
		}
	}
	return b
}

// desiredKeyrings maps spec entries onto stored form, validating the
// single-VAULT_TOKEN constraint (the wrapper reads one shared env var).
func desiredKeyrings(cluster *nomadv1alpha1.NomadCluster) ([]storedKeyring, error) {
	out := make([]storedKeyring, 0, len(cluster.Spec.Server.Keyrings))
	transits := 0
	prefixes := map[string]bool{}
	for i := range cluster.Spec.Server.Keyrings {
		e := cluster.Spec.Server.Keyrings[i]
		if e.Transit != nil {
			transits++
			prefixes[e.Transit.KeyIDPrefix] = true
		}
		out = append(out, storedKeyring{Entry: &e})
	}
	// Multiple transit entries (same or different Vaults) need Nomad's
	// own wrapped-key disambiguation: distinct non-empty keyIDPrefix.
	if transits > 1 && (prefixes[""] || len(prefixes) != transits) {
		return nil, fmt.Errorf("multiple transit keyrings require a distinct non-empty keyIDPrefix on each entry")
	}
	sort.Slice(out, func(i, j int) bool { return storedName(out[i]) < storedName(out[j]) })
	return out, nil
}

// rotate performs the full immediate rotation (the CLI's -now).
func (p *KeyringPhase) rotate(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, token string) error {
	client, err := p.keyringClient(cluster, token)
	if err != nil {
		return err
	}
	return client.KeyringRotateFull(ctx, token)
}

// keyringClient targets the internal Service (BuildClientConfig leaves
// the address to callers).
func (p *KeyringPhase) keyringClient(cluster *nomadv1alpha1.NomadCluster, token string) (nomad.NomadAPI, error) {
	cfg := p.BuildClientConfig(30*time.Second, token)
	cfg.Address = nomad.InternalServiceAddress(cluster.Name, cluster.Namespace, true)
	return p.NewNomadClient(cfg)
}

// removeInactiveKeys deletes terminal non-active keys; true when only
// active keys remain. Keys still rekeying are waited on, not deleted.
func (p *KeyringPhase) removeInactiveKeys(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, token string) (bool, error) {
	client, err := p.keyringClient(cluster, token)
	if err != nil {
		return false, err
	}
	keys, err := client.KeyringList(ctx, token)
	if err != nil {
		return false, err
	}
	done := true
	for _, k := range keys {
		switch k.State {
		case "active":
			continue
		case "inactive":
			done = false
			if err := client.KeyringDelete(ctx, token, k.KeyID); err != nil {
				return false, err
			}
		default:
			// "rekeying" (and anything unknown): re-encryption still in
			// flight — deletion would be refused; just wait.
			done = false
		}
	}
	return done, nil
}

// keyringConfigDelivered reports whether the live ConfigMap carries the
// current render — the roll the pods completed included this state.
func (p *KeyringPhase) keyringConfigDelivered(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, state *keyringState) bool {
	secret := &corev1.Secret{}
	if err := p.Client.Get(ctx, types.NamespacedName{Name: cluster.Name + "-config", Namespace: cluster.Namespace}, secret); err != nil {
		return false
	}
	nomadHCL := string(secret.Data[serverConfigKey])
	for _, b := range renderBlocks(state) {
		if !containsBlock(nomadHCL, b) {
			return false
		}
	}
	return true
}

func containsBlock(nomadHCL string, b hcl.KeyringBlock) bool {
	if b.Name == "" {
		return strings.Contains(nomadHCL, fmt.Sprintf("keyring %q", b.Type))
	}
	return strings.Contains(nomadHCL, fmt.Sprintf("name   = %q", b.Name))
}

// loadState fetches or initialises the state ConfigMap. A cluster born
// with keyrings configured starts directly in that steady state — no
// aead keys ever exist, so no migration is needed.
func (p *KeyringPhase) loadState(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, desired []storedKeyring) (*keyringState, *corev1.ConfigMap, PhaseResult) {
	cm := &corev1.ConfigMap{}
	err := p.Client.Get(ctx, types.NamespacedName{Name: keyringStateName(cluster), Namespace: cluster.Namespace}, cm)
	if err == nil {
		state := &keyringState{}
		if jerr := json.Unmarshal([]byte(cm.Data["state"]), state); jerr != nil {
			return nil, nil, Error(jerr, "Corrupt keyring state ConfigMap")
		}
		return state, cm, OK()
	}
	if !errors.IsNotFound(err) {
		return nil, nil, Error(err, "Failed to read keyring state")
	}

	state := &keyringState{Active: desired, Phase: keyringPhaseReady}
	cm = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      keyringStateName(cluster),
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
	}
	if err := controllerutil.SetControllerReference(cluster, cm, p.Scheme); err != nil {
		return nil, nil, Error(err, "Failed to set owner reference on keyring state")
	}
	raw, _ := json.Marshal(state)
	cm.Data = map[string]string{"state": string(raw)}
	if err := p.Client.Create(ctx, cm); err != nil {
		return nil, nil, Error(err, "Failed to create keyring state ConfigMap")
	}
	return state, cm, OK()
}

func (p *KeyringPhase) saveState(ctx context.Context, cm *corev1.ConfigMap, state *keyringState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	cm.Data = map[string]string{"state": string(raw)}
	return p.Client.Update(ctx, cm)
}

// KeyringSecretNames lists every Secret the spec's keyring entries
// reference; used by the D5 field index.
func KeyringSecretNames(c *nomadv1alpha1.NomadCluster) []string {
	return KeyringSecretNamesFromEntries(c.Spec.Server.Keyrings)
}

// KeyringSecretNamesFromEntries is the entry-list form, used with the
// active+retiring union for pod wiring and the secrets checksum.
func KeyringSecretNamesFromEntries(entries []nomadv1alpha1.KeyringEntry) []string {
	var out []string
	add := func(r *corev1.LocalObjectReference) {
		if r != nil && r.Name != "" {
			out = append(out, r.Name)
		}
	}
	for _, e := range entries {
		if e.AWSKMS != nil {
			add(e.AWSKMS.CredentialsSecretRef)
		}
		if e.AzureKeyVault != nil {
			add(e.AzureKeyVault.CredentialsSecretRef)
		}
		if e.GCPCKMS != nil {
			add(e.GCPCKMS.CredentialsSecretRef)
		}
		if e.Transit != nil {
			add(e.Transit.CASecretRef)
			add(e.Transit.ClientCertSecretRef)
			if a := e.Transit.Auth; a != nil {
				if a.Token != nil {
					add(&a.Token.SecretRef)
				}
				if a.Kubernetes != nil {
					add(a.Kubernetes.ServiceAccountTokenSecretRef)
				}
				if a.JWT != nil {
					add(a.JWT.ServiceAccountTokenSecretRef)
				}
			}
		}
	}
	return out
}

// KeyringGCPCredentialsPath is where an entry's GCP service-account
// JSON is mounted — PER ENTRY, so same-type HA pairs cannot collide;
// shared with the StatefulSet volume wiring.
func KeyringGCPCredentialsPath(name string) string {
	return "/nomad/keyring-gcp/" + name + "/credentials.json"
}

// keyringTLSPath is the mount directory for a transit entry's TLS
// material; shared with the StatefulSet volume wiring.
func keyringTLSPath(name string) string { return "/nomad/keyring-tls/" + name }

// KeyringTLSPath exposes the mount path to the StatefulSet phase.
func KeyringTLSPath(name string) string { return keyringTLSPath(name) }

func kvs(pairs ...string) []hcl.KeyringArg {
	out := []hcl.KeyringArg{}
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] != "" {
			out = append(out, hcl.KeyringArg{Key: pairs[i], Value: pairs[i+1]})
		}
	}
	return out
}

func storedName(sk storedKeyring) string {
	if sk.Entry == nil {
		return "aead"
	}
	return sk.Entry.Name
}

func storedHash(sk storedKeyring) string {
	raw, _ := json.Marshal(sk)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

func storedEqual(a, b []storedKeyring) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if storedHash(a[i]) != storedHash(b[i]) {
			return false
		}
	}
	return true
}

// absorbSpecChanges starts (or extends) a migration when the spec
// diverges from the active set. Demoted entries retire WITH their
// credentials; a migration off the implicit default retires an
// explicit aead block, and a disable activates one — permanently
// (keys wrapped under the explicit block are not loadable by the
// implicit default).
func (p *KeyringPhase) absorbSpecChanges(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, state *keyringState, cm *corev1.ConfigMap, desired []storedKeyring) PhaseResult {
	disableSteady := len(desired) == 0 && len(state.Active) == 1 && state.Active[0].Entry == nil
	if storedEqual(state.Active, desired) || disableSteady {
		return OK()
	}
	demoted := storedMinus(state.Active, desired)
	if len(state.Active) == 0 {
		demoted = append(demoted, storedKeyring{})
	}
	active := desired
	if len(desired) == 0 {
		active = []storedKeyring{{}}
		demoted = storedMinus(state.Active, nil)
	}
	state.Active = active
	state.Retiring = mergeRetiring(state.Retiring, demoted)
	state.Phase = keyringPhaseIntroducing
	if err := p.saveState(ctx, cm, state); err != nil {
		return Error(err, "Failed to persist keyring state")
	}
	if p.Recorder != nil {
		p.Recorder.Event(cluster, corev1.EventTypeNormal, "KeyringMigrationStarted",
			fmt.Sprintf("Migrating keyring set to [%s]", storedNames(state.Active)))
	}
	return OK()
}

// probeSteadyState verifies a Ready keyring is OPERATIONAL: config
// delivery is not initialization — a live cluster once reported Ready
// while every server failed keyring init (unreachable KMS CA). Only
// Nomad's own keyring list proves the wrappers work.
func (p *KeyringPhase) probeSteadyState(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, state *keyringState, cm *corev1.ConfigMap) {
	if !hasExternalEntries(state) || !p.statefulSetFullyRolled(ctx, cluster) {
		return
	}
	token, terr := getManagementToken(ctx, p.Client, cluster)
	if terr != nil {
		return
	}
	client, cerr := p.keyringClient(cluster, token)
	if cerr != nil {
		return
	}
	keys, kerr := client.KeyringList(ctx, token)
	if kerr == nil && len(keys) > 0 {
		return
	}
	p.probeDegraded = true
	msg := "Nomad keyring reports no keys — keyring not initialized"
	if kerr != nil {
		msg = fmt.Sprintf("Nomad keyring unreadable: %v", kerr)
	}
	p.surfaceDegraded(ctx, cluster, state, cm, "KeyringNotInitialized", msg)
	p.RevisitAfter = 30 * time.Second
}

// surfaceDegraded emits a Warning event when the degraded cause
// CHANGES (state-tracked — a 15s revisit loop must not spam events)
// and always logs it.
func (p *KeyringPhase) surfaceDegraded(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, state *keyringState, cm *corev1.ConfigMap, reason, msg string) {
	p.Log.Info("keyring degraded", "reason", reason, "message", msg)
	sig := reason + ": " + msg
	if state.LastDegraded == sig {
		return
	}
	state.LastDegraded = sig
	_ = p.saveState(ctx, cm, state)
	if p.Recorder != nil {
		p.Recorder.Event(cluster, corev1.EventTypeWarning, reason, msg)
	}
}

func hasExternalEntries(state *keyringState) bool {
	for _, sk := range state.Active {
		if sk.Entry != nil {
			return true
		}
	}
	return false
}

// storedMinus returns entries of a not present (by hash) in b.
func storedMinus(a, b []storedKeyring) []storedKeyring {
	inB := map[string]bool{}
	for _, x := range b {
		inB[storedHash(x)] = true
	}
	var out []storedKeyring
	for _, x := range a {
		if !inB[storedHash(x)] {
			out = append(out, x)
		}
	}
	return out
}

// mergeRetiring merges new demotions into the retiring set, deduped by
// name (a re-migration mid-flight keeps the earliest wrapper present).
func mergeRetiring(existing, add []storedKeyring) []storedKeyring {
	seen := map[string]bool{}
	var out []storedKeyring
	for _, x := range append(existing, add...) {
		if seen[storedName(x)] {
			continue
		}
		seen[storedName(x)] = true
		out = append(out, x)
	}
	return out
}

func storedNames(stored []storedKeyring) string {
	if len(stored) == 0 {
		return "aead"
	}
	names := ""
	for i, sk := range stored {
		if i > 0 {
			names += ", "
		}
		names += storedName(sk)
	}
	return names
}

// statefulSetFullyRolled mirrors the certificate phase's gate.
func (p *KeyringPhase) statefulSetFullyRolled(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) bool {
	return statefulSetFullyRolled(ctx, p.Client, cluster)
}
