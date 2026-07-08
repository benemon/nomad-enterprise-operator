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
	"fmt"
	"strings"
	"testing"
	"time"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad/mocks"
	mock2 "github.com/stretchr/testify/mock"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// keyringFixture builds a cluster with a rolled StatefulSet and a
// rendered config Secret whose content tracks whatever the phase renders —
// simulating the ConfigMap/StatefulSet phases having delivered it.
func keyringFixture(t *testing.T, mock *mocks.MockNomadAPI) (*KeyringPhase, *nomadv1alpha1.NomadCluster, *record.FakeRecorder, *[]*nomad.RootKey) {
	t.Helper()
	// One steerable KeyringList expectation for the whole test: the
	// steady-state probe and the rotating-phase cleanup both list keys,
	// and a fixed .Once() chain cannot serve both. Tests mutate the
	// backing slice to steer responses.
	keys := &[]*nomad.RootKey{{KeyID: "k1", State: "active"}}
	mock.EXPECT().KeyringList(mock2.Anything, mock2.Anything).
		RunAndReturn(func(context.Context, string) ([]*nomad.RootKey, error) {
			return *keys, nil
		}).Maybe()
	cluster := newTestCluster("kr-ns", "kr")
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "kr", Namespace: "kr-ns"},
		Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To(int32(1))},
		Status: appsv1.StatefulSetStatus{
			UpdatedReplicas: 1, ReadyReplicas: 1,
			CurrentRevision: "r1", UpdateRevision: "r1",
		},
	}
	recorder := record.NewFakeRecorder(20)
	phase := &KeyringPhase{PhaseContext: &PhaseContext{
		Client: fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(sts,
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "vt", Namespace: "kr-ns"},
				Data:       map[string][]byte{"VAULT_TOKEN": []byte("hvs.static")},
			}).Build(),
		Scheme:   scheme.Scheme,
		Log:      zap.New(zap.UseDevMode(true)),
		Recorder: recorder,
		NomadClientFactory: func(cfg nomad.ClientConfig) (nomad.NomadAPI, error) {
			// The rotate/list/delete client must target the internal
			// Service — BuildClientConfig leaves the address to callers,
			// and defaulting to localhost was a real bug.
			if !strings.Contains(cfg.Address, "kr-internal.kr-ns") {
				t.Fatalf("keyring client address = %q, want the internal Service", cfg.Address)
			}
			return mock, nil
		},
	}}
	return phase, cluster, recorder, keys
}

// deliverConfig writes the rendered config Secret the way the config
// phase would, from the phase's current render set.
func deliverConfig(t *testing.T, p *KeyringPhase) {
	t.Helper()
	content := ""
	for _, b := range p.Keyrings {
		content += fmt.Sprintf("keyring %q {\n", b.Type)
		if b.Name != "" {
			content += fmt.Sprintf("  name   = %q\n", b.Name)
		}
		content += fmt.Sprintf("  active = %v\n}\n", b.Active)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "kr-config", Namespace: "kr-ns"}}
	existing := &corev1.Secret{}
	err := p.Client.Get(context.Background(), types.NamespacedName{Name: "kr-config", Namespace: "kr-ns"}, existing)
	if err != nil {
		secret.Data = map[string][]byte{"server.hcl": []byte(content)}
		if cerr := p.Client.Create(context.Background(), secret); cerr != nil {
			t.Fatal(cerr)
		}
		return
	}
	existing.Data = map[string][]byte{"server.hcl": []byte(content)}
	if uerr := p.Client.Update(context.Background(), existing); uerr != nil {
		t.Fatal(uerr)
	}
}

func transitSpec(name string) nomadv1alpha1.KeyringEntry {
	return nomadv1alpha1.KeyringEntry{
		Name: name,
		Transit: &nomadv1alpha1.TransitKeyring{
			Address: "https://vault:8200", KeyName: "nomad-keyring", MountPath: "transit/",
			Auth: &nomadv1alpha1.TransitAuth{
				Method: "token",
				Token:  &nomadv1alpha1.TransitAuthToken{SecretRef: corev1.LocalObjectReference{Name: "vt"}},
			},
		},
	}
}

// TestKeyringBornWithKMS: a cluster created WITH keyrings starts Ready
// — no aead keys ever exist, so no migration runs and no Nomad API is
// touched.
func TestKeyringBornWithKMS(t *testing.T) {
	mock := mocks.NewMockNomadAPI(t) // fails on ANY call
	phase, cluster, recorder, _ := keyringFixture(t, mock)
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{transitSpec("primary")}

	if result := phase.Execute(context.Background(), cluster); result.Error != nil || result.Requeue {
		t.Fatalf("Execute() = %+v", result)
	}
	if got := cluster.Status.Keyring; got == nil || got.Phase != "Ready" ||
		len(got.Active) != 1 || got.Active[0] != "primary" || len(got.Retiring) != 0 {
		t.Fatalf("status = %+v, want Ready/[primary]", cluster.Status.Keyring)
	}
	if len(phase.Keyrings) != 1 || !phase.Keyrings[0].Active {
		t.Fatalf("render = %+v, want one active block", phase.Keyrings)
	}
	if len(recorder.Events) != 0 {
		t.Fatalf("no events expected, got %d", len(recorder.Events))
	}
}

// TestKeyringEnableLifecycle drives aead -> transit end to end:
// introduce (union render incl. explicit inactive aead), rotate once
// rolled+delivered, remove inactive keys, retire (aead dropped), Ready.
func TestKeyringEnableLifecycle(t *testing.T) {
	mock := mocks.NewMockNomadAPI(t)
	phase, cluster, recorder, keys := keyringFixture(t, mock)

	// Reconcile 1: no keyrings — establishes the implicit-aead state.
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if cluster.Status.Keyring.Phase != "Ready" || cluster.Status.Keyring.Active[0] != "aead" {
		t.Fatalf("baseline status = %+v", cluster.Status.Keyring)
	}
	deliverConfig(t, phase)

	// Reconcile 2: spec adds transit — migration starts. STS is rolled
	// but the delivered config predates the union, so no rotation yet.
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{transitSpec("primary")}
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if cluster.Status.Keyring.Phase != "Introducing" {
		t.Fatalf("phase = %s, want Introducing", cluster.Status.Keyring.Phase)
	}
	if len(phase.Keyrings) != 2 {
		t.Fatalf("union render expected (transit + aead), got %+v", phase.Keyrings)
	}
	var sawInactiveAead bool
	for _, b := range phase.Keyrings {
		if b.Type == "aead" && !b.Active {
			sawInactiveAead = true
		}
	}
	if !sawInactiveAead {
		t.Fatal("explicit inactive aead block must be rendered during introduce")
	}

	// Reconcile 3: config delivered -> rotation fires, phase Rotating.
	deliverConfig(t, phase)
	mock.EXPECT().KeyringRotateFull(context.Background(), "").Return(nil).Once()
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if cluster.Status.Keyring.Phase != "Rotating" {
		t.Fatalf("phase = %s, want Rotating", cluster.Status.Keyring.Phase)
	}

	// Reconcile 3b: a rekeying key means re-encryption is in flight —
	// wait, and crucially do NOT attempt deletion (Nomad refuses).
	*keys = []*nomad.RootKey{
		{KeyID: "old", State: "rekeying"}, {KeyID: "new", State: "active"},
	}
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if cluster.Status.Keyring.Phase != "Rotating" {
		t.Fatalf("phase = %s, want Rotating while rekeying", cluster.Status.Keyring.Phase)
	}

	// Reconcile 4: one inactive key -> deleted; not done this pass.
	*keys = []*nomad.RootKey{
		{KeyID: "old", State: "inactive"}, {KeyID: "new", State: "active"},
	}
	mock.EXPECT().KeyringDelete(context.Background(), "", "old").Return(nil).Once()
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if cluster.Status.Keyring.Phase != "Rotating" {
		t.Fatalf("phase = %s, want Rotating until list is clean", cluster.Status.Keyring.Phase)
	}

	// Reconcile 5: clean list -> Retiring; aead leaves the render.
	*keys = []*nomad.RootKey{
		{KeyID: "new", State: "active"},
	}
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if cluster.Status.Keyring.Phase != "Retiring" {
		t.Fatalf("phase = %s, want Retiring", cluster.Status.Keyring.Phase)
	}
	if len(phase.Keyrings) != 1 || phase.Keyrings[0].Type != "transit" {
		t.Fatalf("retire render = %+v, want transit only", phase.Keyrings)
	}

	// Reconcile 6: retire render delivered -> Ready.
	deliverConfig(t, phase)
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if cluster.Status.Keyring.Phase != "Ready" || len(cluster.Status.Keyring.Retiring) != 0 {
		t.Fatalf("final status = %+v", cluster.Status.Keyring)
	}

	var started, completed bool
	for len(recorder.Events) > 0 {
		e := <-recorder.Events
		if strings.Contains(e, "KeyringMigrationStarted") {
			started = true
		}
		if strings.Contains(e, "KeyringMigrationCompleted") {
			completed = true
		}
	}
	if !started || !completed {
		t.Fatalf("migration events missing: started=%v completed=%v", started, completed)
	}
}

// TestKeyringDisableLifecycle drives transit -> aead: the transient
// explicit aead block becomes active, transit retires, and the final
// state collapses to the implicit default (no blocks rendered).
func TestKeyringDisableLifecycle(t *testing.T) {
	mock := mocks.NewMockNomadAPI(t)
	phase, cluster, _, keys := keyringFixture(t, mock)

	// Born with transit.
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{transitSpec("primary")}
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	deliverConfig(t, phase)

	// Disable.
	cluster.Spec.Server.Keyrings = nil
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if cluster.Status.Keyring.Phase != "Introducing" {
		t.Fatalf("phase = %s", cluster.Status.Keyring.Phase)
	}
	var aeadActive, transitInactive bool
	for _, b := range phase.Keyrings {
		if b.Type == "aead" && b.Active {
			aeadActive = true
		}
		if b.Type == "transit" && !b.Active {
			transitInactive = true
		}
	}
	if !aeadActive || !transitInactive {
		t.Fatalf("disable render wrong: %+v", phase.Keyrings)
	}
	// The retiring transit entry must keep its pod wiring (env,
	// volumes, checksum) until its keys are removed — the run-26
	// deadlock: rekey needs VAULT_TOKEN to unwrap the old key, but the
	// spec no longer carries the entry.
	if len(phase.KeyringEntries) != 1 || phase.KeyringEntries[0].Transit == nil {
		t.Fatalf("KeyringEntries = %+v, want the retiring transit entry", phase.KeyringEntries)
	}

	deliverConfig(t, phase)
	mock.EXPECT().KeyringRotateFull(context.Background(), "").Return(nil).Once()
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	*keys = []*nomad.RootKey{
		{KeyID: "k", State: "active"},
	}
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	// The explicit aead block REMAINS (its wrapped keys are not
	// loadable by the implicit default — no collapse).
	if len(phase.Keyrings) != 1 || phase.Keyrings[0].Type != "aead" || !phase.Keyrings[0].Active {
		t.Fatalf("expected single active aead block after disable, got %+v", phase.Keyrings)
	}
	deliverConfig(t, phase)
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if got := cluster.Status.Keyring; got.Phase != "Ready" || got.Active[0] != "aead" {
		t.Fatalf("final = %+v", got)
	}
}

// TestKeyringMultiTransitPrefixRequired: multiple transit entries
// (same or different Vaults) need distinct non-empty keyIDPrefix for
// Nomad's wrapped-key disambiguation.
func TestKeyringMultiTransitPrefixRequired(t *testing.T) {
	mock := mocks.NewMockNomadAPI(t)
	phase, cluster, _, _ := keyringFixture(t, mock)
	e1 := transitSpec("a")
	e2 := transitSpec("b")
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{e1, e2}

	result := phase.Execute(context.Background(), cluster)
	if result.Error == nil || result.Reason != "KeyringInvalid" {
		t.Fatalf("want KeyringInvalid without prefixes, got %+v", result)
	}

	e1.Transit.KeyIDPrefix, e2.Transit.KeyIDPrefix = "a-", "b-"
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{e1, e2}
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatalf("distinct prefixes must be accepted, got %+v", result)
	}
	if got := cluster.Status.Keyring; len(got.Active) != 2 {
		t.Fatalf("status active = %+v, want both entries", got)
	}
}

// TestKeyringRotationDefersWhenNomadDown: a rotation failure requeues
// with a legible reason and keeps the union render (nothing is lost).
func TestKeyringRotationDefersWhenNomadDown(t *testing.T) {
	mock := mocks.NewMockNomadAPI(t)
	phase, cluster, recorder, _ := keyringFixture(t, mock)

	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	deliverConfig(t, phase)
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{transitSpec("primary")}
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	deliverConfig(t, phase)

	mock.EXPECT().KeyringRotateFull(context.Background(), "").Return(fmt.Errorf("connection refused")).Once()
	result := phase.Execute(context.Background(), cluster)
	// Deferral must NOT stop the phase chain: a Requeue here freezes
	// the config Secret, deadlocking exactly when a rendered token has
	// gone stale (neo-0m0, observed live). OK + RevisitAfter instead.
	if result.Error != nil || result.Requeue {
		t.Fatalf("rotation deferral must keep the chain flowing, got %+v", result)
	}
	if phase.RevisitAfter != 15*time.Second {
		t.Fatalf("RevisitAfter = %v, want 15s", phase.RevisitAfter)
	}
	if len(phase.Keyrings) != 2 {
		t.Fatalf("union render must survive the deferral: %+v", phase.Keyrings)
	}
	if cluster.Status.Keyring.Phase != "Introducing" {
		t.Fatalf("phase = %s, want Introducing", cluster.Status.Keyring.Phase)
	}
	var sawPending bool
	for {
		select {
		case e := <-recorder.Events:
			if strings.Contains(e, "KeyringRotationPending") {
				sawPending = true
			}
			continue
		default:
		}
		break
	}
	if !sawPending {
		t.Fatal("degraded cause must surface as a KeyringRotationPending event")
	}
}

// TestKeyringSpecChangeAbsorbedDespiteTokenFailure pins the neo-vxh
// fix: a stale entry whose credential resolution fails must never
// block the state update that replaces it — the failing credential
// gated its own cure in a live migration.
func TestKeyringSpecChangeAbsorbedDespiteTokenFailure(t *testing.T) {
	mock := mocks.NewMockNomadAPI(t)
	phase, cluster, recorder, _ := keyringFixture(t, mock)

	// Born with an entry whose token Secret does NOT exist.
	broken := transitSpec("primary")
	broken.Transit.Auth.Token.SecretRef.Name = "missing-secret"
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{broken}
	if result := phase.Execute(context.Background(), cluster); result.Error != nil || result.Requeue {
		t.Fatalf("credential failure must not stop the chain, got %+v", result)
	}
	if phase.RevisitAfter != 30*time.Second {
		t.Fatalf("RevisitAfter = %v, want 30s", phase.RevisitAfter)
	}

	// Same-name spec change (the fix: point at the good Secret) must be
	// absorbed in the very next reconcile, while the old entry still
	// fails to resolve.
	fixed := transitSpec("primary")
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{fixed}
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	var tokenSeen bool
	for _, b := range phase.Keyrings {
		if b.Name == "primary" {
			for _, a := range b.Args {
				if a.Key == "token" && a.Value == "hvs.static" {
					tokenSeen = true
				}
			}
		}
	}
	if !tokenSeen {
		t.Fatal("updated entry must render with the good Secret's token — spec change was not absorbed")
	}
	drainEvents(recorder)
}

// TestKeyringSteadyProbeDegraded pins the neo-tkx fix: a Ready state
// machine whose Nomad-side keyring holds no keys (init failed on the
// servers) must report Degraded, not Ready.
func TestKeyringSteadyProbeDegraded(t *testing.T) {
	mock := mocks.NewMockNomadAPI(t)
	phase, cluster, recorder, keys := keyringFixture(t, mock)

	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{transitSpec("primary")}
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if cluster.Status.Keyring.Phase != "Ready" {
		t.Fatalf("born-with-KMS baseline = %s, want Ready", cluster.Status.Keyring.Phase)
	}

	// Nomad reports an uninitialized keyring: Ready must degrade.
	*keys = nil
	if result := phase.Execute(context.Background(), cluster); result.Error != nil || result.Requeue {
		t.Fatalf("probe failure must not stop the chain, got %+v", result)
	}
	if cluster.Status.Keyring.Phase != "Degraded" {
		t.Fatalf("phase = %s, want Degraded", cluster.Status.Keyring.Phase)
	}
	if phase.RevisitAfter == 0 {
		t.Fatal("degraded probe must schedule a revisit")
	}
	var sawEvent bool
	for {
		select {
		case e := <-recorder.Events:
			if strings.Contains(e, "KeyringNotInitialized") {
				sawEvent = true
			}
			continue
		default:
		}
		break
	}
	if !sawEvent {
		t.Fatal("KeyringNotInitialized must surface as a Warning event")
	}

	// Keyring recovers: Ready restored.
	*keys = []*nomad.RootKey{{KeyID: "k2", State: "active"}}
	phase.probeDegraded = false
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if cluster.Status.Keyring.Phase != "Ready" {
		t.Fatalf("phase = %s, want Ready after recovery", cluster.Status.Keyring.Phase)
	}
}

// TestKeyringSameNameMutationReplacesInPlace pins the neo-h6y fix: a
// same-name entry edit (credential fix, same wrapper) must replace the
// entry in place — never demote it into Retiring, whose union render
// would carry two same-name blocks (the duplicate render left a live
// cluster Ready with a root key Nomad could not load).
func TestKeyringSameNameMutationReplacesInPlace(t *testing.T) {
	mock := mocks.NewMockNomadAPI(t)
	phase, cluster, recorder, _ := keyringFixture(t, mock)
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{transitSpec("primary")}

	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	deliverConfig(t, phase)

	// Same name, new credential Secret.
	vt2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "vt2", Namespace: "kr-ns"},
		Data:       map[string][]byte{"VAULT_TOKEN": []byte("hvs.replaced")},
	}
	if err := phase.Client.Create(context.Background(), vt2); err != nil {
		t.Fatal(err)
	}
	mutated := transitSpec("primary")
	mutated.Transit.Auth.Token.SecretRef.Name = "vt2"
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{mutated}

	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if got := cluster.Status.Keyring; got.Phase != "Ready" ||
		len(got.Active) != 1 || got.Active[0] != "primary" || len(got.Retiring) != 0 {
		t.Fatalf("status = %+v, want Ready/[primary] with nothing retiring", cluster.Status.Keyring)
	}
	if len(phase.Keyrings) != 1 {
		t.Fatalf("render = %+v, want exactly ONE block — duplicate same-name blocks are the neo-h6y incident", phase.Keyrings)
	}
	var tokenArg string
	for _, a := range phase.Keyrings[0].Args {
		if a.Key == "token" {
			tokenArg = a.Value
		}
	}
	if tokenArg != "hvs.replaced" {
		t.Fatalf("rendered token = %q, want the replacement credential", tokenArg)
	}
	var updated bool
	for len(recorder.Events) > 0 {
		e := <-recorder.Events
		if strings.Contains(e, "KeyringMigrationStarted") {
			t.Fatalf("in-place replace must not start a migration, got %q", e)
		}
		if strings.Contains(e, "KeyringEntryUpdated") {
			updated = true
		}
	}
	if !updated {
		t.Fatal("in-place replace must surface a KeyringEntryUpdated event")
	}
}

// TestKeyringSameNameMutationWithAddition: mutating an entry while
// adding another starts a migration for the ADDITION only — the
// same-name predecessor is replaced, not retired.
func TestKeyringSameNameMutationWithAddition(t *testing.T) {
	mock := mocks.NewMockNomadAPI(t)
	phase, cluster, _, _ := keyringFixture(t, mock)
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{transitSpec("primary")}

	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	deliverConfig(t, phase)

	mutated := transitSpec("primary")
	mutated.Transit.KeyIDPrefix = "a-"
	second := transitSpec("secondary")
	second.Transit.KeyIDPrefix = "b-"
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{mutated, second}

	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if cluster.Status.Keyring.Phase != "Introducing" {
		t.Fatalf("phase = %s, want Introducing for the added entry", cluster.Status.Keyring.Phase)
	}
	if len(cluster.Status.Keyring.Retiring) != 0 {
		t.Fatalf("retiring = %v, want empty — the same-name predecessor must be replaced, not retired",
			cluster.Status.Keyring.Retiring)
	}
	seen := map[string]int{}
	for _, b := range phase.Keyrings {
		seen[b.Name]++
	}
	if seen["primary"] != 1 || seen["secondary"] != 1 || len(phase.Keyrings) != 2 {
		t.Fatalf("render = %+v, want exactly one block per name", phase.Keyrings)
	}
}

func deleteKeyringStateCM(t *testing.T, p *KeyringPhase, cluster *nomadv1alpha1.NomadCluster) {
	t.Helper()
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name: keyringStateName(cluster), Namespace: cluster.Namespace}}
	if err := p.Client.Delete(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
}

// TestKeyringStateLossSteadyState pins the loadState re-seed semantics
// for the runbook's operator-state custody table (neo-7ph): deleting
// the state ConfigMap on a STEADY-STATE cluster is safe — the next
// reconcile re-seeds {Active: desired-from-spec, Phase: Ready} and
// converges without starting a migration.
func TestKeyringStateLossSteadyState(t *testing.T) {
	mock := mocks.NewMockNomadAPI(t)
	phase, cluster, recorder, _ := keyringFixture(t, mock)
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{transitSpec("primary")}

	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	deliverConfig(t, phase)
	deleteKeyringStateCM(t, phase, cluster)

	if result := phase.Execute(context.Background(), cluster); result.Error != nil || result.Requeue {
		t.Fatalf("Execute() after state loss = %+v", result)
	}
	if got := cluster.Status.Keyring; got.Phase != "Ready" ||
		len(got.Active) != 1 || got.Active[0] != "primary" || len(got.Retiring) != 0 {
		t.Fatalf("re-seeded status = %+v, want Ready/[primary]", cluster.Status.Keyring)
	}
	for len(recorder.Events) > 0 {
		if e := <-recorder.Events; strings.Contains(e, "KeyringMigration") {
			t.Fatalf("steady-state re-seed must not start a migration, got %q", e)
		}
	}
}

// TestKeyringStateLossMidMigration documents the CURRENT mid-migration
// loss semantics truthfully (neo-7ph): deleting the state ConfigMap
// while Retiring is non-empty re-seeds straight to Ready and FORGETS
// the retiring entries — their blocks leave the render immediately, so
// keys wrapped only by them become undecryptable. The runbook's
// Scenario 5 warns operators never to delete the state CM while
// status.keyring.phase != Ready; this test makes the semantics visible,
// it does not bless them.
func TestKeyringStateLossMidMigration(t *testing.T) {
	mock := mocks.NewMockNomadAPI(t)
	phase, cluster, _, _ := keyringFixture(t, mock)

	// Establish the implicit-aead baseline, then start a migration to
	// transit: Introducing, with the demoted aead entry in Retiring.
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	deliverConfig(t, phase)
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{transitSpec("primary")}
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if cluster.Status.Keyring.Phase != "Introducing" || len(cluster.Status.Keyring.Retiring) == 0 {
		t.Fatalf("mid-migration baseline = %+v, want Introducing with retiring entries", cluster.Status.Keyring)
	}

	deleteKeyringStateCM(t, phase, cluster)
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if got := cluster.Status.Keyring; got.Phase != "Ready" ||
		len(got.Active) != 1 || got.Active[0] != "primary" {
		t.Fatalf("re-seeded status = %+v, want Ready/[primary]", cluster.Status.Keyring)
	}
	if len(cluster.Status.Keyring.Retiring) != 0 {
		t.Fatalf("retiring = %v — if re-seed ever learns to preserve retiring entries, update runbook Scenario 5",
			cluster.Status.Keyring.Retiring)
	}
	for _, b := range phase.Keyrings {
		if b.Type == "aead" {
			t.Fatalf("retiring aead block still rendered after re-seed — semantics changed, update runbook Scenario 5")
		}
	}
}
