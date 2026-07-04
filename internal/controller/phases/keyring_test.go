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

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad/mocks"
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
// rendered ConfigMap whose content tracks whatever the phase renders —
// simulating the ConfigMap/StatefulSet phases having delivered it.
func keyringFixture(t *testing.T, mock nomad.NomadAPI) (*KeyringPhase, *nomadv1alpha1.NomadCluster, *record.FakeRecorder) {
	t.Helper()
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
		Client:   fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(sts).Build(),
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
	return phase, cluster, recorder
}

// deliverConfig writes the rendered ConfigMap the way the ConfigMap
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
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "kr-config", Namespace: "kr-ns"}}
	existing := &corev1.ConfigMap{}
	err := p.Client.Get(context.Background(), types.NamespacedName{Name: "kr-config", Namespace: "kr-ns"}, existing)
	if err != nil {
		cm.Data = map[string]string{"server.hcl": content}
		if cerr := p.Client.Create(context.Background(), cm); cerr != nil {
			t.Fatal(cerr)
		}
		return
	}
	existing.Data = map[string]string{"server.hcl": content}
	if uerr := p.Client.Update(context.Background(), existing); uerr != nil {
		t.Fatal(uerr)
	}
}

func transitSpec(name string) nomadv1alpha1.KeyringEntry {
	return nomadv1alpha1.KeyringEntry{
		Name: name,
		Transit: &nomadv1alpha1.TransitKeyring{
			Address: "https://vault:8200", KeyName: "nomad-keyring", MountPath: "transit/",
		},
	}
}

// TestKeyringBornWithKMS: a cluster created WITH keyrings starts Ready
// — no aead keys ever exist, so no migration runs and no Nomad API is
// touched.
func TestKeyringBornWithKMS(t *testing.T) {
	mock := mocks.NewMockNomadAPI(t) // fails on ANY call
	phase, cluster, recorder := keyringFixture(t, mock)
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
	phase, cluster, recorder := keyringFixture(t, mock)

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
	mock.EXPECT().KeyringList(context.Background(), "").Return([]*nomad.RootKey{
		{KeyID: "old", State: "rekeying"}, {KeyID: "new", State: "active"},
	}, nil).Once()
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if cluster.Status.Keyring.Phase != "Rotating" {
		t.Fatalf("phase = %s, want Rotating while rekeying", cluster.Status.Keyring.Phase)
	}

	// Reconcile 4: one inactive key -> deleted; not done this pass.
	mock.EXPECT().KeyringList(context.Background(), "").Return([]*nomad.RootKey{
		{KeyID: "old", State: "inactive"}, {KeyID: "new", State: "active"},
	}, nil).Once()
	mock.EXPECT().KeyringDelete(context.Background(), "", "old").Return(nil).Once()
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatal(result.Error)
	}
	if cluster.Status.Keyring.Phase != "Rotating" {
		t.Fatalf("phase = %s, want Rotating until list is clean", cluster.Status.Keyring.Phase)
	}

	// Reconcile 5: clean list -> Retiring; aead leaves the render.
	mock.EXPECT().KeyringList(context.Background(), "").Return([]*nomad.RootKey{
		{KeyID: "new", State: "active"},
	}, nil).Once()
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
	phase, cluster, _ := keyringFixture(t, mock)

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
	mock.EXPECT().KeyringList(context.Background(), "").Return([]*nomad.RootKey{
		{KeyID: "k", State: "active"},
	}, nil).Once()
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

// TestKeyringMultiTransitTokenRejected: only one transit entry may
// carry credentialsSecretRef (VAULT_TOKEN is a single env var).
func TestKeyringMultiTransitTokenRejected(t *testing.T) {
	mock := mocks.NewMockNomadAPI(t)
	phase, cluster, _ := keyringFixture(t, mock)
	e1 := transitSpec("a")
	e1.Transit.CredentialsSecretRef = &corev1.LocalObjectReference{Name: "t1"}
	e2 := transitSpec("b")
	e2.Transit.CredentialsSecretRef = &corev1.LocalObjectReference{Name: "t2"}
	cluster.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{e1, e2}

	result := phase.Execute(context.Background(), cluster)
	if result.Error == nil || result.Reason != "KeyringInvalid" {
		t.Fatalf("want KeyringInvalid error, got %+v", result)
	}
}

// TestKeyringRotationDefersWhenNomadDown: a rotation failure requeues
// with a legible reason and keeps the union render (nothing is lost).
func TestKeyringRotationDefersWhenNomadDown(t *testing.T) {
	mock := mocks.NewMockNomadAPI(t)
	phase, cluster, _ := keyringFixture(t, mock)

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
	if !result.Requeue || result.Reason != "KeyringRotationPending" {
		t.Fatalf("want KeyringRotationPending requeue, got %+v", result)
	}
	if len(phase.Keyrings) != 2 {
		t.Fatalf("union render must survive the deferral: %+v", phase.Keyrings)
	}
}
