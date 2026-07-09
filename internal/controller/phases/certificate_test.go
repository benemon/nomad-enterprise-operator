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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	tlspkg "github.com/hashicorp/nomad-enterprise-operator/pkg/tls"
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

// testCAWithExpiry builds a self-signed CA whose NotAfter is at the
// given offset from now, so the C5 renewal-window logic can be driven
// without waiting on the wall clock.
func testCAWithExpiry(t *testing.T, expiresIn time.Duration) *tlspkg.CABundle {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "C5 Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(expiresIn),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal CA key: %v", err)
	}
	return &tlspkg.CABundle{
		CACertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		CAKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

// drainEvents empties a FakeRecorder's channel.
func drainEvents(recorder *record.FakeRecorder) []string {
	var out []string
	for {
		select {
		case e := <-recorder.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

// User CAs get escalating CARenewalRequired Warnings (30d/14d, then
// daily), bucket-debounced across restarts, reset on CA replacement.
// Operator CAs emit rotation Events instead, never this warning.
func TestCARenewalWarningEscalation(t *testing.T) {
	newPhase := func() (*CertificatePhase, *record.FakeRecorder) {
		recorder := record.NewFakeRecorder(10)
		return &CertificatePhase{PhaseContext: &PhaseContext{
			Log:      zap.New(zap.UseDevMode(true)),
			Recorder: recorder,
		}}, recorder
	}

	t.Run("bucket mapping and daily cadence", func(t *testing.T) {
		notAfter := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
		cases := []struct {
			daysLeft float64
			want     string
		}{
			{45, ""},
			{29, "30d"},
			{15, "30d"},
			{13, "14d"},
			{6, "7d:2026-07-26"},
			{-2, "7d:2026-08-03"}, // past expiry: daily reminders continue
		}
		for _, tc := range cases {
			now := notAfter.Add(-time.Duration(tc.daysLeft * 24 * float64(time.Hour)))
			if got := renewalWarningBucket(notAfter, now); got != tc.want {
				t.Errorf("bucket(%.0f days left) = %q, want %q", tc.daysLeft, got, tc.want)
			}
		}
		// Same day inside the final week → same bucket (no re-emission);
		// next day → new bucket (daily cadence).
		day1 := notAfter.Add(-3 * 24 * time.Hour)
		if renewalWarningBucket(notAfter, day1) != renewalWarningBucket(notAfter, day1.Add(2*time.Hour)) {
			t.Error("same-day buckets must match")
		}
		if renewalWarningBucket(notAfter, day1) == renewalWarningBucket(notAfter, day1.Add(24*time.Hour)) {
			t.Error("next-day bucket must differ (daily cadence)")
		}
	})

	t.Run("threshold crossings emit once each for user CAs", func(t *testing.T) {
		phase, recorder := newPhase()
		cluster := newTestCluster("test-ns", "esc")

		// Far from expiry: silent.
		phase.updateCAStatus(cluster, "user-provided", testCAWithExpiry(t, tlspkg.CALifetime))
		if events := drainEvents(recorder); len(events) != 0 {
			t.Fatalf("no event expected far from expiry, got %v", events)
		}

		// 20 days out: the 30d bucket fires exactly once.
		ca20 := testCAWithExpiry(t, 20*24*time.Hour)
		phase.updateCAStatus(cluster, "user-provided", ca20)
		if events := drainEvents(recorder); len(events) != 1 || !strings.Contains(events[0], "CARenewalRequired") {
			t.Fatalf("20d out: events = %v, want one CARenewalRequired", events)
		}
		if got := cluster.Status.CertificateAuthority.RenewalWarningThreshold; got != "30d" {
			t.Fatalf("marker = %q, want 30d", got)
		}
		phase.updateCAStatus(cluster, "user-provided", ca20)
		if events := drainEvents(recorder); len(events) != 0 {
			t.Fatalf("debounce failed within the 30d bucket: %v", events)
		}

		// Same CA aged to 10 days out (new cert object, same identity
		// simulated by carrying the marker): 14d bucket fires once.
		ca10 := testCAWithExpiry(t, 10*24*time.Hour)
		cluster.Status.CertificateAuthority.ExpiryTime = "" // force fresh struct path
		phase.updateCAStatus(cluster, "user-provided", ca10)
		if events := drainEvents(recorder); len(events) != 1 {
			t.Fatalf("10d out: events = %v, want one", events)
		}
		if got := cluster.Status.CertificateAuthority.RenewalWarningThreshold; got != "14d" {
			t.Fatalf("marker = %q, want 14d", got)
		}

		// Inside the final week: date-stamped bucket.
		ca3 := testCAWithExpiry(t, 3*24*time.Hour)
		cluster.Status.CertificateAuthority.ExpiryTime = ""
		phase.updateCAStatus(cluster, "user-provided", ca3)
		if events := drainEvents(recorder); len(events) != 1 {
			t.Fatalf("3d out: events = %v, want one", events)
		}
		if got := cluster.Status.CertificateAuthority.RenewalWarningThreshold; !strings.HasPrefix(got, "7d:") {
			t.Fatalf("marker = %q, want 7d:<date>", got)
		}
		// Same day, same CA: silent.
		phase.updateCAStatus(cluster, "user-provided", ca3)
		if events := drainEvents(recorder); len(events) != 0 {
			t.Fatalf("same-day re-emission inside final week: %v", events)
		}

		// Replaced CA far from expiry: marker resets, silent.
		phase.updateCAStatus(cluster, "user-provided", testCAWithExpiry(t, tlspkg.CALifetime))
		if got := cluster.Status.CertificateAuthority.RenewalWarningThreshold; got != "" {
			t.Errorf("marker not reset after CA replacement: %q", got)
		}
		if events := drainEvents(recorder); len(events) != 0 {
			t.Errorf("unexpected events after replacement: %v", events)
		}
	})

	t.Run("operator-generated CAs never emit the warning", func(t *testing.T) {
		phase, recorder := newPhase()
		cluster := newTestCluster("test-ns", "opgen")
		phase.updateCAStatus(cluster, "operator-generated", testCAWithExpiry(t, 3*24*time.Hour))
		if events := drainEvents(recorder); len(events) != 0 {
			t.Fatalf("operator-generated CA emitted renewal warning: %v", events)
		}
	})
}

// rotationFixture builds the world mid-life: a cluster whose
// operator-generated CA is inside the renewal window, a fully-rolled
// StatefulSet (the phase A→B gate), and a TLS secret whose leaf was
// issued by that near-expiry CA.
func rotationFixture(t *testing.T, caExpiresIn time.Duration) (*CertificatePhase, *nomadv1alpha1.NomadCluster, *record.FakeRecorder) {
	t.Helper()
	cluster := newTestCluster("rot-ns", "rot")
	oldCA := testCAWithExpiry(t, caExpiresIn)

	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "rot-ca", Namespace: "rot-ns"},
		Data: map[string][]byte{
			"tls.crt": oldCA.CACertPEM,
			"tls.key": oldCA.CAKeyPEM,
		},
	}

	issued, err := tlspkg.IssueCertificate(oldCA, tlspkg.CertificateRequest{
		CommonName: "server.global.nomad",
		DNSNames:   (&CertificatePhase{PhaseContext: &PhaseContext{}}).serverDNSSANs(cluster),
		TTL:        tlspkg.ServerCertTTL,
		IsServer:   true,
	})
	if err != nil {
		t.Fatalf("IssueCertificate() fixture error = %v", err)
	}
	tlsSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "rot-tls", Namespace: "rot-ns"},
		Data: map[string][]byte{
			"ca.crt":  oldCA.CACertPEM,
			"tls.crt": append(issued.CertPEM, issued.CACertPEM...),
			"tls.key": issued.KeyPEM,
		},
	}

	rolledSTS := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "rot", Namespace: "rot-ns"},
		Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To(int32(1))},
		Status: appsv1.StatefulSetStatus{
			UpdatedReplicas: 1, ReadyReplicas: 1,
			CurrentRevision: "r1", UpdateRevision: "r1",
		},
	}

	recorder := record.NewFakeRecorder(10)
	phase := &CertificatePhase{PhaseContext: &PhaseContext{
		Client: fake.NewClientBuilder().WithScheme(scheme.Scheme).
			WithObjects(caSecret, tlsSecret, rolledSTS).Build(),
		Scheme:   scheme.Scheme,
		Log:      zap.New(zap.UseDevMode(true)),
		Recorder: recorder,
	}}
	return phase, cluster, recorder
}

func getSecret(t *testing.T, phase *CertificatePhase, name string) *corev1.Secret {
	t.Helper()
	s := &corev1.Secret{}
	if err := phase.Client.Get(context.Background(), types.NamespacedName{Name: name, Namespace: "rot-ns"}, s); err != nil {
		t.Fatalf("Get secret %s: %v", name, err)
	}
	return s
}

// TestCARotationLifecycle covers neo-4s4's state machine end to end
// against a fake client: introduce (dual trust), cutover (promote +
// issuer-forced leaf reissue), passive retire, and steady-state
// idempotence — with rotation state derived purely from Secret keys.
func TestCARotationLifecycle(t *testing.T) {
	phase, cluster, recorder := rotationFixture(t, 10*24*time.Hour) // inside the 30d window

	oldCASecret := getSecret(t, phase, "rot-ca")
	oldCAPEM := append([]byte{}, oldCASecret.Data["tls.crt"]...)
	oldCACert, _ := tlspkg.ParseCertificate(oldCAPEM)

	drain := func() []string {
		var out []string
		for len(recorder.Events) > 0 {
			out = append(out, <-recorder.Events)
		}
		return out
	}

	// --- Pass 1: Phase A — next CA introduced, union delivered. ---
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatalf("Execute() pass 1 error = %v", result.Error)
	}
	caSecret := getSecret(t, phase, "rot-ca")
	if _, ok := caSecret.Data["tls-next.crt"]; !ok {
		t.Fatal("phase A did not introduce tls-next.crt")
	}
	if !bytes.Equal(caSecret.Data["tls.crt"], oldCAPEM) {
		t.Fatal("phase A must not change the active CA")
	}
	tlsSecret := getSecret(t, phase, "rot-tls")
	if !bytes.Contains(tlsSecret.Data["ca.crt"], oldCAPEM) ||
		!bytes.Contains(tlsSecret.Data["ca.crt"], caSecret.Data["tls-next.crt"]) {
		t.Fatal("trust union after phase A must contain active AND next CA")
	}
	if !leafSignedBy(tlsSecret.Data["tls.crt"], oldCACert) {
		t.Fatal("phase A must not reissue the leaf")
	}
	if evs := drain(); len(evs) != 1 || !strings.Contains(evs[0], "CARotationStarted") {
		t.Fatalf("events after pass 1 = %v, want exactly CARotationStarted", evs)
	}

	// --- Pass 2: Phase B — rolled + trust delivered => promote + reissue. ---
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatalf("Execute() pass 2 error = %v", result.Error)
	}
	caSecret = getSecret(t, phase, "rot-ca")
	if _, ok := caSecret.Data["tls-next.crt"]; ok {
		t.Fatal("phase B must remove tls-next.*")
	}
	if !bytes.Equal(caSecret.Data["tls-previous.crt"], oldCAPEM) {
		t.Fatal("phase B must retain the old CA cert as tls-previous.crt")
	}
	if bytes.Equal(caSecret.Data["tls.crt"], oldCAPEM) {
		t.Fatal("phase B must promote the next CA to active")
	}
	newCACert, err := tlspkg.ParseCertificate(caSecret.Data["tls.crt"])
	if err != nil {
		t.Fatalf("promoted CA unparseable: %v", err)
	}
	tlsSecret = getSecret(t, phase, "rot-tls")
	if !leafSignedBy(tlsSecret.Data["tls.crt"], newCACert) {
		t.Fatal("leaf must be reissued from the promoted CA (issuer-forced)")
	}
	if !bytes.Contains(tlsSecret.Data["ca.crt"], oldCAPEM) {
		t.Fatal("trust union must retain the unexpired previous CA after cutover")
	}
	if evs := drain(); len(evs) != 1 || !strings.Contains(evs[0], "CARotationCompleted") {
		t.Fatalf("events after pass 2 = %v, want exactly CARotationCompleted", evs)
	}

	// --- Pass 3: steady state — nothing changes, no events. ---
	beforeCA := getSecret(t, phase, "rot-ca").ResourceVersion
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatalf("Execute() pass 3 error = %v", result.Error)
	}
	if rv := getSecret(t, phase, "rot-ca").ResourceVersion; rv != beforeCA {
		t.Errorf("steady-state pass rewrote the CA secret (rv %s -> %s)", beforeCA, rv)
	}
	if evs := drain(); len(evs) != 0 {
		t.Errorf("steady-state pass emitted events: %v", evs)
	}

	// --- Phase C: previous CA expires -> passively retired. ---
	caSecret = getSecret(t, phase, "rot-ca")
	expired := testCAWithExpiry(t, -time.Hour)
	caSecret.Data["tls-previous.crt"] = expired.CACertPEM
	if err := phase.Client.Update(context.Background(), caSecret); err != nil {
		t.Fatal(err)
	}
	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatalf("Execute() retire pass error = %v", result.Error)
	}
	caSecret = getSecret(t, phase, "rot-ca")
	if _, ok := caSecret.Data["tls-previous.crt"]; ok {
		t.Fatal("expired previous CA must be removed")
	}
	tlsSecret = getSecret(t, phase, "rot-tls")
	if bytes.Contains(tlsSecret.Data["ca.crt"], expired.CACertPEM) {
		t.Fatal("expired CA must leave the trust union")
	}
}

// TestCARotationWaitsForRoll covers the phase A→B gate: with the
// StatefulSet mid-roll, promotion must NOT happen no matter how many
// reconciles pass.
func TestCARotationWaitsForRoll(t *testing.T) {
	phase, cluster, _ := rotationFixture(t, 10*24*time.Hour)

	// Make the STS mid-roll.
	sts := &appsv1.StatefulSet{}
	if err := phase.Client.Get(context.Background(), types.NamespacedName{Name: "rot", Namespace: "rot-ns"}, sts); err != nil {
		t.Fatal(err)
	}
	sts.Status.UpdateRevision = "r2" // != CurrentRevision
	if err := phase.Client.Status().Update(context.Background(), sts); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if result := phase.Execute(context.Background(), cluster); result.Error != nil {
			t.Fatalf("Execute() pass %d error = %v", i, result.Error)
		}
	}
	caSecret := getSecret(t, phase, "rot-ca")
	if _, ok := caSecret.Data["tls-next.crt"]; !ok {
		t.Fatal("phase A should still introduce the next CA")
	}
	if _, ok := caSecret.Data["tls-previous.crt"]; ok {
		t.Fatal("promotion happened despite an in-flight roll")
	}
}

// TestUserCANeverRotates covers neo-4s4's negative AC: a near-expiry
// user-provided CA gets the C5 warning but the operator must not mint,
// rotate, or write anything CA-shaped.
func TestUserCANeverRotates(t *testing.T) {
	cluster := newTestCluster("rot-ns", "userca")
	cluster.Spec.Server.TLS.CA = &nomadv1alpha1.CASpec{
		SecretName: "corp-ca",
		SecretKeys: nomadv1alpha1.CASecretKeys{Certificate: "tls.crt", PrivateKey: "tls.key"},
	}
	userCA := testCAWithExpiry(t, 10*24*time.Hour)
	userSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "corp-ca", Namespace: "rot-ns"},
		Data:       map[string][]byte{"tls.crt": userCA.CACertPEM, "tls.key": userCA.CAKeyPEM},
	}

	recorder := record.NewFakeRecorder(10)
	phase := &CertificatePhase{PhaseContext: &PhaseContext{
		Client:   fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(userSecret).Build(),
		Scheme:   scheme.Scheme,
		Log:      zap.New(zap.UseDevMode(true)),
		Recorder: recorder,
	}}

	if result := phase.Execute(context.Background(), cluster); result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}

	// No operator CA secret minted; the user secret untouched.
	caSecret := &corev1.Secret{}
	if err := phase.Client.Get(context.Background(), types.NamespacedName{Name: "userca-ca", Namespace: "rot-ns"}, caSecret); err == nil {
		t.Fatal("operator-generated CA secret created despite user-provided CA")
	}
	got := getSecret(t, phase, "corp-ca")
	if _, ok := got.Data["tls-next.crt"]; ok {
		t.Fatal("rotation artifacts written into the USER's CA secret")
	}

	var events []string
	for len(recorder.Events) > 0 {
		events = append(events, <-recorder.Events)
	}
	for _, e := range events {
		if strings.Contains(e, "CARotation") {
			t.Fatalf("rotation event fired for a user-provided CA: %v", events)
		}
	}
}
