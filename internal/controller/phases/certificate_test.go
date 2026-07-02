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

	tlspkg "github.com/hashicorp/nomad-enterprise-operator/pkg/tls"
	"k8s.io/client-go/tools/record"
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
	return &tlspkg.CABundle{
		CACertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
	}
}

// TestCARenewalRequiredEvent covers C5 (neo-jkg) / AC-2.4.9 / AC-2.4.10:
// status.certificateAuthority carries expiryTime and renewalRequiredBy;
// crossing the renewal deadline emits a one-shot Warning Event debounced
// via the renewalWarningEmitted status marker (surviving operator
// restarts); a rotated CA resets the debounce.
func TestCARenewalRequiredEvent(t *testing.T) {
	drainEvents := func(recorder *record.FakeRecorder) []string {
		var events []string
		for {
			select {
			case e := <-recorder.Events:
				events = append(events, e)
			default:
				return events
			}
		}
	}

	newPhase := func() (*CertificatePhase, *record.FakeRecorder) {
		recorder := record.NewFakeRecorder(5)
		return &CertificatePhase{PhaseContext: &PhaseContext{
			Log:      zap.New(zap.UseDevMode(true)),
			Recorder: recorder,
		}}, recorder
	}

	t.Run("fresh CA populates deadline without warning", func(t *testing.T) {
		phase, recorder := newPhase()
		cluster := newTestCluster("nomad", "ns")

		phase.updateCAStatus(cluster, "operator-generated", testCAWithExpiry(t, tlspkg.CALifetime))

		ca := cluster.Status.CertificateAuthority
		if ca == nil || ca.ExpiryTime == "" || ca.RenewalRequiredBy == "" {
			t.Fatalf("expiryTime/renewalRequiredBy not populated: %+v", ca)
		}
		if ca.RenewalWarningEmitted {
			t.Error("renewalWarningEmitted set for a fresh CA")
		}
		if events := drainEvents(recorder); len(events) != 0 {
			t.Errorf("unexpected events for fresh CA: %v", events)
		}
	})

	t.Run("near-expiry CA warns once and debounces", func(t *testing.T) {
		phase, recorder := newPhase()
		cluster := newTestCluster("nomad", "ns")
		nearExpiry := testCAWithExpiry(t, 10*24*time.Hour) // inside the 30d window

		phase.updateCAStatus(cluster, "operator-generated", nearExpiry)

		ca := cluster.Status.CertificateAuthority
		if !ca.RenewalWarningEmitted {
			t.Fatal("renewalWarningEmitted not set after crossing the renewal deadline")
		}
		events := drainEvents(recorder)
		if len(events) != 1 || !strings.Contains(events[0], "CARenewalRequired") {
			t.Fatalf("events = %v, want exactly one CARenewalRequired Warning", events)
		}

		// Same CA on the next reconcile (marker persisted on status,
		// as after an operator restart) — no re-emission.
		phase.updateCAStatus(cluster, "operator-generated", nearExpiry)
		if events := drainEvents(recorder); len(events) != 0 {
			t.Fatalf("debounce failed, re-emitted: %v", events)
		}

		// Rotated CA — fresh expiry resets the marker; no event until
		// the new deadline is crossed.
		phase.updateCAStatus(cluster, "operator-generated", testCAWithExpiry(t, tlspkg.CALifetime))
		if cluster.Status.CertificateAuthority.RenewalWarningEmitted {
			t.Error("marker not reset after CA rotation")
		}
		if events := drainEvents(recorder); len(events) != 0 {
			t.Errorf("unexpected events after rotation: %v", events)
		}
	})
}
