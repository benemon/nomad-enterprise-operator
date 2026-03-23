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

package tls

import (
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func TestGenerateCA(t *testing.T) {
	ca, err := GenerateCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}
	if len(ca.CACertPEM) == 0 {
		t.Fatal("GenerateCA() returned empty CACertPEM")
	}
	if len(ca.CAKeyPEM) == 0 {
		t.Fatal("GenerateCA() returned empty CAKeyPEM")
	}

	cert, err := ParseCertificate(ca.CACertPEM)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if !cert.IsCA {
		t.Error("CA certificate should have IsCA=true")
	}
	if cert.Subject.CommonName != "Test CA" {
		t.Errorf("CA CN = %q, want %q", cert.Subject.CommonName, "Test CA")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA should have KeyUsageCertSign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("CA should have KeyUsageCRLSign")
	}

	// Verify self-signed
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool})
	if err != nil {
		t.Errorf("CA certificate should be self-signed, verify error: %v", err)
	}
}

func TestIssueCertificate_Server(t *testing.T) {
	ca, err := GenerateCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	issued, err := IssueCertificate(ca, CertificateRequest{
		CommonName:  "server.global.nomad",
		DNSNames:    []string{"server.global.nomad", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		TTL:         24 * time.Hour,
		IsServer:    true,
	})
	if err != nil {
		t.Fatalf("IssueCertificate() error = %v", err)
	}

	cert, err := ParseCertificate(issued.CertPEM)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	// Verify signed by CA
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CACertPEM)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Errorf("Server cert should validate against CA: %v", err)
	}

	// Server cert must have both serverAuth and clientAuth
	hasServerAuth := false
	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("Server cert should have ExtKeyUsageServerAuth")
	}
	if !hasClientAuth {
		t.Error("Server cert should have ExtKeyUsageClientAuth")
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("Server cert should have KeyUsageDigitalSignature")
	}
}

func TestIssueCertificate_Client(t *testing.T) {
	ca, err := GenerateCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	issued, err := IssueCertificate(ca, CertificateRequest{
		CommonName: "operator-client",
		DNSNames:   []string{"operator.test.svc"},
		IsServer:   false,
	})
	if err != nil {
		t.Fatalf("IssueCertificate() error = %v", err)
	}

	cert, err := ParseCertificate(issued.CertPEM)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	// Client cert must have only clientAuth
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("Client cert ExtKeyUsage = %v, want [ClientAuth]", cert.ExtKeyUsage)
	}
}

func TestValidateCertificate_Valid(t *testing.T) {
	ca, err := GenerateCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	issued, err := IssueCertificate(ca, CertificateRequest{
		CommonName: "server.global.nomad",
		DNSNames:   []string{"server.global.nomad", "localhost"},
		TTL:        365 * 24 * time.Hour,
		IsServer:   true,
	})
	if err != nil {
		t.Fatalf("IssueCertificate() error = %v", err)
	}

	err = ValidateCertificate(issued.CertPEM, []string{"server.global.nomad", "localhost"}, 30*24*time.Hour)
	if err != nil {
		t.Errorf("ValidateCertificate() error = %v, want nil", err)
	}
}

func TestValidateCertificate_Expired(t *testing.T) {
	ca, err := GenerateCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	// Issue a cert with very short TTL that expires within warning window
	issued, err := IssueCertificate(ca, CertificateRequest{
		CommonName: "server.global.nomad",
		DNSNames:   []string{"server.global.nomad"},
		TTL:        1 * time.Second,
		IsServer:   true,
	})
	if err != nil {
		t.Fatalf("IssueCertificate() error = %v", err)
	}

	// Wait for cert to expire
	time.Sleep(2 * time.Second)

	err = ValidateCertificate(issued.CertPEM, []string{"server.global.nomad"}, 0)
	if err == nil {
		t.Error("ValidateCertificate() should return error for expired cert")
	}
}

func TestValidateCertificate_MissingSAN(t *testing.T) {
	ca, err := GenerateCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	issued, err := IssueCertificate(ca, CertificateRequest{
		CommonName: "server.global.nomad",
		DNSNames:   []string{"server.global.nomad"},
		TTL:        365 * 24 * time.Hour,
		IsServer:   true,
	})
	if err != nil {
		t.Fatalf("IssueCertificate() error = %v", err)
	}

	err = ValidateCertificate(issued.CertPEM, []string{"server.global.nomad", "missing.example.com"}, 30*24*time.Hour)
	if err == nil {
		t.Error("ValidateCertificate() should return error for missing SAN")
	}
}

func TestValidateCertificate_ExpiringWithinWindow(t *testing.T) {
	ca, err := GenerateCA("Test CA")
	if err != nil {
		t.Fatalf("GenerateCA() error = %v", err)
	}

	issued, err := IssueCertificate(ca, CertificateRequest{
		CommonName: "server.global.nomad",
		DNSNames:   []string{"server.global.nomad"},
		TTL:        10 * 24 * time.Hour, // 10 days
		IsServer:   true,
	})
	if err != nil {
		t.Fatalf("IssueCertificate() error = %v", err)
	}

	// Warning window of 30 days should catch a 10-day cert
	err = ValidateCertificate(issued.CertPEM, []string{"server.global.nomad"}, 30*24*time.Hour)
	if err == nil {
		t.Error("ValidateCertificate() should return error for cert expiring within warning window")
	}
}
