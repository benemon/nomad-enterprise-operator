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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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

	err = ValidateCertificate(issued.CertPEM, []string{"server.global.nomad", "localhost"}, nil, 30*24*time.Hour)
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

	err = ValidateCertificate(issued.CertPEM, []string{"server.global.nomad"}, nil, 0)
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

	err = ValidateCertificate(issued.CertPEM, []string{"server.global.nomad", "missing.example.com"}, nil, 30*24*time.Hour)
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
	err = ValidateCertificate(issued.CertPEM, []string{"server.global.nomad"}, nil, 30*24*time.Hour)
	if err == nil {
		t.Error("ValidateCertificate() should return error for cert expiring within warning window")
	}
}

// generateRSACA creates an RSA CA for testing key type matching.
func generateRSACA(t *testing.T, bits int) *CABundle {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "Test RSA CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create RSA CA certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return &CABundle{CACertPEM: certPEM, CAKeyPEM: keyPEM}
}

// generateECCA creates an ECDSA CA with a specific curve for testing.
func generateECCA(t *testing.T, curve elliptic.Curve) *CABundle {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate EC key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "Test EC CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create EC CA certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal EC key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &CABundle{CACertPEM: certPEM, CAKeyPEM: keyPEM}
}

func TestIssueCertificate_RSA_CA(t *testing.T) {
	ca := generateRSACA(t, 2048)

	issued, err := IssueCertificate(ca, CertificateRequest{
		CommonName: "server.global.nomad",
		DNSNames:   []string{"server.global.nomad", "localhost"},
		TTL:        365 * 24 * time.Hour,
		IsServer:   true,
	})
	if err != nil {
		t.Fatalf("IssueCertificate() error = %v", err)
	}

	// Verify the issued key is RSA
	keyBlock, _ := pem.Decode(issued.KeyPEM)
	if keyBlock == nil {
		t.Fatal("Failed to decode issued key PEM")
	}
	if keyBlock.Type != "RSA PRIVATE KEY" {
		t.Errorf("Key PEM type = %q, want %q", keyBlock.Type, "RSA PRIVATE KEY")
	}

	rsaKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse issued key as RSA: %v", err)
	}
	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("RSA key size = %d bits, want 2048", rsaKey.N.BitLen())
	}

	// Verify the cert is valid and signed by the CA
	cert, err := ParseCertificate(issued.CertPEM)
	if err != nil {
		t.Fatalf("Failed to parse issued cert: %v", err)
	}
	caCert, _ := ParseCertificate(ca.CACertPEM)
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("Certificate signature verification failed: %v", err)
	}
}

func TestIssueCertificate_ECDSA_P384_CA(t *testing.T) {
	ca := generateECCA(t, elliptic.P384())

	issued, err := IssueCertificate(ca, CertificateRequest{
		CommonName: "server.global.nomad",
		DNSNames:   []string{"server.global.nomad"},
		TTL:        365 * 24 * time.Hour,
		IsServer:   true,
	})
	if err != nil {
		t.Fatalf("IssueCertificate() error = %v", err)
	}

	// Verify the issued key is ECDSA P-384
	keyBlock, _ := pem.Decode(issued.KeyPEM)
	if keyBlock == nil {
		t.Fatal("Failed to decode issued key PEM")
	}
	if keyBlock.Type != "EC PRIVATE KEY" {
		t.Errorf("Key PEM type = %q, want %q", keyBlock.Type, "EC PRIVATE KEY")
	}

	ecKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse issued key as EC: %v", err)
	}
	if ecKey.Curve != elliptic.P384() {
		t.Errorf("EC curve = %v, want P-384", ecKey.Curve.Params().Name)
	}

	// Verify the cert is signed by the CA
	cert, err := ParseCertificate(issued.CertPEM)
	if err != nil {
		t.Fatalf("Failed to parse issued cert: %v", err)
	}
	caCert, _ := ParseCertificate(ca.CACertPEM)
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("Certificate signature verification failed: %v", err)
	}
}

func TestIssueCertificate_PKCS8_CA(t *testing.T) {
	// Generate an EC key and encode it as PKCS#8 instead of SEC 1
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "Test PKCS8 CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Marshal key as PKCS#8 (BEGIN PRIVATE KEY)
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS#8 key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

	ca := &CABundle{CACertPEM: certPEM, CAKeyPEM: keyPEM}

	issued, err := IssueCertificate(ca, CertificateRequest{
		CommonName: "server.global.nomad",
		DNSNames:   []string{"server.global.nomad"},
		TTL:        365 * 24 * time.Hour,
		IsServer:   true,
	})
	if err != nil {
		t.Fatalf("IssueCertificate() with PKCS#8 CA error = %v", err)
	}

	// Verify issued key is EC (matching the PKCS#8 CA's underlying type)
	keyBlock, _ := pem.Decode(issued.KeyPEM)
	if keyBlock.Type != "EC PRIVATE KEY" {
		t.Errorf("Key PEM type = %q, want %q", keyBlock.Type, "EC PRIVATE KEY")
	}

	// Verify cert is signed by the CA
	cert, err := ParseCertificate(issued.CertPEM)
	if err != nil {
		t.Fatalf("Failed to parse issued cert: %v", err)
	}
	caCert, _ := ParseCertificate(ca.CACertPEM)
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("Certificate signature verification failed: %v", err)
	}
}
