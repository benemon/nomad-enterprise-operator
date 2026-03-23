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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// CABundle holds the generated CA certificate and private key in PEM format.
type CABundle struct {
	CACertPEM []byte
	CAKeyPEM  []byte
}

// IssuedCertificate holds an issued certificate and private key in PEM format,
// along with the CA certificate that signed it.
type IssuedCertificate struct {
	CACertPEM []byte
	CertPEM   []byte
	KeyPEM    []byte
}

// CertificateRequest defines the parameters for issuing a certificate.
type CertificateRequest struct {
	CommonName  string
	DNSNames    []string
	IPAddresses []net.IP
	TTL         time.Duration
	// IsServer indicates the cert requires both serverAuth and clientAuth EKU.
	// When false, only clientAuth EKU is set (for operator/client certs).
	IsServer bool
}

// GenerateCA creates a new self-signed ECDSA P-256 CA certificate and key.
// The CA is valid for 10 years.
func GenerateCA(commonName string) (*CABundle, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &CABundle{
		CACertPEM: certPEM,
		CAKeyPEM:  keyPEM,
	}, nil
}

// IssueCertificate issues a certificate signed by the provided CA.
func IssueCertificate(ca *CABundle, req CertificateRequest) (*IssuedCertificate, error) {
	// Parse CA cert and key
	caCert, err := ParseCertificate(ca.CACertPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caKeyBlock, _ := pem.Decode(ca.CAKeyPEM)
	if caKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA private key PEM")
	}
	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Generate new key for the certificate
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate key: %w", err)
	}

	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}

	ttl := req.TTL
	if ttl == 0 {
		ttl = 365 * 24 * time.Hour
	}

	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if req.IsServer {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: req.CommonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  extKeyUsage,
		DNSNames:     req.DNSNames,
		IPAddresses:  req.IPAddresses,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &IssuedCertificate{
		CACertPEM: ca.CACertPEM,
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
	}, nil
}

// ParseCertificate parses a PEM-encoded certificate and returns the x509.Certificate.
func ParseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ValidateCertificate checks that a certificate:
// - Is not expired
// - Is not expiring within the given warning window
// - Contains all of the required DNS SANs
// Returns an error describing any validation failure.
func ValidateCertificate(certPEM []byte, requiredDNSSANs []string, warningWindow time.Duration) error {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	now := time.Now()
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate expired at %s", cert.NotAfter.Format(time.RFC3339))
	}

	if now.Add(warningWindow).After(cert.NotAfter) {
		return fmt.Errorf("certificate expiring within warning window at %s", cert.NotAfter.Format(time.RFC3339))
	}

	// Check required SANs
	certDNS := make(map[string]bool, len(cert.DNSNames))
	for _, dns := range cert.DNSNames {
		certDNS[dns] = true
	}
	for _, required := range requiredDNSSANs {
		if !certDNS[required] {
			return fmt.Errorf("certificate missing required DNS SAN: %s", required)
		}
	}

	return nil
}

func randomSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return serialNumber, nil
}
