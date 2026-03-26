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
	"net"
	"time"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	tlspkg "github.com/hashicorp/nomad-enterprise-operator/pkg/tls"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	certWarningWindow = 30 * 24 * time.Hour
	serverCertTTL     = 365 * 24 * time.Hour
	defaultTLSCertKey = "tls.crt"
	defaultTLSKeyKey  = "tls.key"
)

// CertificatePhase ensures all TLS certificates exist, are valid, and are not
// approaching expiry.
type CertificatePhase struct {
	*PhaseContext
}

// NewCertificatePhase creates a new CertificatePhase.
func NewCertificatePhase(ctx *PhaseContext) *CertificatePhase {
	return &CertificatePhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *CertificatePhase) Name() string {
	return "Certificate"
}

// Execute ensures all TLS certificates are present and valid.
func (p *CertificatePhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	var caBundle *tlspkg.CABundle

	if cluster.Spec.Server.TLS.CA != nil && cluster.Spec.Server.TLS.CA.SecretName != "" {
		result, bundle := p.loadUserCA(ctx, cluster)
		if result.Error != nil || result.Requeue {
			return result
		}
		caBundle = bundle
		p.updateCAStatus(cluster, "user-provided", bundle)
	} else {
		result, bundle := p.ensureGeneratedCA(ctx, cluster)
		if result.Error != nil || result.Requeue {
			return result
		}
		caBundle = bundle
		p.updateCAStatus(cluster, "operator-generated", bundle)
	}

	if result := p.ensureServerCertificate(ctx, cluster, caBundle); result.Error != nil || result.Requeue {
		return result
	}

	if result := p.ensureCABundleConfigMap(ctx, cluster, caBundle.CACertPEM); result.Error != nil || result.Requeue {
		return result
	}

	p.CACert = caBundle.CACertPEM

	return OK()
}

// loadUserCA reads the CA Secret referenced by the user.
func (p *CertificatePhase) loadUserCA(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (PhaseResult, *tlspkg.CABundle) {
	caSpec := cluster.Spec.Server.TLS.CA

	certKey := caSpec.SecretKeys.Certificate
	if certKey == "" {
		certKey = defaultTLSCertKey
	}
	keyKey := caSpec.SecretKeys.PrivateKey
	if keyKey == "" {
		keyKey = defaultTLSKeyKey
	}

	secret := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      caSpec.SecretName,
		Namespace: cluster.Namespace,
	}, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return Error(fmt.Errorf("CA secret %q not found", caSpec.SecretName),
				"User-provided CA secret not found"), nil
		}
		return Error(err, "Failed to get CA secret"), nil
	}

	caCertPEM, ok := secret.Data[certKey]
	if !ok {
		return Error(fmt.Errorf("key %q not found in CA secret %q", certKey, caSpec.SecretName),
			"CA secret missing certificate key"), nil
	}
	caKeyPEM, ok := secret.Data[keyKey]
	if !ok {
		return Error(fmt.Errorf("key %q not found in CA secret %q", keyKey, caSpec.SecretName),
			"CA secret missing private key"), nil
	}

	return OK(), &tlspkg.CABundle{
		CACertPEM: caCertPEM,
		CAKeyPEM:  caKeyPEM,
	}
}

// ensureGeneratedCA creates or loads the operator-generated CA.
func (p *CertificatePhase) ensureGeneratedCA(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (PhaseResult, *tlspkg.CABundle) {
	secretName := cluster.Name + "-ca"

	existing := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, existing)
	if err == nil {
		// CA secret exists, load it
		return OK(), &tlspkg.CABundle{
			CACertPEM: existing.Data["tls.crt"],
			CAKeyPEM:  existing.Data["tls.key"],
		}
	}
	if !errors.IsNotFound(err) {
		return Error(err, "Failed to check CA secret"), nil
	}

	// Generate new CA
	commonName := fmt.Sprintf("Nomad Enterprise Operator CA - %s", cluster.Name)
	ca, err := tlspkg.GenerateCA(commonName)
	if err != nil {
		return Error(err, "Failed to generate CA"), nil
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"tls.crt": ca.CACertPEM,
			"tls.key": ca.CAKeyPEM,
		},
	}

	if err := controllerutil.SetControllerReference(cluster, secret, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on CA secret"), nil
	}

	p.Log.Info("Creating CA secret", "name", secretName)
	if err := p.Client.Create(ctx, secret); err != nil {
		return Error(err, "Failed to create CA secret"), nil
	}

	return OK(), ca
}

// updateCAStatus updates the CertificateAuthorityStatus on the cluster.
func (p *CertificatePhase) updateCAStatus(cluster *nomadv1alpha1.NomadCluster, source string, ca *tlspkg.CABundle) {
	status := &nomadv1alpha1.CertificateAuthorityStatus{
		Source: source,
	}

	cert, err := tlspkg.ParseCertificate(ca.CACertPEM)
	if err == nil {
		status.ExpiryTime = cert.NotAfter.Format(time.RFC3339)
		status.Subject = cert.Subject.String()
	}

	cluster.Status.CertificateAuthority = status
}

// ensureServerCertificate ensures the server TLS certificate exists and is valid.
func (p *CertificatePhase) ensureServerCertificate(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, ca *tlspkg.CABundle) PhaseResult {
	secretName := cluster.Name + "-tls"
	requiredDNS := p.serverDNSSANs(cluster)

	// Build required IP SANs — 127.0.0.1 always, plus LoadBalancer IP if known
	requiredIPs := []net.IP{net.ParseIP("127.0.0.1")}
	if p.AdvertiseAddress != "" {
		if ip := net.ParseIP(p.AdvertiseAddress); ip != nil {
			requiredIPs = append(requiredIPs, ip)
		}
	}

	// Check if existing cert is valid (including IP SANs — ensures the cert
	// is reissued when the LoadBalancer IP becomes known after initial creation)
	existing := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, existing)
	if err == nil {
		if certPEM, ok := existing.Data["tls.crt"]; ok {
			if validateErr := tlspkg.ValidateCertificate(certPEM, requiredDNS, requiredIPs, certWarningWindow); validateErr == nil {
				return OK()
			}
			p.Log.Info("Server certificate needs renewal", "name", secretName, "reason", "SANs or expiry changed")
		}
	} else if !errors.IsNotFound(err) {
		return Error(err, "Failed to check server TLS secret")
	}

	// Issue new server certificate

	region := cluster.Spec.Topology.Region
	if region == "" {
		region = "global"
	}

	issued, err := tlspkg.IssueCertificate(ca, tlspkg.CertificateRequest{
		CommonName:  fmt.Sprintf("server.%s.nomad", region),
		DNSNames:    requiredDNS,
		IPAddresses: requiredIPs,
		TTL:         serverCertTTL,
		IsServer:    true,
	})
	if err != nil {
		return Error(err, "Failed to issue server certificate")
	}

	// tls.crt contains the full chain: leaf cert followed by the CA chain.
	// This allows TLS clients to verify the chain back to a trusted root
	// without needing the intermediate CA pre-installed.
	fullChain := append(issued.CertPEM, issued.CACertPEM...)

	return p.writeSecret(ctx, cluster, secretName, map[string][]byte{
		"ca.crt":  issued.CACertPEM,
		"tls.crt": fullChain,
		"tls.key": issued.KeyPEM,
	})
}

// ensureCABundleConfigMap ensures the CA bundle ConfigMap exists.
func (p *CertificatePhase) ensureCABundleConfigMap(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, caCertPEM []byte) PhaseResult {
	cmName := cluster.Name + "-ca-bundle"

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Data: map[string]string{
			"ca.crt": string(caCertPEM),
		},
	}

	if err := controllerutil.SetControllerReference(cluster, cm, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on CA bundle ConfigMap")
	}

	existing := &corev1.ConfigMap{}
	err := p.Client.Get(ctx, types.NamespacedName{Name: cmName, Namespace: cluster.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			p.Log.Info("Creating CA bundle ConfigMap", "name", cmName)
			if err := p.Client.Create(ctx, cm); err != nil {
				return Error(err, "Failed to create CA bundle ConfigMap")
			}
			return OK()
		}
		return Error(err, "Failed to get CA bundle ConfigMap")
	}

	// Update if changed
	if existing.Data["ca.crt"] != string(caCertPEM) {
		existing.Data = cm.Data
		if err := p.Client.Update(ctx, existing); err != nil {
			return Error(err, "Failed to update CA bundle ConfigMap")
		}
	}

	return OK()
}

// writeSecret creates or updates a Secret with the given data.
func (p *CertificatePhase) writeSecret(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, name string, data map[string][]byte) PhaseResult {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}

	if err := controllerutil.SetControllerReference(cluster, secret, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on secret")
	}

	existing := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			p.Log.Info("Creating TLS secret", "name", name)
			if err := p.Client.Create(ctx, secret); err != nil {
				return Error(err, "Failed to create TLS secret")
			}
			return OK()
		}
		return Error(err, "Failed to get TLS secret")
	}

	// Update existing
	existing.Data = data
	p.Log.Info("Updating TLS secret", "name", name)
	if err := p.Client.Update(ctx, existing); err != nil {
		return Error(err, "Failed to update TLS secret")
	}

	return OK()
}

// serverDNSSANs returns the required DNS SANs for the server certificate.
func (p *CertificatePhase) serverDNSSANs(cluster *nomadv1alpha1.NomadCluster) []string {
	region := cluster.Spec.Topology.Region
	if region == "" {
		region = "global"
	}

	replicas := cluster.Spec.Replicas
	if replicas == 0 {
		replicas = 3
	}

	dns := []string{
		fmt.Sprintf("server.%s.nomad", region),
	}

	for i := int32(0); i < replicas; i++ {
		dns = append(dns,
			fmt.Sprintf("%s-%d.%s-headless.%s.svc.cluster.local", cluster.Name, i, cluster.Name, cluster.Namespace),
			fmt.Sprintf("%s-%d.%s-headless.%s.svc", cluster.Name, i, cluster.Name, cluster.Namespace),
		)
	}

	dns = append(dns,
		fmt.Sprintf("%s-internal.%s.svc.cluster.local", cluster.Name, cluster.Namespace),
		fmt.Sprintf("%s-internal.%s.svc", cluster.Name, cluster.Namespace),
		"localhost",
	)

	return dns
}
