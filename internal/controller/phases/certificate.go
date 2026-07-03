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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"time"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/internal/metrics"
	tlspkg "github.com/hashicorp/nomad-enterprise-operator/pkg/tls"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
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
// caBundle is the active signing CA; trustPEM is the union of every CA
// pods must trust (identical outside rotation).
func (p *CertificatePhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	var caBundle *tlspkg.CABundle
	var trustPEM []byte

	if cluster.Spec.Server.TLS.CA != nil && cluster.Spec.Server.TLS.CA.SecretName != "" {
		result, bundle := p.loadUserCA(ctx, cluster)
		if result.Error != nil || result.Requeue {
			return result
		}
		caBundle = bundle
		trustPEM = bundle.CACertPEM
		p.updateCAStatus(cluster, "user-provided", bundle)
	} else {
		result, bundle, trust := p.ensureGeneratedCA(ctx, cluster)
		if result.Error != nil || result.Requeue {
			return result
		}
		caBundle = bundle
		trustPEM = trust
		p.updateCAStatus(cluster, "operator-generated", bundle)
	}

	if result := p.ensureServerCertificate(ctx, cluster, caBundle, trustPEM); result.Error != nil || result.Requeue {
		return result
	}

	if result := p.ensureCABundleConfigMap(ctx, cluster, trustPEM); result.Error != nil || result.Requeue {
		return result
	}

	p.CACert = trustPEM

	return OK()
}

// loadUserCA reads the CA Secret referenced by the user.
func (p *CertificatePhase) loadUserCA(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (PhaseResult, *tlspkg.CABundle) {
	caSpec := cluster.Spec.Server.TLS.CA

	// Key names are guaranteed non-empty by kubebuilder defaulting
	// (+kubebuilder:default={} on SecretKeys + nested field defaults).
	// Overridable for ESO/VSO-populated Secrets that don't follow the
	// kubernetes.io/tls key convention.
	certKey := caSpec.SecretKeys.Certificate
	keyKey := caSpec.SecretKeys.PrivateKey

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

// CA secret data keys. The active pair signs leaf certificates; the
// -next pair exists only between rotation phases A and B; -previous
// holds the retired CA's certificate (no key — it never signs again)
// until it expires and drops out of the trust union passively.
const (
	caSecretCertKey     = "tls.crt"
	caSecretKeyKey      = "tls.key"
	caSecretNextCertKey = "tls-next.crt"
	caSecretNextKeyKey  = "tls-next.key"
	caSecretPrevCertKey = "tls-previous.crt"
)

// ensureGeneratedCA creates or loads the operator-generated CA, drives
// the neo-4s4 rotation state machine, and returns both the active
// signing bundle and the trust union PEM.
func (p *CertificatePhase) ensureGeneratedCA(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) (PhaseResult, *tlspkg.CABundle, []byte) {
	secretName := cluster.Name + "-ca"

	existing := &corev1.Secret{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, existing)
	if err == nil {
		if result := p.rotateCAIfDue(ctx, cluster, existing); result.Error != nil {
			return result, nil, nil
		}
		return OK(), &tlspkg.CABundle{
			CACertPEM: existing.Data[caSecretCertKey],
			CAKeyPEM:  existing.Data[caSecretKeyKey],
		}, caTrustUnion(existing)
	}
	if !errors.IsNotFound(err) {
		return Error(err, "Failed to check CA secret"), nil, nil
	}

	// Generate new CA
	commonName := fmt.Sprintf("Nomad Enterprise Operator CA - %s", cluster.Name)
	ca, err := tlspkg.GenerateCA(commonName)
	if err != nil {
		return Error(err, "Failed to generate CA"), nil, nil
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels:    GetLabels(cluster),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			caSecretCertKey: ca.CACertPEM,
			caSecretKeyKey:  ca.CAKeyPEM,
		},
	}

	if err := controllerutil.SetControllerReference(cluster, secret, p.Scheme); err != nil {
		return Error(err, "Failed to set owner reference on CA secret"), nil, nil
	}

	p.Log.Info("Creating CA secret", "name", secretName)
	if err := p.Client.Create(ctx, secret); err != nil {
		return Error(err, "Failed to create CA secret"), nil, nil
	}

	return OK(), ca, ca.CACertPEM
}

// rotateCAIfDue drives CA rotation: introduce next CA at the renewal
// deadline, promote it once every pod trusts it, drop the previous CA
// when it expires. All state lives in the Secret's keys, so a restarted
// operator resumes where it left off. Never called for user CAs.
func (p *CertificatePhase) rotateCAIfDue(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, secret *corev1.Secret) PhaseResult {
	activeCert, err := tlspkg.ParseCertificate(secret.Data[caSecretCertKey])
	if err != nil {
		// Unparseable active CA — leave rotation alone; the leaf issue
		// path will surface the real error.
		return OK()
	}

	changed := false

	// Phase A: introduce the next CA when renewal is due.
	_, hasNext := secret.Data[caSecretNextCertKey]
	if !hasNext && time.Now().After(activeCert.NotAfter.Add(-tlspkg.CertWarningWindow)) {
		next, genErr := tlspkg.GenerateCA(fmt.Sprintf("Nomad Enterprise Operator CA - %s", cluster.Name))
		if genErr != nil {
			return Error(genErr, "Failed to generate next CA for rotation")
		}
		secret.Data[caSecretNextCertKey] = next.CACertPEM
		secret.Data[caSecretNextKeyKey] = next.CAKeyPEM
		hasNext = true
		changed = true
		p.Log.Info("CA rotation started: next CA introduced", "cluster", cluster.Name,
			"activeExpiry", activeCert.NotAfter.Format(time.RFC3339))
		if p.Recorder != nil {
			p.Recorder.Event(cluster, corev1.EventTypeNormal, "CARotationStarted",
				fmt.Sprintf("CA expires at %s; new CA introduced, rolling pods onto dual trust",
					activeCert.NotAfter.Format(time.RFC3339)))
		}
	}

	// Phase B: promote once every pod demonstrably trusts the next CA.
	if hasNext && !changed &&
		p.statefulSetFullyRolled(ctx, cluster) &&
		p.trustDelivered(ctx, cluster, secret.Data[caSecretNextCertKey]) {
		secret.Data[caSecretPrevCertKey] = secret.Data[caSecretCertKey]
		secret.Data[caSecretCertKey] = secret.Data[caSecretNextCertKey]
		secret.Data[caSecretKeyKey] = secret.Data[caSecretNextKeyKey]
		delete(secret.Data, caSecretNextCertKey)
		delete(secret.Data, caSecretNextKeyKey)
		changed = true
		p.Log.Info("CA rotation cutover: next CA promoted to active", "cluster", cluster.Name)
		if p.Recorder != nil {
			p.Recorder.Event(cluster, corev1.EventTypeNormal, "CARotationCompleted",
				"New CA promoted; server certificates reissue from it and the old CA is retained in the trust bundle until it expires")
		}
	}

	// Phase C: drop the previous CA's certificate once it has expired.
	if prevPEM, ok := secret.Data[caSecretPrevCertKey]; ok {
		if prevCert, perr := tlspkg.ParseCertificate(prevPEM); perr != nil || time.Now().After(prevCert.NotAfter) {
			delete(secret.Data, caSecretPrevCertKey)
			changed = true
			p.Log.Info("CA rotation retire: expired previous CA removed from trust", "cluster", cluster.Name)
		}
	}

	if changed {
		if err := p.Client.Update(ctx, secret); err != nil {
			return Error(err, "Failed to update CA secret during rotation")
		}
	}
	return OK()
}

// caTrustUnion returns the PEM concatenation of every CA certificate a
// pod must trust right now: active, pending next, and the unexpired
// previous. Retirement is a pure function of time.
func caTrustUnion(secret *corev1.Secret) []byte {
	union := append([]byte{}, secret.Data[caSecretCertKey]...)
	if next, ok := secret.Data[caSecretNextCertKey]; ok {
		union = append(union, next...)
	}
	if prev, ok := secret.Data[caSecretPrevCertKey]; ok {
		if prevCert, err := tlspkg.ParseCertificate(prev); err == nil && time.Now().Before(prevCert.NotAfter) {
			union = append(union, prev...)
		}
	}
	return union
}

// statefulSetFullyRolled reports whether every pod is running the
// current pod template — the gate between rotation phases A and B.
// Conservative on any doubt: a missing StatefulSet, stale observation,
// or in-flight roll all return false and rotation simply waits.
func (p *CertificatePhase) statefulSetFullyRolled(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) bool {
	sts := &appsv1.StatefulSet{}
	if err := p.Client.Get(ctx, types.NamespacedName{
		Name: cluster.Name, Namespace: cluster.Namespace,
	}, sts); err != nil {
		return false
	}
	if sts.Generation != sts.Status.ObservedGeneration || sts.Spec.Replicas == nil {
		return false
	}
	replicas := *sts.Spec.Replicas
	return sts.Status.UpdatedReplicas == replicas &&
		sts.Status.ReadyReplicas == replicas &&
		sts.Status.CurrentRevision == sts.Status.UpdateRevision
}

// trustDelivered reports whether the mounted TLS secret's ca.crt
// already carries the given CA certificate — i.e. the union the pods
// rolled onto includes the next CA, making promotion safe.
func (p *CertificatePhase) trustDelivered(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, caCertPEM []byte) bool {
	tlsSecret := &corev1.Secret{}
	if err := p.Client.Get(ctx, types.NamespacedName{
		Name: TLSSecretName(cluster.Name), Namespace: cluster.Namespace,
	}, tlsSecret); err != nil {
		return false
	}
	return bytes.Contains(tlsSecret.Data["ca.crt"], caCertPEM)
}

// updateCAStatus refreshes status.certificateAuthority. The
// CARenewalRequired Warning fires for user-provided CAs only —
// operator CAs rotate themselves and emit rotation Events instead.
func (p *CertificatePhase) updateCAStatus(cluster *nomadv1alpha1.NomadCluster, source string, ca *tlspkg.CABundle) {
	prev := cluster.Status.CertificateAuthority

	status := &nomadv1alpha1.CertificateAuthorityStatus{
		Source: source,
	}

	cert, err := tlspkg.ParseCertificate(ca.CACertPEM)
	if err == nil {
		status.ExpiryTime = cert.NotAfter.Format(time.RFC3339)
		status.Subject = cert.Subject.String()

		// D4c / AC-8.1.3: export the CA expiry for alerting.
		metrics.CertExpiry.WithLabelValues(cluster.Name, cluster.Namespace, "ca").
			Set(float64(cert.NotAfter.Unix()))

		renewalRequiredBy := cert.NotAfter.Add(-tlspkg.CertWarningWindow)
		status.RenewalRequiredBy = renewalRequiredBy.Format(time.RFC3339)

		// Events escalate (30d/14d/7d, then daily) because a single
		// Event expires from etcd within the hour. The bucket marker
		// debounces; a replaced CA resets it via the fresh struct.
		if prev != nil && prev.ExpiryTime == status.ExpiryTime {
			status.RenewalWarningThreshold = prev.RenewalWarningThreshold
		}
		if source == "user-provided" {
			if bucket := renewalWarningBucket(cert.NotAfter, time.Now()); bucket != "" && bucket != status.RenewalWarningThreshold {
				if p.Recorder != nil {
					days := int(time.Until(cert.NotAfter).Hours() / 24)
					msg := fmt.Sprintf("User-provided CA expires at %s (%d days); renew and update the CA Secret", status.ExpiryTime, days)
					if days < 0 {
						msg = fmt.Sprintf("User-provided CA EXPIRED at %s; TLS is broken until the CA Secret is renewed", status.ExpiryTime)
					}
					p.Recorder.Event(cluster, corev1.EventTypeWarning, "CARenewalRequired", msg)
				}
				status.RenewalWarningThreshold = bucket
			}
		}
	}

	cluster.Status.CertificateAuthority = status
}

// renewalWarningBucket maps time-to-expiry onto the warning cadence:
// one bucket per crossing at 30d and 14d, then date-stamped buckets
// inside the final week (and past expiry) so the Event re-emits daily.
func renewalWarningBucket(notAfter, now time.Time) string {
	left := notAfter.Sub(now)
	switch {
	case left > 30*24*time.Hour:
		return ""
	case left > 14*24*time.Hour:
		return "30d"
	case left > 7*24*time.Hour:
		return "14d"
	default:
		return "7d:" + now.Format("2006-01-02")
	}
}

// ensureServerCertificate ensures the server TLS certificate exists, is
// valid, was issued by the ACTIVE CA, and ships alongside the current
// trust union.
func (p *CertificatePhase) ensureServerCertificate(ctx context.Context, cluster *nomadv1alpha1.NomadCluster, ca *tlspkg.CABundle, trustPEM []byte) PhaseResult {
	secretName := TLSSecretName(cluster.Name)
	requiredDNS := p.serverDNSSANs(cluster)

	// Build required IP SANs — 127.0.0.1 always, plus LoadBalancer IP if known
	requiredIPs := []net.IP{net.ParseIP("127.0.0.1")}
	if p.AdvertiseAddress != "" {
		if ip := net.ParseIP(p.AdvertiseAddress); ip != nil {
			requiredIPs = append(requiredIPs, ip)
		}
	}

	activeCACert, err := tlspkg.ParseCertificate(ca.CACertPEM)
	if err != nil {
		return Error(err, "Failed to parse active CA certificate")
	}

	// Check if existing cert is valid (including IP SANs — ensures the cert
	// is reissued when the LoadBalancer IP becomes known after initial creation)
	existing := &corev1.Secret{}
	err = p.Client.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, existing)
	if err == nil {
		if certPEM, ok := existing.Data["tls.crt"]; ok {
			validateErr := tlspkg.ValidateCertificate(certPEM, requiredDNS, requiredIPs, tlspkg.CertWarningWindow)
			issuedByActive := leafSignedBy(certPEM, activeCACert)
			if validateErr == nil && issuedByActive {
				setServerCertExpiryGauge(cluster, certPEM)
				// The leaf is fine, but the trust bundle may still have
				// moved (rotation phases change the union without
				// touching the leaf). Deliver it, preserving the leaf.
				if !bytes.Equal(existing.Data["ca.crt"], trustPEM) {
					p.Log.Info("Updating server TLS trust bundle", "name", secretName)
					leaf := leafPEM(certPEM)
					return p.writeSecret(ctx, cluster, secretName, map[string][]byte{
						"ca.crt":  trustPEM,
						"tls.crt": append(leaf, ca.CACertPEM...),
						"tls.key": existing.Data["tls.key"],
					})
				}
				return OK()
			}
			reason := "SANs or expiry changed"
			if validateErr == nil && !issuedByActive {
				// Rotation cutover (neo-4s4): ValidateCertificate checks
				// SANs and expiry only — an old-CA leaf passes it, so the
				// issuer check forces the reissue.
				reason = "issuer changed (CA rotation)"
			}
			p.Log.Info("Server certificate needs renewal", "name", secretName, "reason", reason)
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
		TTL:         tlspkg.ServerCertTTL,
		IsServer:    true,
	})
	if err != nil {
		return Error(err, "Failed to issue server certificate")
	}

	// tls.crt is the full chain (leaf + signing CA); ca.crt is the
	// trust union, a superset of the signing CA during rotation.
	fullChain := append(issued.CertPEM, issued.CACertPEM...)

	setServerCertExpiryGauge(cluster, issued.CertPEM)

	return p.writeSecret(ctx, cluster, secretName, map[string][]byte{
		"ca.crt":  trustPEM,
		"tls.crt": fullChain,
		"tls.key": issued.KeyPEM,
	})
}

// leafSignedBy reports whether the leaf in pemData was signed by the
// given CA. Signature-checked, not name-compared: rotation generates
// CAs with identical CommonNames.
func leafSignedBy(pemData []byte, caCert *x509.Certificate) bool {
	leaf, err := tlspkg.ParseCertificate(pemData)
	if err != nil {
		return false
	}
	return leaf.CheckSignatureFrom(caCert) == nil
}

// leafPEM returns only the first PEM block from a chain — the leaf —
// so a trust-bundle-only update can rebuild tls.crt without carrying
// a stale CA chain forward.
func leafPEM(pemData []byte) []byte {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return pemData
	}
	return pem.EncodeToMemory(block)
}

// setServerCertExpiryGauge exports the leaf's NotAfter to the
// CertExpiry gauge. Unparseable PEM is skipped; the issue paths
// already error on it.
func setServerCertExpiryGauge(cluster *nomadv1alpha1.NomadCluster, certPEM []byte) {
	if cert, err := tlspkg.ParseCertificate(certPEM); err == nil {
		metrics.CertExpiry.WithLabelValues(cluster.Name, cluster.Namespace, "server").
			Set(float64(cert.NotAfter.Unix()))
	}
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
