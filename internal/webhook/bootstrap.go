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

// Package webhook contains the operator-singleton webhook TLS bootstrap (Tree 1
// in the operator's two-cert-tree model).
//
// Rotation flow:
//
//  1. EnsureSecret runs before manager.Start (cmd/main.go) so the cert exists
//     by the time the webhook server boots and certwatcher begins polling the
//     mounted Secret. On first run it generates a fresh CA (10y) and a leaf
//     cert (ServerCertTTL = 365d) with DNS SAN = <service>.<namespace>.svc.
//     The resulting Secret carries tls.crt, tls.key, and ca.crt.
//  2. The Bootstrap Runnable then runs continuously under the manager. Once
//     every reconcileInterval (24h by default) it reads the Secret, parses the
//     leaf, and if the cert is inside CertWarningWindow (30d) it reissues the
//     leaf using the existing CA — overwriting the Secret in place.
//  3. controller-runtime's certwatcher polls the mounted file every 10s and
//     hot-reloads the new keypair into the webhook server's TLS config — no
//     restart required.
//  4. Each reconcile also patches the ValidatingWebhookConfiguration's
//     clientConfig.caBundle with the current CA cert so kube-apiserver trusts
//     the new chain. The CA itself only rotates if the Secret is deleted out
//     of band; this matches the cert-manager experience and avoids tearing
//     down in-flight admission traffic.
//
// This package must remain independent of internal/controller/phases.
// Tree 1 (this) and Tree 2 (per-NomadCluster server certs) share only the TTL
// constants in pkg/tls — code paths stay separate by design (AC-F3).
package webhook

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	tlspkg "github.com/hashicorp/nomad-enterprise-operator/pkg/tls"
)

const (
	// DefaultSecretName is the Secret in the operator namespace that carries
	// the webhook TLS material. The webhook Deployment mounts this Secret at
	// DefaultCertDir.
	DefaultSecretName = "nomad-enterprise-operator-webhook-tls"

	// DefaultServiceName is the Service that fronts the webhook server. The
	// ValidatingWebhookConfiguration's clientConfig.service points here and the
	// leaf cert's DNS SAN matches <service>.<namespace>.svc. The name follows
	// the kustomize namePrefix applied in config/default/kustomization.yaml.
	DefaultServiceName = "nomad-enterprise-operator-webhook-service"

	// DefaultValidatingWebhookName is the ValidatingWebhookConfiguration the
	// bootstrap patches the caBundle into. Matches the name controller-gen
	// emits in config/webhook/manifests.yaml after the kustomize namePrefix
	// is applied.
	DefaultValidatingWebhookName = "nomad-enterprise-operator-validating-webhook-configuration"

	// DefaultMutatingWebhookName is the MutatingWebhookConfiguration the
	// bootstrap also patches. kubebuilder's WithDefaulter() registers a
	// mutating webhook alongside the validating one even if Default() is
	// a no-op — both have to trust the same CA or the apiserver will
	// reject create/update requests on TLS verification.
	DefaultMutatingWebhookName = "nomad-enterprise-operator-mutating-webhook-configuration"

	// DefaultNamespace is the fallback used when POD_NAMESPACE is unset
	// (e.g. running locally). Matches config/default/kustomization.yaml's
	// namespace.
	DefaultNamespace = "nomad-enterprise-operator-system"

	// DefaultCertDir is the directory controller-runtime's webhook server
	// expects to find tls.crt and tls.key in.
	DefaultCertDir = "/tmp/k8s-webhook-server/serving-certs"

	// PodNamespaceEnvVar is the downward-API-populated env var that tells the
	// operator which namespace it is running in.
	PodNamespaceEnvVar = "POD_NAMESPACE"

	// reconcileInterval is how often the continuous reconciler re-checks
	// cert expiry. 24h is plenty since the leaf lasts ServerCertTTL and
	// reissue is cheap.
	reconcileInterval = 24 * time.Hour

	tlsCrtKey = "tls.crt"
	tlsKeyKey = "tls.key"
	caCrtKey  = "ca.crt"
	caKeyKey  = "ca.key"
)

var log = logf.Log.WithName("webhook-bootstrap")

// RBAC for the bootstrap reconciler: it manages the operator's own webhook
// TLS Secret and patches caBundle into both the Validating and Mutating
// WebhookConfigurations (kubebuilder's WithDefaulter registers both).
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,verbs=get;list;watch;update;patch

// Config configures the webhook TLS bootstrap.
type Config struct {
	// Namespace the operator is running in. Resolved from POD_NAMESPACE with
	// a fallback to DefaultNamespace if NamespaceFromEnv is called.
	Namespace string

	// SecretName, ServiceName, ValidatingWebhookName, MutatingWebhookName,
	// CertDir all default to their Default* counterparts if empty.
	SecretName            string
	ServiceName           string
	ValidatingWebhookName string
	MutatingWebhookName   string
	CertDir               string
}

// applyDefaults fills in zero values with package defaults.
func (c *Config) applyDefaults() {
	if c.Namespace == "" {
		c.Namespace = DefaultNamespace
	}
	if c.SecretName == "" {
		c.SecretName = DefaultSecretName
	}
	if c.ServiceName == "" {
		c.ServiceName = DefaultServiceName
	}
	if c.ValidatingWebhookName == "" {
		c.ValidatingWebhookName = DefaultValidatingWebhookName
	}
	if c.MutatingWebhookName == "" {
		c.MutatingWebhookName = DefaultMutatingWebhookName
	}
	if c.CertDir == "" {
		c.CertDir = DefaultCertDir
	}
}

// NamespaceFromEnv reads POD_NAMESPACE and falls back to DefaultNamespace if
// unset. Use the downward API in the Deployment to populate it — see
// config/manager/manager.yaml.
func NamespaceFromEnv() string {
	if ns := os.Getenv(PodNamespaceEnvVar); ns != "" {
		return ns
	}
	return DefaultNamespace
}

// Bootstrap is a controller-runtime Runnable that keeps the webhook TLS
// Secret rotated and the ValidatingWebhookConfiguration's caBundle in sync.
type Bootstrap struct {
	Client client.Client
	Config Config

	// interval is overridable for tests.
	interval time.Duration
}

// NewBootstrap returns a Bootstrap with the given client and config. Zero-
// valued config fields are filled with defaults.
func NewBootstrap(c client.Client, cfg Config) *Bootstrap {
	cfg.applyDefaults()
	return &Bootstrap{Client: c, Config: cfg, interval: reconcileInterval}
}

// NeedLeaderElection ensures the rotation loop runs on the leader only — the
// bootstrap mutates the shared Secret and ValidatingWebhookConfiguration.
func (b *Bootstrap) NeedLeaderElection() bool { return true }

// Start implements manager.Runnable. Reconciles immediately and then on a
// ticker until the context is cancelled.
func (b *Bootstrap) Start(ctx context.Context) error {
	if err := b.reconcile(ctx); err != nil {
		log.Error(err, "initial webhook TLS reconcile failed")
	}
	t := time.NewTicker(b.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := b.reconcile(ctx); err != nil {
				log.Error(err, "periodic webhook TLS reconcile failed")
			}
		}
	}
}

// EnsureSecret guarantees the webhook TLS Secret exists before the manager
// starts. It is safe to call multiple times: existing valid Secrets are
// returned untouched.
func (b *Bootstrap) EnsureSecret(ctx context.Context) error {
	return b.reconcile(ctx)
}

// WriteCertsToDir reads the current Secret and writes tls.crt / tls.key to
// CertDir so the webhook server (and certwatcher) can pick them up at boot.
// The directory is created if missing.
func (b *Bootstrap) WriteCertsToDir(ctx context.Context) error {
	secret := &corev1.Secret{}
	if err := b.Client.Get(ctx, types.NamespacedName{
		Name:      b.Config.SecretName,
		Namespace: b.Config.Namespace,
	}, secret); err != nil {
		return fmt.Errorf("failed to read webhook TLS secret: %w", err)
	}
	if err := os.MkdirAll(b.Config.CertDir, 0o755); err != nil {
		return fmt.Errorf("failed to create cert dir %q: %w", b.Config.CertDir, err)
	}
	if err := os.WriteFile(filepath.Join(b.Config.CertDir, tlsCrtKey), secret.Data[tlsCrtKey], 0o600); err != nil {
		return fmt.Errorf("failed to write tls.crt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(b.Config.CertDir, tlsKeyKey), secret.Data[tlsKeyKey], 0o600); err != nil {
		return fmt.Errorf("failed to write tls.key: %w", err)
	}
	return nil
}

// reconcile is the single source of truth for the bootstrap's behaviour:
// load-or-create the Secret, check expiry, reissue if needed, then patch the
// ValidatingWebhookConfiguration's caBundle.
func (b *Bootstrap) reconcile(ctx context.Context) error {
	dnsSAN := fmt.Sprintf("%s.%s.svc", b.Config.ServiceName, b.Config.Namespace)
	dnsSANs := []string{
		dnsSAN,
		fmt.Sprintf("%s.%s.svc.cluster.local", b.Config.ServiceName, b.Config.Namespace),
	}

	secret := &corev1.Secret{}
	getErr := b.Client.Get(ctx, types.NamespacedName{
		Name:      b.Config.SecretName,
		Namespace: b.Config.Namespace,
	}, secret)

	switch {
	case apierrors.IsNotFound(getErr):
		// Fresh install — generate CA + leaf.
		if err := b.createSecret(ctx, dnsSANs); err != nil {
			return err
		}
		// Re-read so we have the populated object for caBundle patching.
		if err := b.Client.Get(ctx, types.NamespacedName{
			Name:      b.Config.SecretName,
			Namespace: b.Config.Namespace,
		}, secret); err != nil {
			return fmt.Errorf("failed to re-read freshly created secret: %w", err)
		}
	case getErr != nil:
		return fmt.Errorf("failed to get webhook TLS secret: %w", getErr)
	default:
		// Existing secret — validate, reissue if expiring or SANs changed.
		if err := tlspkg.ValidateCertificate(secret.Data[tlsCrtKey], dnsSANs, nil, tlspkg.CertWarningWindow); err != nil {
			log.Info("reissuing webhook leaf", "reason", err.Error())
			if err := b.reissueLeaf(ctx, secret, dnsSANs); err != nil {
				return err
			}
		}
	}

	return b.patchCABundle(ctx, secret.Data[caCrtKey])
}

// createSecret generates a fresh CA + leaf and writes a new Secret.
func (b *Bootstrap) createSecret(ctx context.Context, dnsSANs []string) error {
	ca, err := tlspkg.GenerateCA("Nomad Enterprise Operator Webhook CA")
	if err != nil {
		return fmt.Errorf("failed to generate webhook CA: %w", err)
	}
	issued, err := tlspkg.IssueCertificate(ca, tlspkg.CertificateRequest{
		CommonName: dnsSANs[0],
		DNSNames:   dnsSANs,
		TTL:        tlspkg.ServerCertTTL,
		IsServer:   true,
	})
	if err != nil {
		return fmt.Errorf("failed to issue webhook leaf cert: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.Config.SecretName,
			Namespace: b.Config.Namespace,
		},
		// Opaque (not kubernetes.io/tls) because we carry the CA key alongside
		// the leaf so the rotation loop can reissue without regenerating the
		// CA. SecretTypeTLS rejects keys other than tls.crt/tls.key.
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			tlsCrtKey: issued.CertPEM,
			tlsKeyKey: issued.KeyPEM,
			caCrtKey:  issued.CACertPEM,
			caKeyKey:  ca.CAKeyPEM,
		},
	}
	log.Info("creating webhook TLS secret", "name", b.Config.SecretName, "namespace", b.Config.Namespace)
	if err := b.Client.Create(ctx, secret); err != nil {
		return fmt.Errorf("failed to create webhook TLS secret: %w", err)
	}
	return nil
}

// reissueLeaf reuses the existing CA in the Secret to issue a fresh leaf and
// updates the Secret in place. Reusing the CA avoids invalidating the
// caBundle already trusted by kube-apiserver, which would race with the
// patchCABundle update. If the CA key is missing from the Secret (e.g. it
// was created by a prior version), the whole tree is regenerated.
func (b *Bootstrap) reissueLeaf(ctx context.Context, secret *corev1.Secret, dnsSANs []string) error {
	ca := &tlspkg.CABundle{
		CACertPEM: secret.Data[caCrtKey],
		CAKeyPEM:  secret.Data[caKeyKey],
	}
	if len(ca.CACertPEM) == 0 || len(ca.CAKeyPEM) == 0 {
		log.Info("CA material missing from secret; regenerating CA + leaf")
		if err := b.Client.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete stale webhook secret: %w", err)
		}
		if err := b.createSecret(ctx, dnsSANs); err != nil {
			return err
		}
		return b.Client.Get(ctx, types.NamespacedName{
			Name:      b.Config.SecretName,
			Namespace: b.Config.Namespace,
		}, secret)
	}

	issued, err := tlspkg.IssueCertificate(ca, tlspkg.CertificateRequest{
		CommonName: dnsSANs[0],
		DNSNames:   dnsSANs,
		TTL:        tlspkg.ServerCertTTL,
		IsServer:   true,
	})
	if err != nil {
		return fmt.Errorf("failed to reissue webhook leaf: %w", err)
	}
	secret.Data[tlsCrtKey] = issued.CertPEM
	secret.Data[tlsKeyKey] = issued.KeyPEM
	secret.Data[caCrtKey] = issued.CACertPEM
	if err := b.Client.Update(ctx, secret); err != nil {
		return fmt.Errorf("failed to update webhook TLS secret: %w", err)
	}
	return nil
}

// patchCABundle updates clientConfig.caBundle on every webhook entry in
// both the Validating and Mutating WebhookConfigurations. It is a no-op
// if the bundle already matches. kubebuilder's WithDefaulter scaffolds a
// mutating webhook alongside the validating one, even when Default() is
// a no-op — both must trust the same CA or the apiserver rejects
// create/update with "x509: certificate signed by unknown authority".
func (b *Bootstrap) patchCABundle(ctx context.Context, caBundle []byte) error {
	if len(caBundle) == 0 {
		return fmt.Errorf("refusing to patch empty caBundle")
	}

	if err := b.patchValidatingCABundle(ctx, caBundle); err != nil {
		return err
	}
	return b.patchMutatingCABundle(ctx, caBundle)
}

func (b *Bootstrap) patchValidatingCABundle(ctx context.Context, caBundle []byte) error {
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	if err := b.Client.Get(ctx, types.NamespacedName{Name: b.Config.ValidatingWebhookName}, vwc); err != nil {
		if apierrors.IsNotFound(err) {
			// The VWC may not exist yet during early bootstrap (e.g. CRDs
			// applied first, webhook manifests applied next). Don't treat
			// this as fatal — the next tick will pick it up.
			log.V(1).Info("ValidatingWebhookConfiguration not found, skipping caBundle patch", "name", b.Config.ValidatingWebhookName)
			return nil
		}
		return fmt.Errorf("failed to get ValidatingWebhookConfiguration: %w", err)
	}

	changed := false
	for i := range vwc.Webhooks {
		if !equalBytes(vwc.Webhooks[i].ClientConfig.CABundle, caBundle) {
			vwc.Webhooks[i].ClientConfig.CABundle = caBundle
			changed = true
		}
	}
	if !changed {
		return nil
	}
	log.Info("patching ValidatingWebhookConfiguration caBundle", "name", b.Config.ValidatingWebhookName)
	if err := b.Client.Update(ctx, vwc); err != nil {
		return fmt.Errorf("failed to update ValidatingWebhookConfiguration: %w", err)
	}
	return nil
}

func (b *Bootstrap) patchMutatingCABundle(ctx context.Context, caBundle []byte) error {
	mwc := &admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := b.Client.Get(ctx, types.NamespacedName{Name: b.Config.MutatingWebhookName}, mwc); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("MutatingWebhookConfiguration not found, skipping caBundle patch", "name", b.Config.MutatingWebhookName)
			return nil
		}
		return fmt.Errorf("failed to get MutatingWebhookConfiguration: %w", err)
	}

	changed := false
	for i := range mwc.Webhooks {
		if !equalBytes(mwc.Webhooks[i].ClientConfig.CABundle, caBundle) {
			mwc.Webhooks[i].ClientConfig.CABundle = caBundle
			changed = true
		}
	}
	if !changed {
		return nil
	}
	log.Info("patching MutatingWebhookConfiguration caBundle", "name", b.Config.MutatingWebhookName)
	if err := b.Client.Update(ctx, mwc); err != nil {
		return fmt.Errorf("failed to update MutatingWebhookConfiguration: %w", err)
	}
	return nil
}

// equalBytes compares two byte slices for equality.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
