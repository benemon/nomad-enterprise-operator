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
	"testing"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

const (
	testAnnotationTrue = "true"
	testInlineCACert   = "inline-ca-cert"
)

func init() {
	_ = nomadv1alpha1.AddToScheme(scheme.Scheme)
}

func newTestPhaseContext(objs ...runtime.Object) *PhaseContext {
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithRuntimeObjects(objs...).
		Build()

	return &PhaseContext{
		Client: fakeClient,
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}
}

func newTestCluster(name, namespace string) *nomadv1alpha1.NomadCluster {
	return &nomadv1alpha1.NomadCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID("test-uid"),
		},
		Spec: nomadv1alpha1.NomadClusterSpec{
			Replicas: 3,
			License: nomadv1alpha1.LicenseSpec{
				SecretName: "nomad-license",
			},
		},
	}
}

// =============================================================================
// PhaseResult Tests
// =============================================================================

func TestPhaseResult_OK(t *testing.T) {
	result := OK()
	if result.Requeue {
		t.Error("OK() should not set Requeue")
	}
	if result.Error != nil {
		t.Error("OK() should not set Error")
	}
}

func TestPhaseResult_Requeue(t *testing.T) {
	result := Requeue(15000000000, "waiting")
	if !result.Requeue {
		t.Error("Requeue() should set Requeue=true")
	}
	if result.Message != "waiting" {
		t.Errorf("Requeue() message = %q, want %q", result.Message, "waiting")
	}
}

func TestPhaseResult_Error(t *testing.T) {
	err := &testError{msg: "test error"}
	result := Error(err, "failed")
	if result.Error == nil {
		t.Error("Error() should set Error")
	}
	if result.Message != "failed" {
		t.Errorf("Error() message = %q, want %q", result.Message, "failed")
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// =============================================================================
// GetLabels / GetSelectorLabels Tests
// =============================================================================

func TestGetLabels(t *testing.T) {
	cluster := newTestCluster("my-cluster", "my-ns")
	labels := GetLabels(cluster)

	expected := map[string]string{
		"app.kubernetes.io/name":       "nomad",
		"app.kubernetes.io/instance":   "my-cluster",
		"app.kubernetes.io/managed-by": "nomad-operator",
		"app.kubernetes.io/component":  "server",
	}

	for k, v := range expected {
		if labels[k] != v {
			t.Errorf("GetLabels()[%q] = %q, want %q", k, labels[k], v)
		}
	}
}

func TestGetSelectorLabels(t *testing.T) {
	cluster := newTestCluster("my-cluster", "my-ns")
	labels := GetSelectorLabels(cluster)

	if labels["app.kubernetes.io/name"] != "nomad" {
		t.Errorf("GetSelectorLabels() missing app.kubernetes.io/name")
	}
	if labels["app.kubernetes.io/instance"] != "my-cluster" {
		t.Errorf("GetSelectorLabels() missing app.kubernetes.io/instance")
	}
	if labels["app"] != "nomad" {
		t.Errorf("GetSelectorLabels() missing app label")
	}
}

// =============================================================================
// GossipPhase Tests
// =============================================================================

func TestGossipPhase_Name(t *testing.T) {
	phase := NewGossipPhase(newTestPhaseContext())
	if phase.Name() != "GossipKey" {
		t.Errorf("Name() = %q, want %q", phase.Name(), "GossipKey")
	}
}

func TestGossipPhase_ExternalSecret(t *testing.T) {
	// Create external gossip secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "external-gossip",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"gossip-key": []byte("external-key-value"),
		},
	}

	ctx := newTestPhaseContext(secret)
	phase := NewGossipPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Gossip.SecretName = "external-gossip"

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
	if ctx.GossipKey != "external-key-value" {
		t.Errorf("GossipKey = %q, want %q", ctx.GossipKey, "external-key-value")
	}
}

func TestGossipPhase_ExternalSecretNotFound(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewGossipPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Gossip.SecretName = "missing-secret"

	result := phase.Execute(context.Background(), cluster)

	if result.Error == nil {
		t.Error("Execute() should return error when external secret not found")
	}
}

func TestGossipPhase_ExternalSecretMissingKey(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "external-gossip",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"wrong-key": []byte("value"),
		},
	}

	ctx := newTestPhaseContext(secret)
	phase := NewGossipPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Gossip.SecretName = "external-gossip"

	result := phase.Execute(context.Background(), cluster)

	if result.Error == nil {
		t.Error("Execute() should return error when key not found in secret")
	}
}

func TestGossipPhase_AutoGenerate(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewGossipPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	// No gossip.secretName specified - should auto-generate

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
	if ctx.GossipKey == "" {
		t.Error("GossipKey should be populated after auto-generation")
	}

	// Verify secret was created
	createdSecret := &corev1.Secret{}
	err := ctx.Client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster-gossip",
		Namespace: "test-ns",
	}, createdSecret)
	if err != nil {
		t.Fatalf("Failed to get created gossip secret: %v", err)
	}
	if _, ok := createdSecret.Data["gossip-key"]; !ok {
		t.Error("Created secret missing gossip-key")
	}
}

func TestGossipPhase_PreserveExisting(t *testing.T) {
	// Create existing operator-managed secret
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-gossip",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"gossip-key": []byte("existing-preserved-key"),
		},
	}

	ctx := newTestPhaseContext(existingSecret)
	phase := NewGossipPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
	if ctx.GossipKey != "existing-preserved-key" {
		t.Errorf("GossipKey = %q, want preserved key %q", ctx.GossipKey, "existing-preserved-key")
	}
}

func TestGossipPhase_CustomSecretKey(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "custom-gossip",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"custom-key": []byte("custom-value"),
		},
	}

	ctx := newTestPhaseContext(secret)
	phase := NewGossipPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Gossip.SecretName = "custom-gossip"
	cluster.Spec.Gossip.SecretKey = "custom-key"

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
	if ctx.GossipKey != "custom-value" {
		t.Errorf("GossipKey = %q, want %q", ctx.GossipKey, "custom-value")
	}
}

// =============================================================================
// ServicesPhase Tests
// =============================================================================

func TestServicesPhase_Name(t *testing.T) {
	phase := NewServicesPhase(newTestPhaseContext())
	if phase.Name() != "Services" {
		t.Errorf("Name() = %q, want %q", phase.Name(), "Services")
	}
}

func TestServicesPhase_CreatesAllServices(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewServicesPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}

	// Verify headless service
	headlessSvc := &corev1.Service{}
	err := ctx.Client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster-headless",
		Namespace: "test-ns",
	}, headlessSvc)
	if err != nil {
		t.Errorf("Failed to get headless service: %v", err)
	}
	if headlessSvc.Spec.ClusterIP != corev1.ClusterIPNone {
		t.Error("Headless service should have ClusterIP=None")
	}

	// Verify internal service
	internalSvc := &corev1.Service{}
	err = ctx.Client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster-internal",
		Namespace: "test-ns",
	}, internalSvc)
	if err != nil {
		t.Errorf("Failed to get internal service: %v", err)
	}
	if internalSvc.Spec.Type != corev1.ServiceTypeClusterIP {
		t.Errorf("Internal service type = %v, want ClusterIP", internalSvc.Spec.Type)
	}

	// Verify external service
	externalSvc := &corev1.Service{}
	err = ctx.Client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster-external",
		Namespace: "test-ns",
	}, externalSvc)
	if err != nil {
		t.Errorf("Failed to get external service: %v", err)
	}
	if externalSvc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		t.Errorf("External service type = %v, want LoadBalancer", externalSvc.Spec.Type)
	}
}

func TestServicesPhase_LoadBalancerIP(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewServicesPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Services.External.LoadBalancerIP = "10.0.0.100"

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}

	externalSvc := &corev1.Service{}
	_ = ctx.Client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster-external",
		Namespace: "test-ns",
	}, externalSvc)

	if externalSvc.Spec.LoadBalancerIP != "10.0.0.100" {
		t.Errorf("LoadBalancerIP = %q, want %q", externalSvc.Spec.LoadBalancerIP, "10.0.0.100")
	}
}

func TestServicesPhase_NodePortType(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewServicesPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Services.External.Type = corev1.ServiceTypeNodePort

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}

	externalSvc := &corev1.Service{}
	_ = ctx.Client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster-external",
		Namespace: "test-ns",
	}, externalSvc)

	if externalSvc.Spec.Type != corev1.ServiceTypeNodePort {
		t.Errorf("External service type = %v, want NodePort", externalSvc.Spec.Type)
	}
}

func TestServicesPhase_Annotations(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewServicesPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Services.External.Annotations = map[string]string{
		"service.beta.kubernetes.io/aws-load-balancer-internal": testAnnotationTrue,
	}

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}

	externalSvc := &corev1.Service{}
	_ = ctx.Client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster-external",
		Namespace: "test-ns",
	}, externalSvc)

	if externalSvc.Annotations["service.beta.kubernetes.io/aws-load-balancer-internal"] != testAnnotationTrue {
		t.Error("External service missing expected annotation")
	}
}

func TestServicesPhase_Idempotent(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewServicesPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")

	// First execution
	result := phase.Execute(context.Background(), cluster)
	if result.Error != nil {
		t.Fatalf("First Execute() error = %v", result.Error)
	}

	// Second execution should not fail
	result = phase.Execute(context.Background(), cluster)
	if result.Error != nil {
		t.Fatalf("Second Execute() error = %v", result.Error)
	}
}

// =============================================================================
// AdvertisePhase Tests
// =============================================================================

func TestAdvertisePhase_Name(t *testing.T) {
	phase := NewAdvertisePhase(newTestPhaseContext())
	if phase.Name() != "AdvertiseResolver" {
		t.Errorf("Name() = %q, want %q", phase.Name(), "AdvertiseResolver")
	}
}

func TestAdvertisePhase_ConfiguredIP(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewAdvertisePhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Services.External.LoadBalancerIP = "192.168.1.100"

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
	if ctx.AdvertiseAddress != "192.168.1.100" {
		t.Errorf("AdvertiseAddress = %q, want %q", ctx.AdvertiseAddress, "192.168.1.100")
	}
}

func TestAdvertisePhase_WaitForLoadBalancer(t *testing.T) {
	// Create external service without LoadBalancer status
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-external",
			Namespace: "test-ns",
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
		},
		Status: corev1.ServiceStatus{
			// No ingress yet
		},
	}

	ctx := newTestPhaseContext(svc)
	phase := NewAdvertisePhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	// No LoadBalancerIP configured, must wait for assignment

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
	if !result.Requeue {
		t.Error("Execute() should request requeue when waiting for LB")
	}
}

func TestAdvertisePhase_LoadBalancerIP(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-external",
			Namespace: "test-ns",
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{
					{IP: "10.0.0.50"},
				},
			},
		},
	}

	ctx := newTestPhaseContext(svc)
	phase := NewAdvertisePhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
	if ctx.AdvertiseAddress != "10.0.0.50" {
		t.Errorf("AdvertiseAddress = %q, want %q", ctx.AdvertiseAddress, "10.0.0.50")
	}
}

func TestAdvertisePhase_LoadBalancerHostname(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-external",
			Namespace: "test-ns",
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{
					{Hostname: "my-lb.example.com"},
				},
			},
		},
	}

	ctx := newTestPhaseContext(svc)
	phase := NewAdvertisePhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
	if ctx.AdvertiseAddress != "my-lb.example.com" {
		t.Errorf("AdvertiseAddress = %q, want %q", ctx.AdvertiseAddress, "my-lb.example.com")
	}
}

func TestAdvertisePhase_ServiceNotFound(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewAdvertisePhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")

	result := phase.Execute(context.Background(), cluster)

	if result.Error == nil {
		t.Error("Execute() should return error when service not found")
	}
}

// =============================================================================
// SecretsPhase Tests
// =============================================================================

func TestSecretsPhase_Name(t *testing.T) {
	phase := NewSecretsPhase(newTestPhaseContext())
	if phase.Name() != "Secrets" {
		t.Errorf("Name() = %q, want %q", phase.Name(), "Secrets")
	}
}

func TestSecretsPhase_LicenseSecretValid(t *testing.T) {
	licenseSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nomad-license",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"license": []byte("license-content"),
		},
	}

	ctx := newTestPhaseContext(licenseSecret)
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
}

func TestSecretsPhase_LicenseSecretNotFound(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")

	result := phase.Execute(context.Background(), cluster)

	if result.Error == nil {
		t.Error("Execute() should return error when license secret not found")
	}
}

func TestSecretsPhase_LicenseSecretMissingKey(t *testing.T) {
	licenseSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nomad-license",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"wrong-key": []byte("value"),
		},
	}

	ctx := newTestPhaseContext(licenseSecret)
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")

	result := phase.Execute(context.Background(), cluster)

	if result.Error == nil {
		t.Error("Execute() should return error when license key not found")
	}
}

func TestSecretsPhase_CustomLicenseKey(t *testing.T) {
	licenseSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nomad-license",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"my-license-key": []byte("license-content"),
		},
	}

	ctx := newTestPhaseContext(licenseSecret)
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.License.SecretKey = "my-license-key"

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
}

func TestSecretsPhase_TLSEnabled_SecretValid(t *testing.T) {
	licenseSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nomad-license",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"license": []byte("license-content"),
		},
	}
	tlsSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nomad-tls",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"ca.crt":     []byte("ca-cert"),
			"server.crt": []byte("server-cert"),
			"server.key": []byte("server-key"),
		},
	}

	ctx := newTestPhaseContext(licenseSecret, tlsSecret)
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.TLS.Enabled = true
	cluster.Spec.Server.TLS.SecretName = "nomad-tls"

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
}

func TestSecretsPhase_TLSEnabled_NoSecretName(t *testing.T) {
	licenseSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nomad-license",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"license": []byte("license-content"),
		},
	}

	ctx := newTestPhaseContext(licenseSecret)
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.TLS.Enabled = true
	// No SecretName specified

	result := phase.Execute(context.Background(), cluster)

	if result.Error == nil {
		t.Error("Execute() should return error when TLS enabled but no secret name")
	}
}

func TestSecretsPhase_TLSEnabled_SecretNotFound(t *testing.T) {
	licenseSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nomad-license",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"license": []byte("license-content"),
		},
	}

	ctx := newTestPhaseContext(licenseSecret)
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.TLS.Enabled = true
	cluster.Spec.Server.TLS.SecretName = "missing-tls"

	result := phase.Execute(context.Background(), cluster)

	if result.Error == nil {
		t.Error("Execute() should return error when TLS secret not found")
	}
}

func TestSecretsPhase_TLSEnabled_MissingKeys(t *testing.T) {
	licenseSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nomad-license",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"license": []byte("license-content"),
		},
	}
	tlsSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nomad-tls",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"ca.crt": []byte("ca-cert"),
			// Missing server.crt and server.key
		},
	}

	ctx := newTestPhaseContext(licenseSecret, tlsSecret)
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.TLS.Enabled = true
	cluster.Spec.Server.TLS.SecretName = "nomad-tls"

	result := phase.Execute(context.Background(), cluster)

	if result.Error == nil {
		t.Error("Execute() should return error when TLS secret missing keys")
	}
}

func TestSecretsPhase_S3Credentials_Valid(t *testing.T) {
	licenseSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nomad-license",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"license": []byte("license-content"),
		},
	}
	s3Secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "s3-creds",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"access-key-id":     []byte("AKIAIOSFODNN7EXAMPLE"),
			"secret-access-key": []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		},
	}

	ctx := newTestPhaseContext(licenseSecret, s3Secret)
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.Snapshot.Enabled = true
	cluster.Spec.Server.Snapshot.S3.CredentialsSecretName = "s3-creds"

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
}

func TestSecretsPhase_S3Credentials_NotFound(t *testing.T) {
	licenseSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nomad-license",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"license": []byte("license-content"),
		},
	}

	ctx := newTestPhaseContext(licenseSecret)
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.Snapshot.Enabled = true
	cluster.Spec.Server.Snapshot.S3.CredentialsSecretName = "missing-creds"

	result := phase.Execute(context.Background(), cluster)

	if result.Error == nil {
		t.Error("Execute() should return error when S3 credentials not found")
	}
}

func TestSecretsPhase_S3Credentials_MissingKeys(t *testing.T) {
	licenseSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nomad-license",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"license": []byte("license-content"),
		},
	}
	s3Secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "s3-creds",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"access-key-id": []byte("AKIAIOSFODNN7EXAMPLE"),
			// Missing secret-access-key
		},
	}

	ctx := newTestPhaseContext(licenseSecret, s3Secret)
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.Snapshot.Enabled = true
	cluster.Spec.Server.Snapshot.S3.CredentialsSecretName = "s3-creds"

	result := phase.Execute(context.Background(), cluster)

	if result.Error == nil {
		t.Error("Execute() should return error when S3 secret missing keys")
	}
}

// =============================================================================
// Inline License Tests
// =============================================================================

func TestSecretsPhase_InlineLicense(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.License.SecretName = ""
	cluster.Spec.License.Value = "inline-license-content"

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}

	// Verify managed secret was created
	createdSecret := &corev1.Secret{}
	err := ctx.Client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster-license",
		Namespace: "test-ns",
	}, createdSecret)
	if err != nil {
		t.Fatalf("Failed to get created license secret: %v", err)
	}
	if string(createdSecret.Data["license"]) != "inline-license-content" {
		t.Errorf("Created secret data = %q, want %q", string(createdSecret.Data["license"]), "inline-license-content")
	}
	if createdSecret.Annotations["nomad.hashicorp.com/managed"] != testAnnotationTrue {
		t.Error("Created secret should have managed annotation")
	}
}

func TestSecretsPhase_InlineLicense_Update(t *testing.T) {
	// Create existing managed secret with old value
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-license",
			Namespace: "test-ns",
			Annotations: map[string]string{
				"nomad.hashicorp.com/managed": testAnnotationTrue,
			},
		},
		Data: map[string][]byte{
			"license": []byte("old-license-value"),
		},
	}

	ctx := newTestPhaseContext(existingSecret)
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.License.SecretName = ""
	cluster.Spec.License.Value = "new-license-value"

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}

	// Verify secret was updated
	updatedSecret := &corev1.Secret{}
	err := ctx.Client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster-license",
		Namespace: "test-ns",
	}, updatedSecret)
	if err != nil {
		t.Fatalf("Failed to get updated license secret: %v", err)
	}
	if string(updatedSecret.Data["license"]) != "new-license-value" {
		t.Errorf("Updated secret data = %q, want %q", string(updatedSecret.Data["license"]), "new-license-value")
	}
}

func TestSecretsPhase_NoLicenseConfigured(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.License.SecretName = ""
	cluster.Spec.License.Value = ""

	result := phase.Execute(context.Background(), cluster)

	if result.Error == nil {
		t.Error("Execute() should return error when no license configured")
	}
}

// =============================================================================
// Inline TLS Tests
// =============================================================================

func TestSecretsPhase_InlineTLS(t *testing.T) {
	licenseSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nomad-license",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"license": []byte("license-content"),
		},
	}

	ctx := newTestPhaseContext(licenseSecret)
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.TLS.Enabled = true
	cluster.Spec.Server.TLS.CACert = testInlineCACert
	cluster.Spec.Server.TLS.ServerCert = "inline-server-cert"
	cluster.Spec.Server.TLS.ServerKey = "inline-server-key"

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}

	// Verify managed TLS secret was created
	createdSecret := &corev1.Secret{}
	err := ctx.Client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster-tls",
		Namespace: "test-ns",
	}, createdSecret)
	if err != nil {
		t.Fatalf("Failed to get created TLS secret: %v", err)
	}
	if string(createdSecret.Data["ca.crt"]) != testInlineCACert {
		t.Errorf("ca.crt = %q, want %q", string(createdSecret.Data["ca.crt"]), testInlineCACert)
	}
	if string(createdSecret.Data["server.crt"]) != "inline-server-cert" {
		t.Errorf("server.crt = %q, want %q", string(createdSecret.Data["server.crt"]), "inline-server-cert")
	}
	if string(createdSecret.Data["server.key"]) != "inline-server-key" {
		t.Errorf("server.key = %q, want %q", string(createdSecret.Data["server.key"]), "inline-server-key")
	}
	if createdSecret.Annotations["nomad.hashicorp.com/managed"] != testAnnotationTrue {
		t.Error("Created TLS secret should have managed annotation")
	}
}

func TestSecretsPhase_InlineTLS_PartialInline(t *testing.T) {
	licenseSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nomad-license",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"license": []byte("license-content"),
		},
	}

	ctx := newTestPhaseContext(licenseSecret)
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.TLS.Enabled = true
	cluster.Spec.Server.TLS.CACert = testInlineCACert
	// Missing serverCert and serverKey - should fail

	result := phase.Execute(context.Background(), cluster)

	if result.Error == nil {
		t.Error("Execute() should return error when TLS inline is partial (missing certs)")
	}
}

// =============================================================================
// Inline S3 Credentials Tests
// =============================================================================

func TestSecretsPhase_InlineS3Credentials(t *testing.T) {
	licenseSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nomad-license",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"license": []byte("license-content"),
		},
	}

	ctx := newTestPhaseContext(licenseSecret)
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.Snapshot.Enabled = true
	cluster.Spec.Server.Snapshot.S3.AccessKeyID = "AKIAIOSFODNN7EXAMPLE"
	cluster.Spec.Server.Snapshot.S3.SecretAccessKey = "wJalrXUtnFEMI/K7MDENG"

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}

	// Verify managed S3 secret was created
	createdSecret := &corev1.Secret{}
	err := ctx.Client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster-s3-credentials",
		Namespace: "test-ns",
	}, createdSecret)
	if err != nil {
		t.Fatalf("Failed to get created S3 credentials secret: %v", err)
	}
	if string(createdSecret.Data["access-key-id"]) != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("access-key-id = %q, want %q", string(createdSecret.Data["access-key-id"]), "AKIAIOSFODNN7EXAMPLE")
	}
	if string(createdSecret.Data["secret-access-key"]) != "wJalrXUtnFEMI/K7MDENG" {
		t.Errorf("secret-access-key = %q, want %q", string(createdSecret.Data["secret-access-key"]), "wJalrXUtnFEMI/K7MDENG")
	}
	if createdSecret.Annotations["nomad.hashicorp.com/managed"] != testAnnotationTrue {
		t.Error("Created S3 secret should have managed annotation")
	}
}

func TestSecretsPhase_S3_NoCredentials_IAMRole(t *testing.T) {
	licenseSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nomad-license",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"license": []byte("license-content"),
		},
	}

	ctx := newTestPhaseContext(licenseSecret)
	phase := NewSecretsPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.Snapshot.Enabled = true
	// No credentials specified - should assume IAM role authentication

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestGetLicenseSecretName(t *testing.T) {
	tests := []struct {
		name     string
		cluster  *nomadv1alpha1.NomadCluster
		expected string
	}{
		{
			name: "inline value",
			cluster: &nomadv1alpha1.NomadCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "my-cluster"},
				Spec: nomadv1alpha1.NomadClusterSpec{
					License: nomadv1alpha1.LicenseSpec{
						Value: "license-content",
					},
				},
			},
			expected: "my-cluster-license",
		},
		{
			name: "external secret",
			cluster: &nomadv1alpha1.NomadCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "my-cluster"},
				Spec: nomadv1alpha1.NomadClusterSpec{
					License: nomadv1alpha1.LicenseSpec{
						SecretName: "external-license",
					},
				},
			},
			expected: "external-license",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetLicenseSecretName(tt.cluster)
			if got != tt.expected {
				t.Errorf("GetLicenseSecretName() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetTLSSecretName(t *testing.T) {
	tests := []struct {
		name     string
		cluster  *nomadv1alpha1.NomadCluster
		expected string
	}{
		{
			name: "inline certs",
			cluster: &nomadv1alpha1.NomadCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "my-cluster"},
				Spec: nomadv1alpha1.NomadClusterSpec{
					Server: nomadv1alpha1.ServerSpec{
						TLS: nomadv1alpha1.TLSSpec{
							Enabled:    true,
							CACert:     "ca-cert",
							ServerCert: "server-cert",
							ServerKey:  "server-key",
						},
					},
				},
			},
			expected: "my-cluster-tls",
		},
		{
			name: "external secret",
			cluster: &nomadv1alpha1.NomadCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "my-cluster"},
				Spec: nomadv1alpha1.NomadClusterSpec{
					Server: nomadv1alpha1.ServerSpec{
						TLS: nomadv1alpha1.TLSSpec{
							Enabled:    true,
							SecretName: "external-tls",
						},
					},
				},
			},
			expected: "external-tls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetTLSSecretName(tt.cluster)
			if got != tt.expected {
				t.Errorf("GetTLSSecretName() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetS3CredentialsSecretName(t *testing.T) {
	tests := []struct {
		name     string
		cluster  *nomadv1alpha1.NomadCluster
		expected string
	}{
		{
			name: "inline credentials",
			cluster: &nomadv1alpha1.NomadCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "my-cluster"},
				Spec: nomadv1alpha1.NomadClusterSpec{
					Server: nomadv1alpha1.ServerSpec{
						Snapshot: nomadv1alpha1.SnapshotSpec{
							Enabled: true,
							S3: nomadv1alpha1.S3Spec{
								AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
								SecretAccessKey: "secret",
							},
						},
					},
				},
			},
			expected: "my-cluster-s3-credentials",
		},
		{
			name: "external secret",
			cluster: &nomadv1alpha1.NomadCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "my-cluster"},
				Spec: nomadv1alpha1.NomadClusterSpec{
					Server: nomadv1alpha1.ServerSpec{
						Snapshot: nomadv1alpha1.SnapshotSpec{
							Enabled: true,
							S3: nomadv1alpha1.S3Spec{
								CredentialsSecretName: "external-s3-creds",
							},
						},
					},
				},
			},
			expected: "external-s3-creds",
		},
		{
			name: "no credentials (IAM)",
			cluster: &nomadv1alpha1.NomadCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "my-cluster"},
				Spec: nomadv1alpha1.NomadClusterSpec{
					Server: nomadv1alpha1.ServerSpec{
						Snapshot: nomadv1alpha1.SnapshotSpec{
							Enabled: true,
						},
					},
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetS3CredentialsSecretName(tt.cluster)
			if got != tt.expected {
				t.Errorf("GetS3CredentialsSecretName() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetGossipSecretName(t *testing.T) {
	tests := []struct {
		name     string
		cluster  *nomadv1alpha1.NomadCluster
		expected string
	}{
		{
			name: "external secret",
			cluster: &nomadv1alpha1.NomadCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "my-cluster"},
				Spec: nomadv1alpha1.NomadClusterSpec{
					Gossip: nomadv1alpha1.GossipSpec{
						SecretName: "external-gossip",
					},
				},
			},
			expected: "external-gossip",
		},
		{
			name: "auto-generated",
			cluster: &nomadv1alpha1.NomadCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "my-cluster"},
				Spec:       nomadv1alpha1.NomadClusterSpec{},
			},
			expected: "my-cluster-gossip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetGossipSecretName(tt.cluster)
			if got != tt.expected {
				t.Errorf("GetGossipSecretName() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// =============================================================================
// RoutePhase Tests
// =============================================================================

func TestRoutePhase_Name(t *testing.T) {
	phase := NewRoutePhase(newTestPhaseContext())
	if phase.Name() != "Route" {
		t.Errorf("Name() = %q, want %q", phase.Name(), "Route")
	}
}

func TestRoutePhase_Disabled(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewRoutePhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.OpenShift.Enabled = false

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
	if result.Requeue {
		t.Error("Execute() should not requeue when disabled")
	}
}

func TestRoutePhase_OpenShiftEnabledRouteDisabled(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewRoutePhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.OpenShift.Enabled = true
	cluster.Spec.OpenShift.Route.Enabled = false

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
}

// =============================================================================
// ACLBootstrapPhase Tests
// =============================================================================

func TestACLBootstrapPhase_Name(t *testing.T) {
	phase := NewACLBootstrapPhase(newTestPhaseContext())
	if phase.Name() != "ACLBootstrap" {
		t.Errorf("Name() = %q, want %q", phase.Name(), "ACLBootstrap")
	}
}

func TestACLBootstrapPhase_Disabled(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewACLBootstrapPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.ACL.Enabled = false

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
	if result.Requeue {
		t.Error("Execute() should not requeue when ACL disabled")
	}
}

func TestACLBootstrapPhase_AlreadyBootstrapped(t *testing.T) {
	// Create existing bootstrap secret
	bootstrapSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-acl-bootstrap",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"secret-id": []byte("existing-token"),
		},
	}

	ctx := newTestPhaseContext(bootstrapSecret)
	phase := NewACLBootstrapPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.ACL.Enabled = true

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
	if result.Requeue {
		t.Error("Execute() should not requeue when already bootstrapped")
	}
}

func TestACLBootstrapPhase_CustomSecretName(t *testing.T) {
	bootstrapSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "custom-bootstrap-secret",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"secret-id": []byte("existing-token"),
		},
	}

	ctx := newTestPhaseContext(bootstrapSecret)
	phase := NewACLBootstrapPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.ACL.Enabled = true
	cluster.Spec.Server.ACL.BootstrapSecretName = "custom-bootstrap-secret"

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
}

func TestACLBootstrapPhase_WaitForPods(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewACLBootstrapPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")
	cluster.Spec.Server.ACL.Enabled = true

	result := phase.Execute(context.Background(), cluster)

	// Should requeue waiting for pods
	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}
	if !result.Requeue {
		t.Error("Execute() should request requeue when no pods ready")
	}
}

// =============================================================================
// ServiceAccountPhase Tests
// =============================================================================

func TestServiceAccountPhase_Name(t *testing.T) {
	phase := NewServiceAccountPhase(newTestPhaseContext())
	if phase.Name() != "ServiceAccount" {
		t.Errorf("Name() = %q, want %q", phase.Name(), "ServiceAccount")
	}
}

func TestServiceAccountPhase_Creates(t *testing.T) {
	ctx := newTestPhaseContext()
	phase := NewServiceAccountPhase(ctx)

	cluster := newTestCluster("test-cluster", "test-ns")

	result := phase.Execute(context.Background(), cluster)

	if result.Error != nil {
		t.Fatalf("Execute() error = %v", result.Error)
	}

	sa := &corev1.ServiceAccount{}
	err := ctx.Client.Get(context.Background(), types.NamespacedName{
		Name:      "test-cluster",
		Namespace: "test-ns",
	}, sa)
	if err != nil {
		t.Fatalf("Failed to get ServiceAccount: %v", err)
	}
}

// =============================================================================
// RBACPhase Tests
// =============================================================================

func TestRBACPhase_Name(t *testing.T) {
	phase := NewRBACPhase(newTestPhaseContext())
	if phase.Name() != "RBAC" {
		t.Errorf("Name() = %q, want %q", phase.Name(), "RBAC")
	}
}

// =============================================================================
// mapsEqual Tests
// =============================================================================

func TestMapsEqual(t *testing.T) {
	tests := []struct {
		name string
		a    map[string]string
		b    map[string]string
		want bool
	}{
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "both empty",
			a:    map[string]string{},
			b:    map[string]string{},
			want: true,
		},
		{
			name: "equal",
			a:    map[string]string{"key": "value"},
			b:    map[string]string{"key": "value"},
			want: true,
		},
		{
			name: "different values",
			a:    map[string]string{"key": "value1"},
			b:    map[string]string{"key": "value2"},
			want: false,
		},
		{
			name: "different keys",
			a:    map[string]string{"key1": "value"},
			b:    map[string]string{"key2": "value"},
			want: false,
		},
		{
			name: "different lengths",
			a:    map[string]string{"key": "value"},
			b:    map[string]string{"key": "value", "key2": "value2"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mapsEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("mapsEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}
