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

package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// B3 (neo-x8i): every field on ADR 0003's DROP list must be gone from the
// CRD schema. A validating webhook cannot reject removed fields — the API
// server prunes unknown CR fields during decode, BEFORE admission webhooks
// run (same finding as B2). Empirically (envtest k8s 1.35), CR pruning
// also takes precedence over server-side strict field validation: the
// apiserver silently drops the field rather than erroring. kubectl users
// still get an "unknown field" error from kubectl's own strict validation;
// programmatic clients get silent pruning. This table therefore asserts
// the enforceable invariant: each dropped field is PRUNED from the stored
// object — proving it is absent from the served schema.
var _ = Describe("ADR 0003 dropped fields are pruned from the schema", func() {
	const namespace = "dropped-fields-test"

	ctx := context.Background()

	BeforeEach(func() {
		// Every It shares one namespace; tolerate AlreadyExists.
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
		if err := k8sClient.Create(ctx, ns); err != nil && !errors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	// Each entry sets exactly one dropped field on an otherwise-minimal
	// spec, then asserts the stored object does NOT contain it.
	type droppedField struct {
		name      string
		fieldPath []string // path under .spec that must be pruned
		spec      map[string]interface{}
	}

	dropped := []droppedField{
		{"license.secretKey", []string{"license", "secretKey"},
			map[string]interface{}{"license": map[string]interface{}{"secretName": "l", "secretKey": "k"}}},
		{"gossip.secretKey", []string{"gossip", "secretKey"},
			map[string]interface{}{"gossip": map[string]interface{}{"secretKey": "k"}}},
		{"server.extraConfig", []string{"server", "extraConfig"},
			map[string]interface{}{"server": map[string]interface{}{"extraConfig": "x"}}},
		{"server.acl.bootstrapSecretName", []string{"server", "acl", "bootstrapSecretName"},
			map[string]interface{}{"server": map[string]interface{}{"acl": map[string]interface{}{"bootstrapSecretName": "x"}}}},
		{"server.autopilot block", []string{"server", "autopilot"},
			map[string]interface{}{"server": map[string]interface{}{"autopilot": map[string]interface{}{"cleanupDeadServers": true}}}},
		{"server.audit.deliveryGuarantee", []string{"server", "audit", "deliveryGuarantee"},
			map[string]interface{}{"server": map[string]interface{}{"audit": map[string]interface{}{"deliveryGuarantee": "enforced"}}}},
		{"server.audit.format", []string{"server", "audit", "format"},
			map[string]interface{}{"server": map[string]interface{}{"audit": map[string]interface{}{"format": "json"}}}},
		{"server.audit.rotateDuration", []string{"server", "audit", "rotateDuration"},
			map[string]interface{}{"server": map[string]interface{}{"audit": map[string]interface{}{"rotateDuration": "24h"}}}},
		{"server.audit.rotateMaxFiles", []string{"server", "audit", "rotateMaxFiles"},
			map[string]interface{}{"server": map[string]interface{}{"audit": map[string]interface{}{"rotateMaxFiles": int64(15)}}}},
		{"affinity block", []string{"affinity"},
			map[string]interface{}{"affinity": map[string]interface{}{"podAntiAffinity": map[string]interface{}{"enabled": true}}}},
		{"monitoring.scrapeInterval", []string{"monitoring", "scrapeInterval"},
			map[string]interface{}{"monitoring": map[string]interface{}{"scrapeInterval": "30s"}}},
		{"monitoring.scrapeTimeout", []string{"monitoring", "scrapeTimeout"},
			map[string]interface{}{"monitoring": map[string]interface{}{"scrapeTimeout": "10s"}}},
		{"monitoring.additionalLabels", []string{"monitoring", "additionalLabels"},
			map[string]interface{}{"monitoring": map[string]interface{}{"additionalLabels": map[string]interface{}{"a": "b"}}}},
		{"openshift.monitoring block", []string{"openshift", "monitoring"},
			map[string]interface{}{"openshift": map[string]interface{}{"monitoring": map[string]interface{}{"enabled": true}}}},
		{"oidc block", []string{"oidc"},
			map[string]interface{}{"oidc": map[string]interface{}{"enabled": true}}},
	}

	create := func(name string, spec map[string]interface{}) (*unstructured.Unstructured, error) {
		// Ensure the minimal required field is present unless the case
		// already provides license.
		if _, ok := spec["license"]; !ok {
			spec["license"] = map[string]interface{}{"secretName": "l"}
		}
		u := &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": "nomad.hashicorp.com/v1alpha1",
			"kind":       "NomadCluster",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": spec,
		}}
		err := k8sClient.Create(ctx, u, &client.CreateOptions{
			Raw: &metav1.CreateOptions{FieldValidation: metav1.FieldValidationStrict},
		})
		return u, err
	}

	for i, df := range dropped {
		df := df
		It(fmt.Sprintf("prunes %s", df.name), func() {
			stored, err := create(fmt.Sprintf("dropped-%d", i), df.spec)
			Expect(err).NotTo(HaveOccurred())

			specPath := append([]string{"spec"}, df.fieldPath...)
			_, found, err := unstructured.NestedFieldNoCopy(stored.Object, specPath...)
			Expect(err).NotTo(HaveOccurred())
			Expect(found).To(BeFalse(),
				"dropped field %s should be pruned from the stored object", df.name)
		})
	}

	It("accepts and stores the minimal CR (negative control)", func() {
		stored, err := create("dropped-control", map[string]interface{}{})
		Expect(err).NotTo(HaveOccurred())
		_, found, err := unstructured.NestedFieldNoCopy(stored.Object, "spec", "license", "secretName")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue(), "kept field license.secretName must survive")
	})
})
