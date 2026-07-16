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
	"strings"

	"k8s.io/apimachinery/pkg/types"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
)

// Every README spec-invariant gets a rejection and an acceptance case
// against the real apiserver, so a marker regression cannot silently
// drop a rule. Transition CELs are covered in their own suites,
// except NomadAutoscaler clusterRef immutability, which is small
// enough to live alongside its create-time invariants below.
var _ = Describe("CRD admission invariants (neo-f7j)", func() {
	const namespace = "admission-invariants-test"
	ctx := context.Background()

	BeforeEach(func() {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
		if err := k8sClient.Create(ctx, ns); err != nil && !errors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	Describe("NomadCluster", func() {
		type tc struct {
			name    string
			mutate  func(*nomadv1alpha1.NomadCluster)
			wantErr string // empty = must be accepted
			verify  func(Gomega, *nomadv1alpha1.NomadCluster)
		}

		cases := []tc{
			{
				name:   "baseline valid cluster accepted (positive control)",
				mutate: func(*nomadv1alpha1.NomadCluster) {},
			},
			{
				name: "license with both secretName and value rejected",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.License.Value = "inline-license"
				},
				wantErr: "mutually exclusive",
			},
			{
				name: "license with neither secretName nor value rejected",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.License.SecretName = ""
				},
				wantErr: "either secretName or value",
			},
			{
				name: "license via inline value only accepted",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.License.SecretName = ""
					c.Spec.License.Value = "inline-license"
				},
			},
			{
				name:    "replicas=2 rejected by enum",
				mutate:  func(c *nomadv1alpha1.NomadCluster) { c.Spec.Replicas = 2 },
				wantErr: "Unsupported value",
			},
			{
				name:    "replicas=4 rejected by enum",
				mutate:  func(c *nomadv1alpha1.NomadCluster) { c.Spec.Replicas = 4 },
				wantErr: "Unsupported value",
			},
			{
				name:   "replicas=5 accepted",
				mutate: func(c *nomadv1alpha1.NomadCluster) { c.Spec.Replicas = 5 },
			},
			{
				name: "image tag with path separator rejected by pattern",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Image.Tag = "1.11/evil"
				},
				wantErr: "should match",
			},
			{
				name: "image tag with shell metacharacter rejected by pattern",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Image.Tag = "$(reboot)"
				},
				wantErr: "should match",
			},
			{
				name: "concrete patch tag accepted",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Image.Tag = "2.0.4-ent"
				},
			},
			{
				name: "malformed digest rejected by pattern",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Image.Digest = "sha256:nothex"
				},
				wantErr: "should match",
			},
			{
				name: "digest without sha256 prefix rejected",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Image.Digest = "md5:" + strings.Repeat("ab", 32)
				},
				wantErr: "should match",
			},
			{
				name: "well-formed digest accepted",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Image.Digest = "sha256:" + strings.Repeat("ab", 32)
				},
			},
			{
				name: "pullPolicy outside enum rejected",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Image.PullPolicy = corev1.PullPolicy("Sometimes")
				},
				wantErr: "Unsupported value",
			},
			{
				name: "external service type ClusterIP rejected",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Services.External.Type = corev1.ServiceTypeClusterIP
				},
				wantErr: "Unsupported value",
			},
			{
				name: "external service type NodePort accepted",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Services.External.Type = corev1.ServiceTypeNodePort
				},
			},
			{
				name: "transit auth with unknown method rejected",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{{
						Name: "badmethod",
						Transit: &nomadv1alpha1.TransitKeyring{
							Address: "https://vault:8200", KeyName: "nk", MountPath: "transit/",
							Auth: &nomadv1alpha1.TransitAuth{Method: "approle", Mount: "approle"},
						},
					}}
				},
				wantErr: "supported values",
			},
			{
				name: "transit auth method/block mismatch rejected",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{{
						Name: "mismatched",
						Transit: &nomadv1alpha1.TransitKeyring{
							Address: "https://vault:8200", KeyName: "nk", MountPath: "transit/",
							Auth: &nomadv1alpha1.TransitAuth{
								Method: "kubernetes", Mount: "kubernetes",
								Token: &nomadv1alpha1.TransitAuthToken{SecretRef: corev1.LocalObjectReference{Name: "tok"}},
							},
						},
					}}
				},
				wantErr: "per-method block",
			},
			{
				name: "transit token method accepted without mount",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{{
						Name: "static",
						Transit: &nomadv1alpha1.TransitKeyring{
							Address: "https://vault:8200", KeyName: "nk", MountPath: "transit/",
							Auth: &nomadv1alpha1.TransitAuth{
								Method: "token",
								Token:  &nomadv1alpha1.TransitAuthToken{SecretRef: corev1.LocalObjectReference{Name: "tok"}},
							},
						},
					}}
				},
			},
			{
				name: "transit jwt method without mount rejected",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{{
						Name: "nomount",
						Transit: &nomadv1alpha1.TransitKeyring{
							Address: "https://vault:8200", KeyName: "nk", MountPath: "transit/",
							Auth: &nomadv1alpha1.TransitAuth{
								Method: "jwt",
								JWT:    &nomadv1alpha1.TransitAuthKubernetes{Role: "nomad"},
							},
						},
					}}
				},
				wantErr: "mount is required",
			},
			{
				name: "transit auth alone accepted with defaults applied",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{{
						Name: "dynamic",
						Transit: &nomadv1alpha1.TransitKeyring{
							Address: "https://vault:8200", KeyName: "nk", MountPath: "transit/",
							Auth: &nomadv1alpha1.TransitAuth{
								Method: "jwt", Mount: "jwt",
								JWT: &nomadv1alpha1.TransitAuthKubernetes{Role: "nomad"},
							},
						},
					}}
				},
			},
			{
				name: "transit auth token expiration below floor rejected",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{{
						Name: "short",
						Transit: &nomadv1alpha1.TransitKeyring{
							Address: "https://vault:8200", KeyName: "nk", MountPath: "transit/",
							Auth: &nomadv1alpha1.TransitAuth{
								Method: "kubernetes", Mount: "kubernetes",
								Kubernetes: &nomadv1alpha1.TransitAuthKubernetes{
									Role: "nomad", TokenExpirationSeconds: 300,
								},
							},
						},
					}}
				},
				wantErr: "600",
			},
			{
				name: "keyring entry with no provider rejected",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{{Name: "empty"}}
				},
				wantErr: "exactly one of",
			},
			{
				name: "keyring entry with two providers rejected",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{{
						Name:   "both",
						AWSKMS: &nomadv1alpha1.AWSKMSKeyring{KMSKeyID: "alias/x"},
						Transit: &nomadv1alpha1.TransitKeyring{
							Address: "https://v:8200", KeyName: "k", MountPath: "transit/",
							Auth: &nomadv1alpha1.TransitAuth{
								Method: "token",
								Token:  &nomadv1alpha1.TransitAuthToken{SecretRef: corev1.LocalObjectReference{Name: "vt"}},
							},
						},
					}}
				},
				wantErr: "exactly one of",
			},
			{
				name: "duplicate keyring names rejected",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{
						{Name: "dup", AWSKMS: &nomadv1alpha1.AWSKMSKeyring{KMSKeyID: "alias/x"}},
						{Name: "dup", GCPCKMS: &nomadv1alpha1.GCPCKMSKeyring{Project: "p", Region: "r", KeyRing: "kr", CryptoKey: "ck"}},
					}
				},
				wantErr: "Duplicate value",
			},
			{
				name: "transit address without scheme rejected",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{{
						Name:    "bad",
						Transit: &nomadv1alpha1.TransitKeyring{Address: "vault:8200", KeyName: "k", MountPath: "transit/"},
					}}
				},
				wantErr: "should match",
			},
			{
				name: "valid HA keyring pair accepted",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Server.Keyrings = []nomadv1alpha1.KeyringEntry{
						{Name: "primary", Transit: &nomadv1alpha1.TransitKeyring{
							Address: "https://v:8200", KeyName: "k", MountPath: "transit/",
							Auth: &nomadv1alpha1.TransitAuth{
								Method: "token",
								Token:  &nomadv1alpha1.TransitAuthToken{SecretRef: corev1.LocalObjectReference{Name: "vt"}},
							},
						}},
						{Name: "dr", AWSKMS: &nomadv1alpha1.AWSKMSKeyring{KMSKeyID: "alias/nomad", Region: "eu-west-2"}},
					}
				},
			},
			{
				name: "reclaimPolicy defaults to Delete",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Persistence.ReclaimPolicy = ""
				},
				verify: func(g Gomega, c *nomadv1alpha1.NomadCluster) {
					g.Expect(c.Spec.Persistence.ReclaimPolicy).To(Equal("Delete"))
				},
			},
			{
				name: "reclaimPolicy outside enum rejected",
				mutate: func(c *nomadv1alpha1.NomadCluster) {
					c.Spec.Persistence.ReclaimPolicy = "Recycle"
				},
				wantErr: "Unsupported value",
			},
		}

		for i, c := range cases {
			name := fmt.Sprintf("adm-cluster-%d", i)
			It(c.name, func() {
				cluster := newTestCluster(namespace, name)
				c.mutate(cluster)

				err := k8sClient.Create(ctx, cluster)
				if c.wantErr == "" {
					Expect(err).NotTo(HaveOccurred())
					if c.verify != nil {
						stored := &nomadv1alpha1.NomadCluster{}
						Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, stored)).To(Succeed())
						c.verify(Default, stored)
					}
					Expect(k8sClient.Delete(ctx, cluster)).To(Succeed())
					return
				}
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(c.wantErr))
			})
		}
	})

	Describe("NomadSnapshot", func() {
		base := func(name string) *nomadv1alpha1.NomadSnapshot {
			return &nomadv1alpha1.NomadSnapshot{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec: nomadv1alpha1.NomadSnapshotSpec{
					ClusterRef: nomadv1alpha1.ClusterReference{Name: "some-cluster"},
					Target: nomadv1alpha1.SnapshotTarget{
						Local: &nomadv1alpha1.SnapshotLocalConfig{Size: "1Gi"},
					},
				},
			}
		}

		type tc struct {
			name    string
			mutate  func(*nomadv1alpha1.NomadSnapshot)
			wantErr string
		}

		cases := []tc{
			{
				name:   "baseline valid snapshot accepted (positive control)",
				mutate: func(*nomadv1alpha1.NomadSnapshot) {},
			},
			{
				name: "no storage target rejected by one-of rule",
				mutate: func(s *nomadv1alpha1.NomadSnapshot) {
					s.Spec.Target = nomadv1alpha1.SnapshotTarget{}
				},
				wantErr: "one of target",
			},
			{
				name: "negative retain rejected by minimum",
				mutate: func(s *nomadv1alpha1.NomadSnapshot) {
					s.Spec.Schedule = &nomadv1alpha1.SnapshotSchedule{Interval: "1h", Retain: -1}
				},
				wantErr: "should be greater than or equal to 1",
			},
			{
				name: "non-duration interval rejected by pattern",
				mutate: func(s *nomadv1alpha1.NomadSnapshot) {
					s.Spec.Schedule = &nomadv1alpha1.SnapshotSchedule{Interval: "1 fortnight", Retain: 24}
				},
				wantErr: "should match",
			},
			{
				name: "compound duration interval accepted",
				mutate: func(s *nomadv1alpha1.NomadSnapshot) {
					s.Spec.Schedule = &nomadv1alpha1.SnapshotSchedule{Interval: "1h30m", Retain: 24}
				},
			},
		}

		for i, c := range cases {
			name := fmt.Sprintf("adm-snapshot-%d", i)
			It(c.name, func() {
				snap := base(name)
				c.mutate(snap)

				err := k8sClient.Create(ctx, snap)
				if c.wantErr == "" {
					Expect(err).NotTo(HaveOccurred())
					Expect(k8sClient.Delete(ctx, snap)).To(Succeed())
					return
				}
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(c.wantErr))
			})
		}
	})

	Describe("NomadAutoscaler", func() {
		base := func(name string) *nomadv1alpha1.NomadAutoscaler {
			return &nomadv1alpha1.NomadAutoscaler{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec: nomadv1alpha1.NomadAutoscalerSpec{
					ClusterRef: nomadv1alpha1.ClusterReference{Name: "some-cluster"},
				},
			}
		}

		type tc struct {
			name    string
			mutate  func(*nomadv1alpha1.NomadAutoscaler)
			wantErr string
			verify  func(*nomadv1alpha1.NomadAutoscaler)
		}

		cases := []tc{
			{
				name:   "baseline minimal autoscaler accepted (positive control)",
				mutate: func(*nomadv1alpha1.NomadAutoscaler) {},
				verify: func(a *nomadv1alpha1.NomadAutoscaler) {
					Expect(a.Spec.Replicas).To(Equal(int32(1)), "replicas must default to 1")
					Expect(a.Spec.Namespaces).To(Equal([]string{"default"}), "namespaces must default to [default]")
					Expect(a.Spec.Image.Repository).To(Equal("hashicorp/nomad-autoscaler-enterprise"), "image must default to the enterprise repository")
					Expect(a.Spec.LogLevel).To(Equal("INFO"))
				},
			},
			{
				// 0 is the Go zero value and never serializes; -1 exercises
				// the same Minimum rule.
				name: "negative replicas rejected by minimum",
				mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
					a.Spec.Replicas = -1
				},
				wantErr: "should be greater than or equal to 1",
			},
			{
				name: "replicas above maximum rejected",
				mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
					a.Spec.Replicas = 4
				},
				wantErr: "should be less than or equal to 3",
			},
			{
				name: "wildcard alongside other namespaces rejected by CEL",
				mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
					a.Spec.Namespaces = []string{"*", "default"}
				},
				wantErr: "must be the only entry",
			},
			{
				name: "wildcard alone accepted",
				mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
					a.Spec.Namespaces = []string{"*"}
				},
			},
			{
				name: "invalid namespace name rejected by item pattern",
				mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
					a.Spec.Namespaces = []string{"not a namespace"}
				},
				wantErr: "should match",
			},
			{
				name: "invalid log level rejected by enum",
				mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
					a.Spec.LogLevel = "TRACE"
				},
				wantErr: "supported values",
			},
			{
				name: "malformed image digest rejected by pattern",
				mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
					a.Spec.Image.Digest = "sha256:short"
				},
				wantErr: "should match",
			},
			{
				name: "DAS without prometheusURL rejected by CEL",
				mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
					a.Spec.DynamicApplicationSizing.Enabled = true
				},
				wantErr: "prometheusURL is required",
			},
			{
				name: "DAS with prometheusURL accepted",
				mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
					a.Spec.DynamicApplicationSizing.Enabled = true
					a.Spec.DynamicApplicationSizing.PrometheusURL = "http://das-prometheus:9090"
				},
			},
			{
				name: "non-http prometheusURL rejected by pattern",
				mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
					a.Spec.DynamicApplicationSizing.Enabled = true
					a.Spec.DynamicApplicationSizing.PrometheusURL = "das-prometheus:9090"
				},
				wantErr: "should match",
			},
			{
				// The agent pod mounts the cluster's TLS Secret, which
				// pods cannot do across namespaces (neo-2um.13).
				name: "cross-namespace clusterRef rejected by CEL",
				mutate: func(a *nomadv1alpha1.NomadAutoscaler) {
					a.Spec.ClusterRef.Namespace = "elsewhere"
				},
				wantErr: "clusterRef.namespace is not supported",
			},
		}

		// Structural defaulting does not descend into an absent object,
		// so default={} on spec.image is what materialises the nested
		// image defaults for a YAML-applied CR that omits the block
		// (neo-2um.15). The typed client cannot express an absent struct
		// field (image:{} always serializes), hence unstructured.
		It("defaults the whole image block on an image-less CR", func() {
			u := &unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "nomad.hashicorp.com/v1alpha1",
				"kind":       "NomadAutoscaler",
				"metadata": map[string]interface{}{
					"name":      "adm-autoscaler-imageless",
					"namespace": namespace,
				},
				"spec": map[string]interface{}{
					"clusterRef": map[string]interface{}{"name": "some-cluster"},
				},
			}}
			Expect(k8sClient.Create(ctx, u)).To(Succeed())
			defer func() { Expect(k8sClient.Delete(ctx, u)).To(Succeed()) }()

			fetched := &nomadv1alpha1.NomadAutoscaler{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "adm-autoscaler-imageless", Namespace: namespace}, fetched)).To(Succeed())
			Expect(fetched.Spec.Image.PullPolicy).To(Equal(corev1.PullAlways),
				"the documented Always retag defence must survive an omitted image block")
			Expect(fetched.Spec.Image.Repository).To(Equal("hashicorp/nomad-autoscaler-enterprise"))
			Expect(fetched.Spec.Image.Tag).To(Equal("0.5.0-ent"))
		})

		// clusterRef transition rule (neo-2um.3): retargeting orphans
		// the previous cluster's ACL policy+token, so the reference is
		// frozen after create; replace-by-recreate is the supported path.
		It("rejects any spec.clusterRef change on update, accepts other field edits", func() {
			a := base("adm-autoscaler-clusterref")
			Expect(k8sClient.Create(ctx, a)).To(Succeed())
			defer func() { Expect(k8sClient.Delete(ctx, a)).To(Succeed()) }()

			key := types.NamespacedName{Name: a.Name, Namespace: namespace}

			fetched := &nomadv1alpha1.NomadAutoscaler{}
			Expect(k8sClient.Get(ctx, key, fetched)).To(Succeed())
			fetched.Spec.LogLevel = "DEBUG"
			Expect(k8sClient.Update(ctx, fetched)).To(Succeed(),
				"non-clusterRef spec edits must remain allowed")

			Expect(k8sClient.Get(ctx, key, fetched)).To(Succeed())
			fetched.Spec.ClusterRef.Name = "other-cluster"
			err := k8sClient.Update(ctx, fetched)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.clusterRef is immutable"))

			Expect(k8sClient.Get(ctx, key, fetched)).To(Succeed())
			fetched.Spec.ClusterRef.Namespace = "other-namespace"
			err = k8sClient.Update(ctx, fetched)
			Expect(err).To(HaveOccurred(),
				"a namespace change is also a retarget and must be rejected")
			Expect(err.Error()).To(ContainSubstring("spec.clusterRef is immutable"))
		})

		for i, c := range cases {
			name := fmt.Sprintf("adm-autoscaler-%d", i)
			It(c.name, func() {
				a := base(name)
				c.mutate(a)

				err := k8sClient.Create(ctx, a)
				if c.wantErr == "" {
					Expect(err).NotTo(HaveOccurred())
					if c.verify != nil {
						fetched := &nomadv1alpha1.NomadAutoscaler{}
						Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, fetched)).To(Succeed())
						c.verify(fetched)
					}
					Expect(k8sClient.Delete(ctx, a)).To(Succeed())
					return
				}
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(c.wantErr))
			})
		}
	})
})
