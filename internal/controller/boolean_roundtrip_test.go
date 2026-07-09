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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
)

// Pins BOTH failure directions of the default-true booleans against
// the real apiserver: plain bool + omitempty dropped explicit false
// (re-defaulted true on the operator's next write); plain bool without
// omitempty wrote false into fields the user never set. Pointer +
// omitempty must survive both round-trips through an operator-style
// update.
var _ = Describe("default-true boolean round-trips", func() {
	roundTrip := func(name string, set func(*nomadv1alpha1.NomadCluster)) *nomadv1alpha1.NomadCluster {
		ctx := context.Background()
		c := newTestCluster("default", name)
		set(c)
		Expect(k8sClient.Create(ctx, c)).To(Succeed())
		DeferCleanup(func() {
			got := &nomadv1alpha1.NomadCluster{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, got); err == nil {
				got.Finalizers = nil
				_ = k8sClient.Update(ctx, got)
				_ = k8sClient.Delete(ctx, got)
			}
		})
		// Operator-style write: mutate metadata, marshal the full
		// struct back — exactly the finalizer-add path.
		c.Finalizers = append(c.Finalizers, "test/round-trip")
		Expect(k8sClient.Update(ctx, c)).To(Succeed())
		got := &nomadv1alpha1.NomadCluster{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, got)).To(Succeed())
		return got
	}

	It("keeps absent fields enabled-by-default after an operator write", func() {
		got := roundTrip("rt-absent", func(c *nomadv1alpha1.NomadCluster) {
			c.Spec.Server.ACL.Enabled = nil
			c.Spec.Server.Audit.Enabled = nil
			c.Spec.Monitoring.Enabled = nil
		})
		Expect(got.Spec.Server.ACL.IsEnabled()).To(BeTrue())
		Expect(got.Spec.Server.Audit.IsEnabled()).To(BeTrue())
		Expect(got.Spec.Monitoring.IsEnabled()).To(BeTrue())
	})

	It("keeps explicit false through an operator write", func() {
		got := roundTrip("rt-false", func(c *nomadv1alpha1.NomadCluster) {
			c.Spec.Server.ACL.Enabled = ptr.To(false)
			c.Spec.Server.Audit.Enabled = ptr.To(false)
			c.Spec.Monitoring.Enabled = ptr.To(false)
		})
		Expect(got.Spec.Server.ACL.IsEnabled()).To(BeFalse())
		Expect(got.Spec.Server.Audit.IsEnabled()).To(BeFalse())
		Expect(got.Spec.Monitoring.IsEnabled()).To(BeFalse())
	})
})
