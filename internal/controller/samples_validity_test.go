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
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// Every file under config/samples must be admission-valid against the
// live CRD schema — samples are the first thing a user applies, and
// this suite pins them so they cannot silently drift from the API.
// The keyIDPrefix multi-transit rule is reconcile-time (operator-side,
// covered by the keyring unit tests), so admission success here does
// not imply reconcile validity for keyring HA shapes.
var _ = Describe("config/samples validity", func() {
	const ns = "samples-validity"

	BeforeEach(func() {
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}
		err := k8sClient.Create(context.Background(), namespace)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	It("applies every sample document successfully", func() {
		root := filepath.Join("..", "..", "config", "samples")
		var files []string
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasSuffix(path, ".yaml") &&
				filepath.Base(path) != "kustomization.yaml" {
				files = append(files, path)
			}
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(files).NotTo(BeEmpty(), "no sample files found — wrong path?")

		applied := 0
		for _, file := range files {
			raw, err := os.ReadFile(file)
			Expect(err).NotTo(HaveOccurred())
			for i, doc := range strings.Split(string(raw), "\n---") {
				obj := &unstructured.Unstructured{}
				if err := yaml.Unmarshal([]byte(doc), &obj.Object); err != nil {
					Fail(fmt.Sprintf("%s doc %d: unparseable YAML: %v", file, i, err))
				}
				if len(obj.Object) == 0 {
					continue // comment-only or empty document
				}
				obj.SetNamespace(ns)
				// Unique per-file names: samples reuse names across files.
				base := strings.ReplaceAll(strings.TrimSuffix(filepath.Base(file), ".yaml"), "_", "-")
				obj.SetName(fmt.Sprintf("%s-%d-%s", base, i, obj.GetName()))
				Expect(k8sClient.Create(context.Background(), obj)).To(Succeed(),
					"%s doc %d must pass admission", file, i)
				Expect(k8sClient.Delete(context.Background(), obj)).To(Succeed())
				applied++
			}
		}
		Expect(applied).To(BeNumerically(">=", 7),
			"expected at least the seven known samples to apply")
	})
})
