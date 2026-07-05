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

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/hashicorp/nomad-enterprise-operator/test/utils"
)

// namespace where the project is deployed in
const namespace = "nomad-enterprise-operator-system"

// serviceAccountName created for the project
const serviceAccountName = "nomad-enterprise-operator-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "nomad-enterprise-operator-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "nomad-enterprise-operator-metrics-binding"

// testClusterName is the name of the NomadCluster CR used in reconciliation tests
const testClusterName = "test-cluster"

// testSnapshotName is the name of the NomadSnapshot CR used in snapshot tests
const testSnapshotName = "test-snapshot"

// testSnapshotCR is the NomadSnapshot CR applied during snapshot tests.
// Uses local storage to avoid cloud dependencies in Kind.
const testSnapshotCR = `apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadSnapshot
metadata:
  name: test-snapshot
  namespace: nomad-enterprise-operator-system
spec:
  clusterRef:
    name: test-cluster
  schedule:
    interval: "1h"
    retain: 3
  target:
    local:
      size: 1Gi
`

// testClusterCR: replicas=1 for cheap Kind runs, fixed loadBalancerIP
// to skip the LB wait, audit enabled to exercise that path (its shape
// is operator-owned; specs assert the applied defaults).
const testClusterCR = `apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: test-cluster
  namespace: nomad-enterprise-operator-system
spec:
  replicas: 1
  image:
    repository: hashicorp/nomad
    tag: "2.0.3-ent"
  license:
    secretName: nomad-license
  monitoring:
    prometheusRulesEnabled: true
  services:
    external:
      type: LoadBalancer
      loadBalancerIP: "10.0.0.1"
  server:
    acl:
      enabled: true
    audit:
      enabled: true
`

// stripLeftoverFinalizers force-clears finalizers on any remaining
// NomadCluster/NomadSnapshot CRs in the namespace. Only for harness
// states where no operator exists to process them (aborted-run
// recovery and post-undeploy teardown) — never a substitute for real
// finalizer handling.
func stripLeftoverFinalizers(namespace string) {
	for _, crd := range []string{"nomadclusters", "nomadsnapshots"} {
		listCmd := exec.Command("kubectl", "get", crd+".nomad.hashicorp.com", "-n", namespace,
			"-o", "jsonpath={.items[*].metadata.name}")
		names, err := utils.Run(listCmd)
		if err != nil || strings.TrimSpace(names) == "" {
			continue // CRD absent or no leftovers
		}
		for _, name := range strings.Fields(names) {
			patchCmd := exec.Command("kubectl", "patch", crd+".nomad.hashicorp.com", name, "-n", namespace,
				"--type=merge", "-p", `{"metadata":{"finalizers":[]}}`)
			_, _ = utils.Run(patchCmd)
		}
	}
}

// nearExpiryCA builds a CA inside the operator's 30-day rotation
// window (neo-4s4), for seeding into a live cluster's <cluster>-ca
// Secret to trigger rotation.
func nearExpiryCA() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "e2e Near-Expiry CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

// envOr returns the environment variable's value, or fallback when it
// is unset or empty (matrix lanes pass UPGRADE_FROM/UPGRADE_TO).
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		// Tolerate AlreadyExists: the namespace survives aborted runs on
		// a reused kind cluster (neo-9eq re-entrance, same rationale as
		// the pre-clean sweep below).
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		if output, nsErr := utils.Run(cmd); nsErr != nil {
			Expect(output).To(ContainSubstring("already exists"),
				"Failed to create namespace: %s", output)
			// "already exists" can mean Terminating: a previous run's
			// teardown deletes the namespace asynchronously and a rerun
			// racing it would hit "namespace is being terminated" at
			// deploy time (neo-9eq). Wait it out, then recreate.
			phaseCmd := exec.Command("kubectl", "get", "ns", namespace, "-o", "jsonpath={.status.phase}")
			if phase, _ := utils.Run(phaseCmd); strings.Contains(phase, "Terminating") {
				// A Terminating namespace can only be stuck on CR
				// finalizers here — no operator runs inside a namespace
				// being deleted, so stripping them is the only unstick.
				stripLeftoverFinalizers(namespace)
				waitCmd := exec.Command("kubectl", "wait", "--for=delete", "ns/"+namespace, "--timeout=5m")
				_, waitErr := utils.Run(waitCmd)
				Expect(waitErr).NotTo(HaveOccurred(),
					"namespace %s stuck in Terminating — inspect finalizers manually", namespace)
				cmd = exec.Command("kubectl", "create", "ns", namespace)
				_, recreateErr := utils.Run(cmd)
				Expect(recreateErr).NotTo(HaveOccurred(), "Failed to recreate namespace after termination")
			}
		}

		By("labeling the namespace to enforce the restricted security policy (neo-8xu)")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("installing Prometheus Operator CRDs (vendored, neo-ru9)")
		// MonitoringPhase discovery-gates on these; without them the
		// PrometheusRule path is silently skipped and never e2e-tested.
		cmd = exec.Command("kubectl", "apply",
			"-f", "test/e2e/testdata/monitoring.coreos.com_servicemonitors.yaml",
			"-f", "test/e2e/testdata/monitoring.coreos.com_prometheusrules.yaml")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install Prometheus Operator CRDs")

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

		By("pre-cleaning leftovers from any aborted previous run (neo-9eq)")
		// The kind cluster survives failed runs for debugging; without
		// this sweep, a rerun trips over AlreadyExists (license secret)
		// or half-reconciled CRs. All deletes tolerate absence.
		for _, args := range [][]string{
			{"delete", "nomadsnapshot", "--all", "-n", namespace, "--ignore-not-found", "--timeout=2m"},
			{"delete", "nomadcluster", "--all", "-n", namespace, "--ignore-not-found", "--timeout=5m"},
			{"delete", "secret", "nomad-license", "dead-s3-creds", "-n", namespace, "--ignore-not-found"},
		} {
			cmd = exec.Command("kubectl", args...)
			_, _ = utils.Run(cmd) // best-effort: the namespace may not even exist yet
		}

		By("creating the license secret from test license file")
		projectDir, err := utils.GetProjectDir()
		Expect(err).NotTo(HaveOccurred())
		licensePath := filepath.Join(projectDir, "test", "e2e", "testdata", "nomad.hclic")
		_, err = os.Stat(licensePath)
		Expect(err).NotTo(HaveOccurred(),
			"License file not found at %s — place your Nomad Enterprise license there", licensePath)

		cmd = exec.Command("kubectl", "create", "secret", "generic", "nomad-license",
			"--namespace", namespace,
			fmt.Sprintf("--from-file=license=%s", licensePath))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create license secret")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace, "--ignore-not-found")
		_, _ = utils.Run(cmd)

		By("cleaning up the metrics ClusterRoleBinding")
		cmd = exec.Command("kubectl", "delete", "clusterrolebinding", metricsRoleBindingName, "--ignore-not-found")
		_, _ = utils.Run(cmd)

		By("draining CRs while the operator can still process finalizers (neo-9eq)")
		// Order matters: once the operator is undeployed, nothing clears
		// CR finalizers — deleting the namespace afterwards deadlocks it
		// in Terminating and hangs the whole binary to its -timeout.
		for _, crd := range []string{"nomadsnapshot", "nomadcluster"} {
			cmd = exec.Command("kubectl", "delete", crd, "--all", "-n", namespace,
				"--ignore-not-found", "--timeout=3m")
			_, _ = utils.Run(cmd)
		}
		stripLeftoverFinalizers(namespace)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace, "--timeout=3m")
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				// Get the name of the controller-manager pod
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=nomad-enterprise-operator-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
				"--dry-run=client", "-o", "yaml",
			)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to generate ClusterRoleBinding")
			applyCmd := exec.Command("kubectl", "apply", "-f", "-")
			applyCmd.Stdin = strings.NewReader(output)
			_, err = utils.Run(applyCmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply ClusterRoleBinding")

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("waiting for the metrics endpoint to be ready")
			verifyMetricsEndpointReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "endpoints", metricsServiceName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("8443"), "Metrics endpoint is not ready")
			}
			Eventually(verifyMetricsEndpointReady).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				// A5 flipped zap.Development=false, so the manager emits
				// JSON-format logs. The tab-separated text-format string the
				// kubebuilder scaffold originally generated no longer
				// appears. Match both formats so the assertion survives
				// development-vs-production logger toggles.
				g.Expect(output).To(SatisfyAny(
					ContainSubstring(`"logger":"controller-runtime.metrics"`),
					ContainSubstring("controller-runtime.metrics\tServing metrics server"),
				), "Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted).Should(Succeed())

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": ["curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics"],
							"securityContext": {
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccount": "%s"
					}
				}`, token, metricsServiceName, namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			metricsOutput := getMetricsOutput()
			Expect(metricsOutput).To(ContainSubstring(
				"controller_runtime_reconcile_total",
			))

			By("verifying domain-specific operator metrics are registered (F4 / neo-76n)")
			// AC-F4.3: each nomad_operator_* family must emit HELP/TYPE on
			// /metrics from startup, seeded by the empty-label children in
			// internal/metrics/metrics.go init(). Live scrape against a
			// real apiserver catches registration regressions that envtest
			// can't (envtest doesn't run the metrics server).
			for _, metricName := range []string{
				"nomad_operator_phase_duration_seconds",
				"nomad_operator_nomad_api_requests_total",
				"nomad_operator_cert_expiry_timestamp_seconds",
				"nomad_operator_license_expiry_timestamp_seconds",
				"nomad_operator_acl_bootstrap_failures_total",
				"nomad_operator_scale_down_in_progress",
				"nomad_operator_nomad_version_info",
			} {
				Expect(metricsOutput).To(ContainSubstring(metricName),
					"expected metric %q to appear in /metrics scrape output", metricName)
			}
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks
	})

	Context("NomadCluster reconciliation", Ordered, func() {
		BeforeAll(func() {
			By("applying the NomadCluster CR")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(testClusterCR)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply NomadCluster CR")
		})

		AfterAll(func() {
			By("deleting the NomadCluster CR")
			cmd := exec.Command("kubectl", "delete", "nomadcluster", testClusterName, "-n", namespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)

			By("waiting for owned resources to be cleaned up")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred(), "StatefulSet should be deleted")
			}, 2*time.Minute).Should(Succeed())
		})

		It("should create all expected Kubernetes resources", func() {
			By("waiting for the StatefulSet to be created (last resource in phase chain)")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "StatefulSet not yet created")
			}).Should(Succeed())

			By("verifying all reconciled resources exist")
			resources := []struct {
				kind string
				name string
			}{
				{"serviceaccount", testClusterName},
				{"role", testClusterName},
				{"rolebinding", testClusterName},
				{"secret", testClusterName + "-gossip"},
				{"secret", testClusterName + "-config"},
				{"service", testClusterName + "-headless"},
				{"service", testClusterName + "-internal"},
				{"service", testClusterName + "-external"},
				{"statefulset", testClusterName},
			}
			for _, r := range resources {
				cmd := exec.Command("kubectl", "get", r.kind, r.name, "-n", namespace)
				_, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred(), "%s %s should exist", r.kind, r.name)
			}
		})

		It("should apply correct labels to created resources", func() {
			cmd := exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace,
				"-o", "jsonpath={.metadata.labels}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var labels map[string]string
			Expect(json.Unmarshal([]byte(output), &labels)).To(Succeed())
			Expect(labels).To(HaveKeyWithValue("app.kubernetes.io/name", "nomad"))
			Expect(labels).To(HaveKeyWithValue("app.kubernetes.io/instance", testClusterName))
			Expect(labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "nomad-operator"))
			Expect(labels).To(HaveKeyWithValue("app.kubernetes.io/component", "server"))
		})

		It("should configure the StatefulSet correctly", func() {
			type check struct {
				jsonpath string
				expected string
				desc     string
			}
			checks := []check{
				{"{.spec.replicas}", "1", "replica count"},
				{"{.spec.template.spec.containers[0].image}", "hashicorp/nomad:2.0.3-ent", "container image"},
				{"{.spec.template.spec.serviceAccountName}", testClusterName, "service account"},
				{"{.spec.serviceName}", testClusterName + "-headless", "headless service name"},
				{"{.spec.podManagementPolicy}", "Parallel", "pod management policy"},
				{"{.spec.updateStrategy.type}", "RollingUpdate", "update strategy"},
			}
			for _, c := range checks {
				cmd := exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace,
					"-o", fmt.Sprintf("jsonpath=%s", c.jsonpath))
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				Expect(output).To(Equal(c.expected), "unexpected %s", c.desc)
			}

			By("verifying container command")
			cmd := exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace,
				"-o", `jsonpath={.spec.template.spec.containers[0].command}`)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("nomad"), "command should include nomad")
			Expect(output).To(ContainSubstring("agent"), "command should include agent")
			Expect(output).To(ContainSubstring("-config=/nomad/config"), "command should reference config path")

			By("verifying container ports")
			cmd = exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace,
				"-o", `jsonpath={.spec.template.spec.containers[0].ports}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("4646"), "http port missing")
			Expect(output).To(ContainSubstring("4647"), "rpc port missing")
			Expect(output).To(ContainSubstring("4648"), "serf port missing")

			By("verifying liveness probe")
			cmd = exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace,
				"-o", `jsonpath={.spec.template.spec.containers[0].livenessProbe.httpGet.path}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("/v1/agent/health"), "wrong liveness probe path")

			By("verifying readiness probe")
			cmd = exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace,
				"-o", `jsonpath={.spec.template.spec.containers[0].readinessProbe.httpGet.path}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("/v1/agent/health"), "wrong readiness probe path")

			By("verifying NOMAD_LICENSE env var references the license secret")
			cmd = exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace,
				"-o", `jsonpath={.spec.template.spec.containers[0].env}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("NOMAD_LICENSE"), "NOMAD_LICENSE env var missing")
			Expect(output).To(ContainSubstring("nomad-license"), "license secret reference missing")

			By("verifying volume mounts")
			cmd = exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace,
				"-o", `jsonpath={.spec.template.spec.containers[0].volumeMounts}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("/nomad/config"), "config volume mount missing")
			Expect(output).To(ContainSubstring("/nomad/data"), "data volume mount missing")
			Expect(output).To(ContainSubstring("/nomad/audit"), "audit volume mount missing")

			By("verifying data PVC in volume claim templates")
			cmd = exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace,
				"-o", `jsonpath={.spec.volumeClaimTemplates[0].metadata.name}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("data"), "data PVC name mismatch")

			cmd = exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace,
				"-o", `jsonpath={.spec.volumeClaimTemplates[0].spec.resources.requests.storage}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("10Gi"), "data PVC size mismatch")

			By("verifying audit PVC in volume claim templates")
			cmd = exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace,
				"-o", `jsonpath={.spec.volumeClaimTemplates[1].metadata.name}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("audit"), "audit PVC name mismatch")

			cmd = exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace,
				"-o", `jsonpath={.spec.volumeClaimTemplates[1].spec.resources.requests.storage}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("5Gi"), "audit PVC size mismatch")

			By("verifying config checksum annotation on pod template")
			cmd = exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace,
				"-o", `jsonpath={.spec.template.metadata.annotations.checksum/config}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "config checksum annotation should be set")

			By("verifying secrets checksum annotation on pod template")
			cmd = exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace,
				"-o", `jsonpath={.spec.template.metadata.annotations.checksum/secrets}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "secrets checksum annotation should be set")
		})

		It("should generate valid HCL in the ConfigMap", func() {
			cmd := exec.Command("sh", "-c", fmt.Sprintf(
				`kubectl get secret %s-config -n %s -o jsonpath='{.data.server\.hcl}' | base64 -d`,
				testClusterName, namespace))
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("server {"), "missing server block")
			Expect(output).To(ContainSubstring("bootstrap_expect = 1"), "wrong bootstrap_expect")
			Expect(output).To(ContainSubstring(`region`), "missing region")
			Expect(output).To(ContainSubstring(`"global"`), "missing global region value")
			Expect(output).To(ContainSubstring("encrypt ="), "missing gossip encrypt key")
			Expect(output).To(ContainSubstring("acl {"), "missing acl block")

			By("verifying audit configuration in HCL (ADR 0003 operator-owned shape)")
			Expect(output).To(ContainSubstring("audit {"), "missing audit block")
			Expect(output).To(ContainSubstring(`sink "file"`), "missing audit sink")
			Expect(output).To(ContainSubstring(`"json"`), "missing operator-owned audit format=json")
			Expect(output).To(ContainSubstring(`"24h"`), "missing operator-owned audit rotate_duration=24h")
			Expect(output).To(ContainSubstring("rotate_max_files   = 15"),
				"missing operator-owned audit rotate_max_files=15 (previously settable to 10 in fixture)")
			Expect(output).To(ContainSubstring("enforced"), "missing operator-owned audit delivery_guarantee=enforced")

			By("verifying autopilot configuration in HCL")
			Expect(output).To(ContainSubstring("autopilot {"), "missing autopilot block")
			Expect(output).To(ContainSubstring("cleanup_dead_servers"), "missing cleanup_dead_servers")

			By("verifying telemetry configuration in HCL")
			Expect(output).To(ContainSubstring("telemetry {"), "missing telemetry block")
			Expect(output).To(ContainSubstring("prometheus_metrics"), "missing prometheus_metrics")
		})

		It("should configure services with correct types and ports", func() {
			By("verifying headless service has ClusterIP=None and publishes not-ready addresses")
			cmd := exec.Command("kubectl", "get", "svc", testClusterName+"-headless", "-n", namespace,
				"-o", "jsonpath={.spec.clusterIP}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("None"))

			cmd = exec.Command("kubectl", "get", "svc", testClusterName+"-headless", "-n", namespace,
				"-o", "jsonpath={.spec.publishNotReadyAddresses}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("true"), "headless service should publish not-ready addresses")

			By("verifying headless service exposes http, rpc, and serf ports")
			cmd = exec.Command("kubectl", "get", "svc", testClusterName+"-headless", "-n", namespace,
				"-o", `jsonpath={.spec.ports[*].port}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("4646"), "headless missing http port")
			Expect(output).To(ContainSubstring("4647"), "headless missing rpc port")
			Expect(output).To(ContainSubstring("4648"), "headless missing serf port")

			By("verifying internal service is ClusterIP with http port only")
			cmd = exec.Command("kubectl", "get", "svc", testClusterName+"-internal", "-n", namespace,
				"-o", "jsonpath={.spec.type}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("ClusterIP"))

			cmd = exec.Command("kubectl", "get", "svc", testClusterName+"-internal", "-n", namespace,
				"-o", `jsonpath={.spec.ports[*].port}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("4646"), "internal missing http port")

			By("verifying external service is LoadBalancer with http and rpc ports")
			cmd = exec.Command("kubectl", "get", "svc", testClusterName+"-external", "-n", namespace,
				"-o", "jsonpath={.spec.type}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("LoadBalancer"))

			cmd = exec.Command("kubectl", "get", "svc", testClusterName+"-external", "-n", namespace,
				"-o", `jsonpath={.spec.ports[*].port}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("4646"), "external missing http port")
			Expect(output).To(ContainSubstring("4647"), "external missing rpc port")
		})

		It("should reach Running phase with all pods ready", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "cluster not yet Running, current phase: %s", output)
			}, 5*time.Minute).Should(Succeed())

			cmd := exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.readyReplicas}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("1"), "expected 1 ready replica")

			By("verifying Ready condition is True")
			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				`-o`, `jsonpath={.status.conditions[?(@.type=="Ready")].status}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("True"))

			By("verifying Ready is the ONLY condition type (C9 / AC-2.5.4)")
			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				`-o`, `jsonpath={.status.conditions[*].type}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("Ready"), "status.conditions must contain exactly the single Ready type")

			By("verifying replica counters in status sub-fields")
			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				`-o`, `jsonpath={.status.readyReplicas}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "readyReplicas should be set")

			By("verifying observedGeneration is set")
			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.observedGeneration}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "observedGeneration should be set")

			By("verifying lastReconcileTime is set")
			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.lastReconcileTime}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "lastReconcileTime should be set")
		})

		It("should expose infrastructure state in status sub-fields (C9 / AC-2.5.7)", func() {
			type fieldCheck struct {
				jsonPath string
				desc     string
			}
			checks := []fieldCheck{
				{`{.status.gossipKeySecretName}`, "gossip key secret name"},
				{`{.status.advertiseAddress}`, "advertise address"},
			}
			for _, c := range checks {
				cmd := exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
					"-o", "jsonpath="+c.jsonPath)
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				Expect(output).NotTo(BeEmpty(), "%s should be set", c.desc)
			}

			By("verifying gossip key secret name in status")
			cmd := exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.gossipKeySecretName}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal(testClusterName + "-gossip"))

			By("verifying advertise address in status")
			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.advertiseAddress}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("10.0.0.1"))
		})

		It("should bootstrap ACL and store token", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
					`-o`, `jsonpath={.status.aclBootstrapped}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"), "ACL not yet bootstrapped")
			}, 5*time.Minute).Should(Succeed())

			By("verifying ACL bootstrap status fields")
			cmd := exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.aclBootstrapped}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("true"))

			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.aclBootstrapSecretName}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal(testClusterName + "-acl-bootstrap"))

			By("verifying ACL bootstrap secret contains expected keys")
			cmd = exec.Command("kubectl", "get", "secret", testClusterName+"-acl-bootstrap", "-n", namespace,
				"-o", "jsonpath={.data}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("accessor-id"))
			Expect(output).To(ContainSubstring("secret-id"))

			By("verifying operatorStatusSecretName is set in cluster status")
			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.operatorStatusSecretName}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "operatorStatusSecretName should be set after ACL bootstrap")
			Expect(output).To(Equal(testClusterName+"-operator-status"),
				"operatorStatusSecretName should follow expected naming convention")

			By("verifying operatorStatusPolicyName is set in cluster status")
			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.operatorStatusPolicyName}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "operatorStatusPolicyName should be set after ACL bootstrap")
			Expect(output).To(Equal(testClusterName+"-operator-status"),
				"operatorStatusPolicyName should follow expected naming convention")

			By("verifying the operator status secret contains expected keys")
			cmd = exec.Command("kubectl", "get", "secret", testClusterName+"-operator-status", "-n", namespace,
				"-o", "jsonpath={.data.secret-id}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "operator status secret should contain a non-empty secret-id")

			By("verifying operatorManagementSecretName is set in cluster status (C4 / AC-2.4.4)")
			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.operatorManagementSecretName}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal(testClusterName+"-operator-management"),
				"operatorManagementSecretName should follow expected naming convention")

			By("verifying the operator management secret contains expected keys")
			cmd = exec.Command("kubectl", "get", "secret", testClusterName+"-operator-management", "-n", namespace,
				"-o", "jsonpath={.data.secret-id}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "operator management secret should contain a non-empty secret-id")
		})

		It("should enrich status with Nomad API data", func() {
			By("waiting for license status to be populated")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
					`-o`, `jsonpath={.status.license.valid}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"), "status.license.valid not yet true")
			}, 5*time.Minute).Should(Succeed())

			By("verifying license fields are populated")
			cmd := exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.license.valid}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("true"), "license should be valid")

			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.license.licenseId}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "licenseId should be populated")

			By("waiting for autopilot status to be populated")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
					`-o`, `jsonpath={.status.autopilot.healthy}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"), "status.autopilot.healthy not yet true")
			}, 5*time.Minute).Should(Succeed())

			By("verifying autopilot fields are populated")
			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.autopilot.healthy}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("true"), "autopilot should be healthy")

			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.autopilot.voters}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("1"), "should have 1 voter")

			By("verifying leader address is populated")
			// A6 (neo-tuo): the field was renamed from leaderID to
			// leaderAddress because it actually stores the leader's
			// host:port (RPC address), not the Raft server ID. For the
			// server ID, see status.autopilot.servers[].id.
			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.leaderAddress}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "leaderAddress should be populated")

			By("verifying currentReplicas is set")
			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.currentReplicas}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("1"), "currentReplicas should be 1")

			By("verifying InitialReconcileComplete Event was emitted (F5 / neo-76n)")
			// One-shot Event on first Ready=True: assert flag AND Event
			// — real-apiserver EventRecorder behaviour is what envtest
			// cannot exercise.
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
					"-o", "jsonpath={.status.initialReconcileEventEmitted}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"),
					"initialReconcileEventEmitted should be true once Ready=True")
			}).Should(Succeed())

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "events", "-n", namespace,
					"--field-selector",
					fmt.Sprintf("involvedObject.name=%s,involvedObject.kind=NomadCluster,reason=Reconciled",
						testClusterName),
					"-o", "jsonpath={.items[*].message}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("InitialReconcileComplete"),
					"expected an InitialReconcileComplete Event on the cluster")
			}).Should(Succeed())
		})

		It("should set the finalizer", func() {
			cmd := exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.metadata.finalizers[0]}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("nomad.hashicorp.com/finalizer"))
		})

		// NomadSnapshot tests — run while cluster is still healthy
		It("should reconcile a NomadSnapshot with local storage", func() {
			By("applying the NomadSnapshot CR")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(testSnapshotCR)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply NomadSnapshot CR")

			By("waiting for snapshot agent deployment to exist")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "deployment",
					testSnapshotName+"-snapshot-agent", "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Snapshot agent deployment not yet created")
			}).Should(Succeed())

			By("verifying all snapshot resources exist")
			resources := []struct {
				kind string
				name string
			}{
				{"configmap", testSnapshotName + "-snapshot-config"},
				{"secret", testSnapshotName + "-snapshot-token"},
				{"pvc", testSnapshotName + "-snapshots"},
				{"deployment", testSnapshotName + "-snapshot-agent"},
			}
			for _, r := range resources {
				cmd := exec.Command("kubectl", "get", r.kind, r.name, "-n", namespace)
				_, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred(), "%s %s should exist", r.kind, r.name)
			}
		})

		It("should configure the snapshot agent deployment correctly", func() {
			By("verifying container image matches the NomadCluster image")
			cmd := exec.Command("kubectl", "get", "deployment",
				testSnapshotName+"-snapshot-agent", "-n", namespace,
				"-o", `jsonpath={.spec.template.spec.containers[0].image}`)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("hashicorp/nomad:2.0.3-ent"), "snapshot agent should use same image as cluster")

			By("verifying container command runs snapshot agent")
			cmd = exec.Command("kubectl", "get", "deployment",
				testSnapshotName+"-snapshot-agent", "-n", namespace,
				"-o", `jsonpath={.spec.template.spec.containers[0].command}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("snapshot"), "command should include snapshot")
			Expect(output).To(ContainSubstring("agent"), "command should include agent")

			By("verifying config volume mount")
			cmd = exec.Command("kubectl", "get", "deployment",
				testSnapshotName+"-snapshot-agent", "-n", namespace,
				"-o", `jsonpath={.spec.template.spec.containers[0].volumeMounts}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("/config"), "config volume mount missing")

			By("verifying NOMAD_TOKEN env var references the token secret")
			cmd = exec.Command("kubectl", "get", "deployment",
				testSnapshotName+"-snapshot-agent", "-n", namespace,
				"-o", `jsonpath={.spec.template.spec.containers[0].env}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("NOMAD_TOKEN"), "NOMAD_TOKEN env var missing")
			Expect(output).To(ContainSubstring(testSnapshotName+"-snapshot-token"), "token secret reference missing")
		})

		It("should generate valid snapshot agent HCL config", func() {
			cmd := exec.Command("kubectl", "get", "configmap",
				testSnapshotName+"-snapshot-config", "-n", namespace,
				`-o`, `jsonpath={.data.snapshot\.hcl}`)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("snapshot {"), "missing snapshot block")
			Expect(output).To(ContainSubstring(`interval`), "missing interval")
			Expect(output).To(ContainSubstring(`retain`), "missing retain")
			Expect(output).To(ContainSubstring("local_storage {"), "missing local_storage block")
			Expect(output).To(ContainSubstring("/snapshots"), "missing snapshots path")
		})

		It("should reach Ready condition for snapshot agent", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadsnapshot", testSnapshotName, "-n", namespace,
					`-o`, `jsonpath={.status.conditions[?(@.type=="Ready")].status}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "snapshot agent not yet ready")
			}, 5*time.Minute).Should(Succeed())

			By("verifying snapshot status fields")
			cmd := exec.Command("kubectl", "get", "nomadsnapshot", testSnapshotName, "-n", namespace,
				"-o", "jsonpath={.status.deploymentName}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal(testSnapshotName + "-snapshot-agent"))

			cmd = exec.Command("kubectl", "get", "nomadsnapshot", testSnapshotName, "-n", namespace,
				"-o", "jsonpath={.status.configMapName}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal(testSnapshotName + "-snapshot-config"))

			cmd = exec.Command("kubectl", "get", "nomadsnapshot", testSnapshotName, "-n", namespace,
				"-o", "jsonpath={.status.tokenAccessorID}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "tokenAccessorID should be set")

			By("verifying nomadAddress is set in snapshot status")
			cmd = exec.Command("kubectl", "get", "nomadsnapshot", testSnapshotName, "-n", namespace,
				"-o", "jsonpath={.status.nomadAddress}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "nomadAddress should be set")

			By("verifying observedGeneration is set in snapshot status")
			cmd = exec.Command("kubectl", "get", "nomadsnapshot", testSnapshotName, "-n", namespace,
				"-o", "jsonpath={.status.observedGeneration}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "observedGeneration should be set")
		})

		It("should set the snapshot finalizer", func() {
			cmd := exec.Command("kubectl", "get", "nomadsnapshot", testSnapshotName, "-n", namespace,
				"-o", "jsonpath={.metadata.finalizers[0]}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("nomad.hashicorp.com/snapshot-cleanup"))
		})

		It("should clean up snapshot resources on CR deletion", func() {
			By("deleting the NomadSnapshot CR")
			cmd := exec.Command("kubectl", "delete", "nomadsnapshot", testSnapshotName, "-n", namespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying owned snapshot resources are deleted")
			ownedResources := []struct {
				kind string
				name string
			}{
				{"deployment", testSnapshotName + "-snapshot-agent"},
				{"configmap", testSnapshotName + "-snapshot-config"},
				{"secret", testSnapshotName + "-snapshot-token"},
				{"pvc", testSnapshotName + "-snapshots"},
			}
			for _, r := range ownedResources {
				Eventually(func(g Gomega) {
					cmd := exec.Command("kubectl", "get", r.kind, r.name, "-n", namespace)
					_, err := utils.Run(cmd)
					g.Expect(err).To(HaveOccurred(), "%s %s should be deleted", r.kind, r.name)
				}).Should(Succeed())
			}
		})

		// D3 (neo-kk7): one-shot mode smoke — spec.schedule omitted runs a
		// Job that takes a single snapshot and reaches phase=Succeeded.
		It("should complete a one-shot NomadSnapshot via a Job", func() {
			By("applying a NomadSnapshot CR without a schedule")
			oneShotCR := `apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadSnapshot
metadata:
  name: test-snapshot-oneshot
  namespace: nomad-enterprise-operator-system
spec:
  clusterRef:
    name: test-cluster
  target:
    local:
      size: 1Gi
`
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(oneShotCR)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply one-shot NomadSnapshot CR")

			By("verifying status reflects the Job operation")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadsnapshot", "test-snapshot-oneshot", "-n", namespace,
					"-o", "jsonpath={.status.operation}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Job"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for phase=Succeeded")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadsnapshot", "test-snapshot-oneshot", "-n", namespace,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"))
			}, 5*time.Minute, 10*time.Second).Should(Succeed())

			By("verifying lastSnapshot records the success")
			cmd = exec.Command("kubectl", "get", "nomadsnapshot", "test-snapshot-oneshot", "-n", namespace,
				"-o", "jsonpath={.status.lastSnapshot.status}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("Success"))

			By("verifying the stamped Nomad version matches the live cluster (same-version restore rule)")
			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.nomadVersion}")
			clusterVersion, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(clusterVersion).NotTo(BeEmpty())
			cmd = exec.Command("kubectl", "get", "nomadsnapshot", "test-snapshot-oneshot", "-n", namespace,
				"-o", "jsonpath={.status.lastSnapshot.nomadVersion} {.status.nomadVersion}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal(clusterVersion + " " + clusterVersion))

			By("cleaning up the one-shot NomadSnapshot")
			cmd = exec.Command("kubectl", "delete", "nomadsnapshot", "test-snapshot-oneshot", "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		// neo-bqd (a): the external-Secret watch pipeline end-to-end —
		// editing a user-referenced Secret must reconcile the cluster,
		// change the pod template's secrets checksum, and roll the pods.
		It("rolls pods when a referenced external Secret changes (neo-bqd)", func() {
			By("capturing the current secrets checksum")
			cmd := exec.Command("kubectl", "get", "statefulset", testClusterName, "-n", namespace,
				"-o", `jsonpath={.spec.template.metadata.annotations.checksum/secrets}`)
			before, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(before).NotTo(BeEmpty(), "secrets checksum annotation should be present")

			By("adding a canary key to the license Secret (content of the license key untouched)")
			cmd = exec.Command("kubectl", "patch", "secret", "nomad-license", "-n", namespace,
				"--type=merge", "-p", `{"stringData":{"rotation-canary":"1"}}`)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for the checksum to change (watch -> index -> checksum pipeline)")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", testClusterName, "-n", namespace,
					"-o", `jsonpath={.spec.template.metadata.annotations.checksum/secrets}`)
				after, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(after).NotTo(Equal(before), "secrets checksum should change after the Secret edit")
			}, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for the rolled pod to become Ready again")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
					"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].status}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"))
			}, 5*time.Minute, 10*time.Second).Should(Succeed())
		})

		// neo-bqd (b): AC-2.7.6a — patching a recurring snapshot's target
		// updates the agent config checksum and rolls the Deployment.
		It("rolls the snapshot agent Deployment when spec.target changes (neo-bqd / AC-2.7.6a)", func() {
			By("creating a recurring NomadSnapshot")
			rollCR := `apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadSnapshot
metadata:
  name: test-snapshot-roll
  namespace: nomad-enterprise-operator-system
spec:
  clusterRef:
    name: test-cluster
  schedule:
    interval: "1h"
    retain: 3
  target:
    local:
      size: 1Gi
`
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(rollCR)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for the agent Deployment and capturing its config checksum")
			var before string
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "deployment", "test-snapshot-roll-snapshot-agent", "-n", namespace,
					"-o", `jsonpath={.spec.template.metadata.annotations.checksum/config}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty())
				before = output
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("patching spec.target.local.path")
			cmd = exec.Command("kubectl", "patch", "nomadsnapshot", "test-snapshot-roll", "-n", namespace,
				"--type=merge", "-p", `{"spec":{"target":{"local":{"path":"/altpath"}}}}`)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for the Deployment template checksum to change")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "deployment", "test-snapshot-roll-snapshot-agent", "-n", namespace,
					"-o", `jsonpath={.spec.template.metadata.annotations.checksum/config}`)
				after, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(after).NotTo(Equal(before), "config checksum should change after a target edit")
			}, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("cleaning up")
			cmd = exec.Command("kubectl", "delete", "nomadsnapshot", "test-snapshot-roll", "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		// neo-ru9: the operator-shipped PrometheusRule exists on a live
		// cluster and carries the cert-lifecycle alerts.
		It("ships cert-lifecycle alerts in the PrometheusRule (neo-ru9)", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "prometheusrule", testClusterName, "-n", namespace,
					"-o", "jsonpath={.spec.groups[*].rules[*].alert}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				for _, alert := range []string{"NomadCACertExpiringSoon", "NomadCACertExpired",
					"NomadServerCertExpiringSoon", "NomadLicenseExpiringSoon",
					"NomadEvalsBlocked", "NomadPlanQueueBacklog", "NomadRaftCommitSlow"} {
					g.Expect(output).To(ContainSubstring(alert))
				}
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
		})

		// neo-4s4: automatic CA rotation end-to-end — seed a CA inside
		// the 30-day window and watch the operator introduce, cut over,
		// and reissue with the cluster Ready throughout.
		It("rotates a near-expiry CA with dual-trust overlap (neo-4s4)", func() {
			By("seeding a near-expiry CA into the cluster's CA secret")
			certPEM, keyPEM, err := nearExpiryCA()
			Expect(err).NotTo(HaveOccurred())
			seedYAML := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s-ca
  namespace: %s
type: Opaque
data:
  tls.crt: %s
  tls.key: %s
`, testClusterName, namespace,
				base64.StdEncoding.EncodeToString(certPEM),
				base64.StdEncoding.EncodeToString(keyPEM))
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(seedYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for rotation to complete (next CA promoted, old retained as previous)")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secret", testClusterName+"-ca", "-n", namespace,
					"-o", "jsonpath={.data.tls-previous\\.crt}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty(), "tls-previous.crt should hold the retired CA after cutover")

				cmd = exec.Command("kubectl", "get", "secret", testClusterName+"-ca", "-n", namespace,
					"-o", "jsonpath={.data.tls-next\\.crt}")
				output, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(BeEmpty(), "tls-next.crt should be gone once promoted")
			}, 10*time.Minute, 10*time.Second).Should(Succeed())

			By("verifying the promoted CA is long-lived and status reflects it")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
					"-o", "jsonpath={.status.certificateAuthority.expiryTime}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				expiry, perr := time.Parse(time.RFC3339, output)
				g.Expect(perr).NotTo(HaveOccurred())
				g.Expect(expiry.After(time.Now().Add(365*24*time.Hour))).To(BeTrue(),
					"promoted CA should be a fresh 2-year CA, got expiry %s", output)
			}, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying both rotation Events were emitted")
			for _, reason := range []string{"CARotationStarted", "CARotationCompleted"} {
				cmd := exec.Command("kubectl", "get", "events", "-n", namespace,
					"--field-selector", "reason="+reason, "-o", "jsonpath={.items[*].reason}")
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				Expect(output).To(ContainSubstring(reason))
			}

			By("verifying the cluster returned to Ready on the rotated trust")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
					"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].status}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"))
			}, 5*time.Minute, 10*time.Second).Should(Succeed())
		})

		// neo-bqd (c): the CRD contract enforced by the real kind
		// apiserver — invalid CRs are rejected at admission.
		It("rejects invalid CRs at admission (neo-bqd)", func() {
			By("rejecting replicas outside the 1/3/5 enum")
			badCluster := `apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: bad-replicas
  namespace: nomad-enterprise-operator-system
spec:
  replicas: 2
  license:
    secretName: nomad-license
`
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(badCluster)
			output, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "replicas=2 must be rejected, got: %s", output)

			By("rejecting a NomadSnapshot with no storage target")
			badSnapshot := `apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadSnapshot
metadata:
  name: bad-target
  namespace: nomad-enterprise-operator-system
spec:
  clusterRef:
    name: test-cluster
  target: {}
`
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(badSnapshot)
			output, err = utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "empty target must be rejected, got: %s", output)
		})

		// neo-bqd (d): one-shot failure path on a real cluster — an
		// unreachable S3 endpoint drives the Job to Failed with the
		// Degraded condition and the SnapshotDegraded Warning Event.
		It("surfaces a failed one-shot snapshot as phase=Failed with Degraded (neo-bqd)", func() {
			By("creating fake S3 credentials and a one-shot snapshot with a dead endpoint")
			cmd := exec.Command("kubectl", "create", "secret", "generic", "dead-s3-creds", "-n", namespace,
				"--from-literal=AWS_ACCESS_KEY_ID=x", "--from-literal=AWS_SECRET_ACCESS_KEY=y")
			_, _ = utils.Run(cmd) // tolerate AlreadyExists on rerun

			failCR := `apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadSnapshot
metadata:
  name: test-snapshot-fail
  namespace: nomad-enterprise-operator-system
spec:
  clusterRef:
    name: test-cluster
  target:
    s3:
      bucket: no-such-bucket
      region: eu-west-1
      endpoint: "http://127.0.0.1:1"
      forcePathStyle: true
      credentialsSecretRef:
        name: dead-s3-creds
`
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(failCR)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for phase=Failed after the Job exhausts its retries")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadsnapshot", "test-snapshot-fail", "-n", namespace,
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Failed"))
			}, 8*time.Minute, 15*time.Second).Should(Succeed())

			By("verifying the Degraded condition is True")
			cmd = exec.Command("kubectl", "get", "nomadsnapshot", "test-snapshot-fail", "-n", namespace,
				"-o", `jsonpath={.status.conditions[?(@.type=="Degraded")].status}`)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("True"))

			By("verifying the SnapshotDegraded Warning Event was emitted")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace,
				"--field-selector", "reason=SnapshotDegraded",
				"-o", "jsonpath={.items[*].reason}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("SnapshotDegraded"))

			By("cleaning up")
			cmd = exec.Command("kubectl", "delete", "nomadsnapshot", "test-snapshot-fail", "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should clean up resources on CR deletion", func() {
			By("deleting the NomadCluster CR")
			cmd := exec.Command("kubectl", "delete", "nomadcluster", testClusterName, "-n", namespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying owned resources are deleted")
			ownedResources := []struct {
				kind string
				name string
			}{
				{"statefulset", testClusterName},
				{"secret", testClusterName + "-config"},
				{"secret", testClusterName + "-gossip"},
				{"secret", testClusterName + "-acl-bootstrap"},
			}
			for _, r := range ownedResources {
				Eventually(func(g Gomega) {
					cmd := exec.Command("kubectl", "get", r.kind, r.name, "-n", namespace)
					_, err := utils.Run(cmd)
					g.Expect(err).To(HaveOccurred(), "%s %s should be deleted", r.kind, r.name)
				}).Should(Succeed())
			}

			By("verifying operator status secret is cleaned up after cluster deletion")
			Eventually(func() error {
				cmd = exec.Command("kubectl", "get", "secret", testClusterName+"-operator-status", "-n", namespace)
				_, err = utils.Run(cmd)
				return err
			}, time.Minute, time.Second*5).Should(HaveOccurred(),
				"operator status secret should be deleted with the cluster")

			By("verifying operator management secret is cleaned up after cluster deletion (C4)")
			Eventually(func() error {
				cmd = exec.Command("kubectl", "get", "secret", testClusterName+"-operator-management", "-n", namespace)
				_, err = utils.Run(cmd)
				return err
			}, time.Minute, time.Second*5).Should(HaveOccurred(),
				"operator management secret should be deleted with the cluster")

			By("verifying license secret still exists (not owned by CR)")
			cmd = exec.Command("kubectl", "get", "secret", "nomad-license", "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "License secret should still exist")
		})
	})

	Context("NomadCluster with operator-managed TLS", Ordered, func() {
		const opTLSClusterName = "tls-operator-cluster"

		BeforeAll(func() {
			cr := fmt.Sprintf(`apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  image:
    repository: hashicorp/nomad
    tag: "2.0.3-ent"
  license:
    secretName: nomad-license
  services:
    external:
      type: LoadBalancer
      loadBalancerIP: "10.0.0.2"
  server:
    acl:
      enabled: false
    audit:
      enabled: false
`, opTLSClusterName, namespace)

			By("applying the operator-managed TLS NomadCluster CR")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(cr)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply operator-managed TLS NomadCluster CR")
		})

		AfterAll(func() {
			By("deleting the operator-managed TLS NomadCluster CR")
			cmd := exec.Command("kubectl", "delete", "nomadcluster", opTLSClusterName, "-n", namespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "sts", opTLSClusterName, "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred(), "StatefulSet should be deleted")
			}, 2*time.Minute).Should(Succeed())
		})

		It("should create operator-generated CA secret", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secret", opTLSClusterName+"-ca", "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "CA secret not yet created")
			}).Should(Succeed())
		})

		It("should create server TLS secret", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secret", opTLSClusterName+"-tls", "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Server TLS secret not yet created")
			}).Should(Succeed())
		})

		It("should create CA bundle ConfigMap", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "configmap", opTLSClusterName+"-ca-bundle", "-n", namespace,
					"-o", "jsonpath={.data}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("ca.crt"), "CA bundle ConfigMap missing ca.crt key")
			}).Should(Succeed())
		})

		It("should set certificateAuthority status to operator-generated", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", opTLSClusterName, "-n", namespace,
					"-o", "jsonpath={.status.certificateAuthority.source}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("operator-generated"))
			}).Should(Succeed())

			cmd := exec.Command("kubectl", "get", "nomadcluster", opTLSClusterName, "-n", namespace,
				"-o", "jsonpath={.status.certificateAuthority.expiryTime}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "expiryTime should be set")
		})

		It("should reference operator-managed TLS secret in StatefulSet volume", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "sts", opTLSClusterName, "-n", namespace,
					"-o", `jsonpath={.spec.template.spec.volumes}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring(opTLSClusterName+"-tls"),
					"StatefulSet TLS volume should reference operator-managed secret")
			}).Should(Succeed())
		})

		It("should generate HCL with operator-managed TLS paths", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("sh", "-c", fmt.Sprintf(
					`kubectl get secret %s-config -n %s -o jsonpath='{.data.server\.hcl}' | base64 -d`,
					opTLSClusterName, namespace))
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("tls {"), "missing tls block")
				g.Expect(output).To(ContainSubstring(`cert_file = "/nomad/tls/tls.crt"`), "wrong cert_file path")
				g.Expect(output).To(ContainSubstring(`key_file  = "/nomad/tls/tls.key"`), "wrong key_file path")
				g.Expect(output).To(ContainSubstring("verify_server_hostname = true"), "missing verify_server_hostname")
				g.Expect(output).To(ContainSubstring("verify_https_client    = false"), "verify_https_client should be false")
			}).Should(Succeed())
		})
	})

	Context("NomadCluster with user-provided CA", Ordered, func() {
		const userCAClusterName = "tls-user-ca-cluster"
		const userCASecretName = "nomad-user-ca"

		BeforeAll(func() {
			By("generating a CA for the user-provided CA test")
			caKeyECDSA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())

			caTemplate := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: "User Test CA"},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			}
			caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKeyECDSA.PublicKey, caKeyECDSA)
			Expect(err).NotTo(HaveOccurred())
			caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
			caKeyDER, err := x509.MarshalECPrivateKey(caKeyECDSA)
			Expect(err).NotTo(HaveOccurred())
			caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER})

			By("creating the user CA secret")
			secretYAML := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque
data:
  tls.crt: %s
  tls.key: %s
`, userCASecretName, namespace,
				base64Encode(caCertPEM),
				base64Encode(caKeyPEM))

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(secretYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create user CA secret")

			cr := fmt.Sprintf(`apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  image:
    repository: hashicorp/nomad
    tag: "2.0.3-ent"
  license:
    secretName: nomad-license
  services:
    external:
      type: LoadBalancer
      loadBalancerIP: "10.0.0.3"
  server:
    acl:
      enabled: false
    tls:
      ca:
        secretName: %s
    audit:
      enabled: false
`, userCAClusterName, namespace, userCASecretName)

			By("applying the user-provided CA NomadCluster CR")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(cr)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply user-provided CA NomadCluster CR")
		})

		AfterAll(func() {
			By("deleting the user-provided CA NomadCluster CR")
			cmd := exec.Command("kubectl", "delete", "nomadcluster", userCAClusterName, "-n", namespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "sts", userCAClusterName, "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred(), "StatefulSet should be deleted")
			}, 2*time.Minute).Should(Succeed())

			By("deleting the user CA secret")
			cmd = exec.Command("kubectl", "delete", "secret", userCASecretName, "-n", namespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should create server TLS secret issued from user CA", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secret", userCAClusterName+"-tls", "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Server TLS secret not yet created")
			}).Should(Succeed())
		})

		It("should issue server cert with EC key matching the CA", func() {
			cmd := exec.Command("kubectl", "get", "secret", userCAClusterName+"-tls", "-n", namespace,
				"-o", `jsonpath={.data.tls\.key}`)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			keyPEM, err := base64.StdEncoding.DecodeString(output)
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(keyPEM)
			Expect(block).NotTo(BeNil(), "Failed to decode server key PEM")
			Expect(block.Type).To(Equal("EC PRIVATE KEY"), "Server key should be EC to match EC CA")
		})

		It("should NOT create an operator-generated CA secret", func() {
			cmd := exec.Command("kubectl", "get", "secret", userCAClusterName+"-ca", "-n", namespace)
			_, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "Operator-generated CA secret should NOT exist when user CA is provided")
		})

		It("should create CA bundle ConfigMap", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "configmap", userCAClusterName+"-ca-bundle", "-n", namespace,
					"-o", "jsonpath={.data}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("ca.crt"))
			}).Should(Succeed())
		})

		It("should set certificateAuthority status to user-provided", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", userCAClusterName, "-n", namespace,
					"-o", "jsonpath={.status.certificateAuthority.source}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("user-provided"))
			}).Should(Succeed())
		})
	})

	Context("NomadCluster with RSA user-provided CA", Ordered, func() {
		const rsaCAClusterName = "tls-rsa-ca-cluster"
		const rsaCASecretName = "nomad-rsa-ca"

		BeforeAll(func() {
			By("generating an RSA CA for the user-provided CA test")
			rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())

			caTemplate := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: "User RSA Test CA"},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			}
			caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &rsaKey.PublicKey, rsaKey)
			Expect(err).NotTo(HaveOccurred())
			caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
			caKeyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
			})

			By("creating the RSA CA secret")
			secretYAML := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
type: kubernetes.io/tls
data:
  tls.crt: %s
  tls.key: %s
`, rsaCASecretName, namespace,
				base64Encode(caCertPEM),
				base64Encode(caKeyPEM))

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(secretYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create RSA CA secret")

			cr := fmt.Sprintf(`apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  image:
    repository: hashicorp/nomad
    tag: "2.0.3-ent"
  license:
    secretName: nomad-license
  services:
    external:
      type: LoadBalancer
      loadBalancerIP: "10.0.0.4"
  server:
    acl:
      enabled: false
    tls:
      ca:
        secretName: %s
    audit:
      enabled: false
`, rsaCAClusterName, namespace, rsaCASecretName)

			By("applying the RSA CA NomadCluster CR")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(cr)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply RSA CA NomadCluster CR")
		})

		AfterAll(func() {
			By("deleting the RSA CA NomadCluster CR")
			cmd := exec.Command("kubectl", "delete", "nomadcluster", rsaCAClusterName, "-n", namespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "sts", rsaCAClusterName, "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred(), "StatefulSet should be deleted")
			}, 2*time.Minute).Should(Succeed())

			By("deleting the RSA CA secret")
			cmd = exec.Command("kubectl", "delete", "secret", rsaCASecretName, "-n", namespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should create server TLS secret from RSA CA", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secret", rsaCAClusterName+"-tls", "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Server TLS secret not yet created")
			}).Should(Succeed())
		})

		It("should issue server cert with RSA key matching the CA", func() {
			cmd := exec.Command("kubectl", "get", "secret", rsaCAClusterName+"-tls", "-n", namespace,
				"-o", `jsonpath={.data.tls\.key}`)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			keyPEM, err := base64.StdEncoding.DecodeString(output)
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(keyPEM)
			Expect(block).NotTo(BeNil(), "Failed to decode server key PEM")
			Expect(block.Type).To(Equal("RSA PRIVATE KEY"), "Server key should be RSA to match RSA CA")
		})

		It("should set certificateAuthority status to user-provided", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", rsaCAClusterName, "-n", namespace,
					"-o", "jsonpath={.status.certificateAuthority.source}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("user-provided"))
			}).Should(Succeed())
		})
	})

	// openshift.enabled without Route CRDs must warn and skip, not
	// error — kind has no Route CRDs, so the scenario falls out
	// naturally with a real REST mapper.
	Context("NomadCluster with openshift.enabled on a non-OpenShift cluster", Ordered, func() {
		const openshiftClusterName = "openshift-test"
		openshiftClusterCR := fmt.Sprintf(`apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  image:
    repository: hashicorp/nomad
    tag: "2.0.3-ent"
  license:
    secretName: nomad-license
  services:
    external:
      type: LoadBalancer
      loadBalancerIP: "10.0.0.3"
  openshift:
    enabled: true
    route:
      enabled: true
`, openshiftClusterName, namespace)

		BeforeAll(func() {
			By("applying the openshift-enabled NomadCluster CR")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(openshiftClusterCR)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply openshift-enabled NomadCluster CR")
		})

		AfterAll(func() {
			By("deleting the openshift-enabled NomadCluster CR")
			cmd := exec.Command("kubectl", "delete", "nomadcluster", openshiftClusterName,
				"-n", namespace, "--ignore-not-found", "--wait=true", "--timeout=2m")
			_, _ = utils.Run(cmd)
		})

		It("should emit a RouteCRDMissing Warning Event and skip Route creation", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "events", "-n", namespace,
					"--field-selector",
					fmt.Sprintf("involvedObject.name=%s,involvedObject.kind=NomadCluster,reason=RouteCRDMissing",
						openshiftClusterName),
					"-o", "jsonpath={.items[*].type}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("Warning"),
					"expected a Warning RouteCRDMissing Event on the cluster")
			}, 3*time.Minute).Should(Succeed())
		})
	})

	// reclaimPolicy=Delete must actually remove the data PVC — e2e
	// proves the kubelet+KCM finalizer chain releases it, which envtest
	// cannot.
	Context("NomadCluster with reclaimPolicy=Delete", Ordered, func() {
		const reclaimClusterName = "reclaim-test"
		reclaimClusterCR := fmt.Sprintf(`apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  image:
    repository: hashicorp/nomad
    tag: "2.0.3-ent"
  license:
    secretName: nomad-license
  services:
    external:
      type: LoadBalancer
      loadBalancerIP: "10.0.0.4"
  persistence:
    reclaimPolicy: Delete
`, reclaimClusterName, namespace)
		pvcName := "data-" + reclaimClusterName + "-0"

		JustAfterEach(func() {
			if !CurrentSpecReport().Failed() {
				return
			}
			for _, args := range [][]string{
				{"get", "nomadcluster", reclaimClusterName, "-n", namespace, "-o", "yaml"},
				{"get", "sts,pods,pvc", "-n", namespace, "-l", "app.kubernetes.io/instance=" + reclaimClusterName},
				{"get", "events", "-n", namespace,
					"--field-selector", "involvedObject.name=" + reclaimClusterName,
					"--sort-by", ".lastTimestamp"},
			} {
				out, _ := utils.Run(exec.Command("kubectl", args...))
				_, _ = fmt.Fprintf(GinkgoWriter, "--- kubectl %v ---\n%s\n", args, out)
			}
			out, _ := utils.Run(exec.Command("sh", "-c",
				"kubectl logs -n "+namespace+" deploy/nomad-enterprise-operator-controller-manager --tail=400"+
					" | grep -E 'reclaim-test|deletion|Waiting for StatefulSet' | tail -60"))
			_, _ = fmt.Fprintf(GinkgoWriter, "--- operator log (deletion path) ---\n%s\n", out)
		})

		BeforeAll(func() {
			By("applying the reclaimPolicy=Delete NomadCluster CR")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(reclaimClusterCR)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply reclaim-test NomadCluster CR")
		})

		It("should provision the data PVC then remove it on cluster delete", func() {
			By("waiting for the data PVC to be provisioned by the StatefulSet")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pvc", pvcName, "-n", namespace,
					"-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal(pvcName))
			}, 5*time.Minute).Should(Succeed())

			By("deleting the NomadCluster CR to trigger the finalizer's reclaim path")
			cmd := exec.Command("kubectl", "delete", "nomadcluster", reclaimClusterName,
				"-n", namespace, "--wait=true", "--timeout=3m")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "NomadCluster delete should complete within timeout")

			By("verifying the data PVC has been deleted")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pvc", pvcName, "-n", namespace,
					"--ignore-not-found", "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(BeEmpty(), "PVC %q should be deleted with reclaimPolicy=Delete", pvcName)
			}, 2*time.Minute).Should(Succeed())
		})
	})

	// Raft-aware scale-down against real Nomad: 3 -> 1, serial peer
	// removal, STS patched last, PVCs preserved. The opt-in annotation
	// is set up-front to satisfy the sub-3 floor gate.
	Context("NomadCluster scale-down (D2b)", Ordered, func() {
		const scaleDownClusterName = "scaledown-test"
		scaleDownClusterCR := fmt.Sprintf(`apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: %s
  namespace: %s
  annotations:
    nomad.hashicorp.com/accept-degraded-quorum: "true"
spec:
  replicas: 3
  image:
    repository: hashicorp/nomad
    tag: "2.0.3-ent"
  license:
    secretName: nomad-license
  services:
    external:
      type: LoadBalancer
      loadBalancerIP: "10.0.0.5"
  server:
    acl:
      enabled: true
`, scaleDownClusterName, namespace)

		BeforeAll(func() {
			By("applying the 3-replica NomadCluster CR")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(scaleDownClusterCR)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to apply scale-down NomadCluster CR")
		})

		AfterAll(func() {
			By("deleting the scale-down NomadCluster CR")
			cmd := exec.Command("kubectl", "delete", "nomadcluster", scaleDownClusterName,
				"-n", namespace, "--ignore-not-found", "--wait=true", "--timeout=3m")
			_, _ = utils.Run(cmd)
		})

		It("removes peers serially, patches the STS, and preserves PVCs (AC-2.3.4/4b/4c/7)", func() {
			By("waiting for autopilot to report healthy (3-server cluster fully formed)")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", scaleDownClusterName, "-n", namespace,
					"-o", `jsonpath={.status.autopilot.healthy}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"),
					"status.autopilot.healthy must be true before scale-down can proceed")
			}, 10*time.Minute).Should(Succeed())

			By("verifying initial state: STS has 3 replicas, status.scaleDown is nil")
			cmd := exec.Command("kubectl", "get", "statefulset", scaleDownClusterName, "-n", namespace,
				"-o", "jsonpath={.spec.replicas}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("3"), "STS should start at 3 replicas")

			cmd = exec.Command("kubectl", "get", "nomadcluster", scaleDownClusterName, "-n", namespace,
				"-o", "jsonpath={.status.scaleDown}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(BeEmpty(), "status.scaleDown should be nil at baseline")

			By("patching spec.replicas from 3 to 1 to trigger scale-down")
			cmd = exec.Command("kubectl", "patch", "nomadcluster", scaleDownClusterName,
				"-n", namespace, "--type", "merge", "-p", `{"spec":{"replicas":1}}`)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to patch spec.replicas")

			By("waiting for the operator to drive sts.spec.replicas down to 1")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", scaleDownClusterName, "-n", namespace,
					"-o", "jsonpath={.spec.replicas}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("1"),
					"sts.spec.replicas should reach 1 after scale-down completes")
			}, 5*time.Minute).Should(Succeed())

			By("verifying status.scaleDown was cleared at completion (AC-2.3.7)")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", scaleDownClusterName, "-n", namespace,
					"-o", "jsonpath={.status.scaleDown}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(BeEmpty(),
					"status.scaleDown should be cleared once the operation completes")
			}, 1*time.Minute).Should(Succeed())

			By("verifying PVCs for removed ordinals 1 and 2 survive (AC-2.3.4c)")
			for _, ordinal := range []string{"1", "2"} {
				pvcName := fmt.Sprintf("data-%s-%s", scaleDownClusterName, ordinal)
				cmd := exec.Command("kubectl", "get", "pvc", pvcName, "-n", namespace,
					"-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred(),
					"PVC %q must still exist after scale-down (reclaimPolicy governs cluster-delete only)", pvcName)
				Expect(output).To(Equal(pvcName))
			}
		})

		// neo-i4a: scale-UP after scale-down — proves the README claim
		// that preserved PVCs re-attach and peers rejoin the quorum.
		It("scales back up to 3 re-attaching the preserved PVCs (neo-i4a)", func() {
			By("capturing the preserved PVC UIDs before scale-up")
			pvcUIDs := map[string]string{}
			for _, ordinal := range []string{"1", "2"} {
				pvcName := fmt.Sprintf("data-%s-%s", scaleDownClusterName, ordinal)
				cmd := exec.Command("kubectl", "get", "pvc", pvcName, "-n", namespace,
					"-o", "jsonpath={.metadata.uid}")
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				Expect(output).NotTo(BeEmpty())
				pvcUIDs[pvcName] = output
			}

			By("patching spec.replicas back to 3")
			cmd := exec.Command("kubectl", "patch", "nomadcluster", scaleDownClusterName, "-n", namespace,
				"--type=merge", "-p", `{"spec":{"replicas":3}}`)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for the StatefulSet to reach 3 ready replicas")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", scaleDownClusterName, "-n", namespace,
					"-o", "jsonpath={.status.readyReplicas}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("3"), "all three replicas should become ready on scale-up")
			}, 10*time.Minute, 10*time.Second).Should(Succeed())

			By("verifying the rejoined peers reformed a healthy 3-voter quorum")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", scaleDownClusterName, "-n", namespace,
					"-o", "jsonpath={.status.autopilot.healthy} {.status.autopilot.voters}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true 3"), "autopilot should report a healthy 3-voter quorum")
			}, 10*time.Minute, 10*time.Second).Should(Succeed())

			By("verifying ordinals 1 and 2 re-attached the SAME PVCs (uid match)")
			for pvcName, wantUID := range pvcUIDs {
				cmd := exec.Command("kubectl", "get", "pvc", pvcName, "-n", namespace,
					"-o", "jsonpath={.metadata.uid}")
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				Expect(output).To(Equal(wantUID),
					"PVC %q must be the same object post-scale-up — re-attach, not recreate", pvcName)
			}
		})
	})

	// The minimal sample is the first YAML a new user applies: this
	// spec applies the ACTUAL FILE from config/samples and requires a
	// Ready cluster — the quickstart cannot silently rot. Slow lane.
	Context("Minimal sample quickstart", Ordered, func() {
		const sampleCluster = "nomad" // metadata.name inside the sample

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "nomadcluster", sampleCluster, "-n", namespace,
				"--ignore-not-found", "--timeout=3m")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "pvc", "-n", namespace,
				"-l", "app.kubernetes.io/instance="+sampleCluster, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("reaches Ready from the untouched sample file", func() {
			By("applying config/samples/minimal/nomadcluster.yaml verbatim")
			cmd := exec.Command("kubectl", "apply", "-n", namespace,
				"-f", "config/samples/minimal/nomadcluster.yaml")
			cmd.Dir = "../.."
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for the defaulted 3-replica cluster to be Ready")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", sampleCluster, "-n", namespace,
					"-o", "jsonpath={.status.phase} {.status.readyReplicas}")
				out, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(Equal("Running 3"))
			}, 8*time.Minute, 10*time.Second).Should(Succeed())

			By("verifying the promised defaults MATERIALIZE (regression: absent fields once flipped to false)")
			Eventually(func(g Gomega) {
				out, err := utils.Run(exec.Command("kubectl", "get", "nomadcluster", sampleCluster, "-n", namespace,
					"-o", "jsonpath={.status.aclBootstrapped}"))
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(Equal("true"), "ACL default must bootstrap")
			}, 3*time.Minute, 10*time.Second).Should(Succeed())
			out, err := utils.Run(exec.Command("kubectl", "get", "sts", sampleCluster, "-n", namespace,
				"-o", "jsonpath={.spec.template.spec.volumes[*].name} {.spec.volumeClaimTemplates[*].metadata.name}"))
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("audit"), "audit default must create its volume")
		})
	})

	// Keyring HA pair (neo-4q2): two transit keyrings on two INDEPENDENT
	// Vault clusters, each with its own credential — every listed
	// keyring wraps new keys, ANY ONE reachable Vault unwraps them.
	// Proves per-entry credentials (inline token rendering), HA
	// expansion across Vaults, and decrypt-any-one-alive under total
	// Vault-cluster loss. Slow lane: skipped on the PR lane.
	Context("Keyring HA pair (neo-4q2)", Ordered, func() {
		const krHA = "keyring-ha"

		haCR := func(entries string) string {
			return fmt.Sprintf(`apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  license:
    secretName: nomad-license
  server:
    acl:
      enabled: false
    keyrings:
%s  services:
    external:
      type: NodePort
`, krHA, namespace, entries)
		}
		entryYAML := func(name, ns, prefix, tokenSecret string) string {
			return fmt.Sprintf(`    - name: %s
      transit:
        address: "http://vault.%s.svc.cluster.local:8200"
        keyName: nomad-keyring
        mountPath: transit/
        keyIDPrefix: %s
        auth:
          method: token
          token:
            secretRef:
              name: %s
`, name, ns, prefix, tokenSecret)
		}

		deployVault := func(ns string) {
			cmd := exec.Command("kubectl", "create", "ns", ns)
			_, _ = utils.Run(cmd)
			vaultYAML := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata: {name: vault, namespace: %s, labels: {app: vault}}
spec:
  containers:
  - name: vault
    image: hashicorp/vault:1.18
    args: ["server", "-dev", "-dev-root-token-id=e2e-root", "-dev-listen-address=0.0.0.0:8200"]
---
apiVersion: v1
kind: Service
metadata: {name: vault, namespace: %s}
spec:
  selector: {app: vault}
  ports: [{port: 8200, targetPort: 8200}]
`, ns, ns)
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(vaultYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			cmd = exec.Command("kubectl", "wait", "--for=condition=Ready", "pod/vault", "-n", ns, "--timeout=120s")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "exec", "vault", "-n", ns, "--", "sh", "-c",
					"export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=e2e-root; "+
						"vault secrets enable transit || true; vault write -f transit/keys/nomad-keyring")
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
			}, 90*time.Second, 5*time.Second).Should(Succeed())
		}

		BeforeAll(func() {
			By("deploying TWO independent Vault clusters")
			deployVault("e2e-vault")
			deployVault("e2e-vault2")
			for _, name := range []string{"keyring-vault-token", "keyring-vault-token2"} {
				cmd := exec.Command("kubectl", "create", "secret", "generic", name,
					"-n", namespace, "--from-literal=VAULT_TOKEN=e2e-root")
				_, _ = utils.Run(cmd)
			}
		})

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "nomadcluster", krHA, "-n", namespace,
				"--ignore-not-found", "--timeout=3m")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "pvc", "-n", namespace,
				"-l", "app.kubernetes.io/instance="+krHA, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "secret/keyring-vault-token", "secret/keyring-vault-token2",
				"-n", namespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			for _, ns := range []string{"e2e-vault", "e2e-vault2"} {
				cmd = exec.Command("kubectl", "delete", "ns", ns, "--ignore-not-found", "--timeout=2m")
				_, _ = utils.Run(cmd)
			}
		})

		It("expands across two Vaults and survives losing one entirely", func() {
			By("creating a single-keyring cluster on Vault 1 and writing a Variable")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(haCR(entryYAML("primary", "e2e-vault", "a-", "keyring-vault-token")))
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				out, err := utils.Run(exec.Command("kubectl", "get", "nomadcluster", krHA, "-n", namespace,
					"-o", "jsonpath={.status.keyring.phase} {.status.keyring.active[0]}"))
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(Equal("Ready primary"))
			}, 6*time.Minute, 10*time.Second).Should(Succeed())
			Eventually(func(g Gomega) {
				_, err := utils.Run(exec.Command("kubectl", "exec", krHA+"-0", "-n", namespace, "--",
					"nomad", "var", "put", "-force", "e2e/ha", "v=hotel345"))
				g.Expect(err).NotTo(HaveOccurred())
			}, 3*time.Minute, 10*time.Second).Should(Succeed())

			By("expanding to an HA pair across BOTH Vault clusters")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(haCR(
				entryYAML("primary", "e2e-vault", "a-", "keyring-vault-token") +
					entryYAML("secondary", "e2e-vault2", "b-", "keyring-vault-token2")))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				out, err := utils.Run(exec.Command("kubectl", "get", "nomadcluster", krHA, "-n", namespace,
					"-o", "jsonpath={.status.keyring.phase} {.status.keyring.active}"))
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(Equal(`Ready ["primary","secondary"]`))
			}, 8*time.Minute, 10*time.Second).Should(Succeed())

			By("verifying the Variable survived the expansion")
			out, err := utils.Run(exec.Command("kubectl", "exec", krHA+"-0", "-n", namespace, "--",
				"nomad", "var", "get", "e2e/ha"))
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("hotel345"))

			By("ANY-ONE-ALIVE: destroying Vault cluster 1 ENTIRELY and restarting the server")
			cmd = exec.Command("kubectl", "delete", "pod/vault", "svc/vault", "-n", "e2e-vault", "--ignore-not-found")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			cmd = exec.Command("kubectl", "delete", "pod", krHA+"-0", "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the restarted server unwraps via the surviving Vault")
			Eventually(func(g Gomega) {
				out, err := utils.Run(exec.Command("kubectl", "exec", krHA+"-0", "-n", namespace, "--",
					"nomad", "var", "get", "e2e/ha"))
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(ContainSubstring("hotel345"))
			}, 4*time.Minute, 10*time.Second).Should(Succeed())
		})
	})

	// Keyring transit auth (neo-3xe P2): operator-managed Vault login
	// via the cluster's own ServiceAccount — mint, scheduled renewal,
	// and revocation recovery, against real kubernetes-auth TokenReview
	// (mode 1: reviewer JWT). Slow lane: skipped on the PR lane.
	Context("Keyring transit auth (neo-3xe P2)", Ordered, func() {
		const krAuth = "keyring-auth"

		authClusterCR := fmt.Sprintf(`apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  license:
    secretName: nomad-license
  server:
    acl:
      enabled: false
    keyrings:
    - name: primary
      transit:
        address: "http://vault.e2e-vault.svc.cluster.local:8200"
        keyName: nomad-keyring
        mountPath: transit/
        auth:
          method: kubernetes
          mount: kubernetes
          kubernetes:
            role: nomad-keyring
            # vector 3: ephemeral short-lived SA token (TokenRequest) —
            # stated explicitly rather than riding the defaults
            audiences: ["vault"]
            tokenExpirationSeconds: 600
  services:
    external:
      type: NodePort
`, krAuth, namespace)

		vaultCmd := func(script string) (string, error) {
			cmd := exec.Command("kubectl", "exec", "vault", "-n", "e2e-vault", "--", "sh", "-c",
				"export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=e2e-root; "+script)
			return utils.Run(cmd)
		}
		managedToken := func() string {
			cmd := exec.Command("kubectl", "get", "secret", krAuth+"-keyring-token", "-n", namespace,
				"-o", "jsonpath={.data.primary}")
			out, err := utils.Run(cmd)
			if err != nil {
				return ""
			}
			return out
		}
		tokenExpiry := func() string {
			cmd := exec.Command("kubectl", "get", "nomadcluster", krAuth, "-n", namespace,
				"-o", "jsonpath={.status.keyring.tokenExpiry}")
			out, _ := utils.Run(cmd)
			return out
		}

		JustAfterEach(func() {
			if !CurrentSpecReport().Failed() {
				return
			}
			for _, name := range []string{krAuth, "keyring-auth2", "keyring-auth3", "keyring-auth4"} {
				out, _ := utils.Run(exec.Command("kubectl", "get", "nomadcluster", name, "-n", namespace,
					"-o", "jsonpath={.status.keyring}"))
				_, _ = fmt.Fprintf(GinkgoWriter, "--- %s status.keyring: %s\n", name, out)
			}
			out, _ := utils.Run(exec.Command("sh", "-c",
				"kubectl logs -n "+namespace+" deploy/nomad-enterprise-operator-controller-manager --tail=300"+
					" | grep -iE 'keyring|vault' | tail -30"))
			_, _ = fmt.Fprintf(GinkgoWriter, "--- operator keyring log ---\n%s\n", out)
		})

		BeforeAll(func() {
			By("deploying Vault with transit and kubernetes auth (reviewer JWT mode)")
			cmd := exec.Command("kubectl", "create", "ns", "e2e-vault")
			_, _ = utils.Run(cmd)
			vaultYAML := `apiVersion: v1
kind: Pod
metadata: {name: vault, namespace: e2e-vault, labels: {app: vault}}
spec:
  containers:
  - name: vault
    image: hashicorp/vault:1.18
    args: ["server", "-dev", "-dev-root-token-id=e2e-root", "-dev-listen-address=0.0.0.0:8200"]
---
apiVersion: v1
kind: Service
metadata: {name: vault, namespace: e2e-vault}
spec:
  selector: {app: vault}
  ports: [{port: 8200, targetPort: 8200}]
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: vault-reviewer, namespace: e2e-vault}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: e2e-vault-reviewer}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: system:auth-delegator}
subjects: [{kind: ServiceAccount, name: vault-reviewer, namespace: e2e-vault}]
`
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(vaultYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			cmd = exec.Command("kubectl", "wait", "--for=condition=Ready", "pod/vault", "-n", "e2e-vault", "--timeout=120s")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("minting a reviewer JWT and configuring vault kubernetes auth")
			cmd = exec.Command("kubectl", "create", "token", "vault-reviewer", "-n", "e2e-vault", "--duration=2h")
			reviewerJWT, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				_, err := vaultCmd("vault secrets enable transit || true; vault write -f transit/keys/nomad-keyring")
				g.Expect(err).NotTo(HaveOccurred())
			}, 90*time.Second, 5*time.Second).Should(Succeed())
			_, err = vaultCmd("vault auth enable kubernetes || true")
			Expect(err).NotTo(HaveOccurred())
			_, err = vaultCmd(fmt.Sprintf(
				"vault write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc "+
					"kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt "+
					"token_reviewer_jwt=%q", reviewerJWT))
			Expect(err).NotTo(HaveOccurred())
			_, err = vaultCmd(`printf 'path "transit/*" { capabilities = ["read","create","update"] }' ` +
				`| vault policy write nomad-transit -`)
			Expect(err).NotTo(HaveOccurred())
			// TTL deliberately short so this spec exercises renewal and
			// revocation recovery in real time.
			_, err = vaultCmd(fmt.Sprintf(
				"vault write auth/kubernetes/role/nomad-keyring "+
					"bound_service_account_names=%s bound_service_account_namespaces=%s "+
					"audience=vault token_policies=nomad-transit token_ttl=2m token_max_ttl=1h", krAuth, namespace))
			Expect(err).NotTo(HaveOccurred())
		})

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "nomadcluster", krAuth, "-n", namespace,
				"--ignore-not-found", "--timeout=3m")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "pvc", "-n", namespace,
				"-l", "app.kubernetes.io/instance="+krAuth, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "clusterrolebinding", "e2e-vault-reviewer", "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "ns", "e2e-vault", "--ignore-not-found", "--timeout=2m")
			_, _ = utils.Run(cmd)
		})

		It("mints, renews, and recovers the managed Vault token", func() {
			By("creating a born-with-auth-keyring cluster")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(authClusterCR)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for Ready with a minted token and expiry in status")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", krAuth, "-n", namespace,
					"-o", "jsonpath={.status.keyring.phase} {.status.keyring.active[0]}")
				out, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(Equal("Ready primary"))
				g.Expect(managedToken()).NotTo(BeEmpty())
				g.Expect(tokenExpiry()).NotTo(BeEmpty())
			}, 6*time.Minute, 10*time.Second).Should(Succeed())

			By("proving the minted token actually wraps keys (Variable write)")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "exec", krAuth+"-0", "-n", namespace, "--",
					"nomad", "var", "put", "-force", "e2e/auth", "v=delta456")
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
			}, 3*time.Minute, 10*time.Second).Should(Succeed())

			By("observing scheduled renewal: expiry advances, token string does not change")
			tokenBefore := managedToken()
			expiryBefore := tokenExpiry()
			Eventually(func(g Gomega) {
				g.Expect(tokenExpiry()).NotTo(Equal(expiryBefore), "renewal must advance expiry")
			}, 4*time.Minute, 15*time.Second).Should(Succeed())
			Expect(managedToken()).To(Equal(tokenBefore), "renewal must not rotate the token")

			By("revoking the token in Vault and observing re-mint")
			raw, err := exec.Command("sh", "-c", fmt.Sprintf(
				"kubectl get secret %s-keyring-token -n %s -o jsonpath='{.data.primary}' | base64 -d",
				krAuth, namespace)).Output()
			Expect(err).NotTo(HaveOccurred())
			_, err = vaultCmd("vault token revoke " + strings.TrimSpace(string(raw)))
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				g.Expect(managedToken()).NotTo(Equal(tokenBefore), "revocation must force a re-mint")
			}, 5*time.Minute, 15*time.Second).Should(Succeed())

			By("verifying the cluster still functions after the re-mint roll")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "exec", krAuth+"-0", "-n", namespace, "--",
					"nomad", "var", "get", "e2e/auth")
				out, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(ContainSubstring("delta456"))
			}, 4*time.Minute, 15*time.Second).Should(Succeed())
		})

		// Mode 2 of the Vault-side matrix, CORRECTED empirically: with
		// no token_reviewer_jwt, modern kubernetes auth (v0.18+) uses
		// VAULT'S OWN pod ServiceAccount as the TokenReview identity —
		// NOT the client JWT (that behaviour is gone). So the harness
		// grants auth-delegator to Vault's pod SA; client SAs need
		// nothing. JWT source here: long-lived legacy SA token via
		// serviceAccountTokenSecretRef (the secretRef path).
		It("logs in via self-review mode with a long-lived SA token", func() {
			const krAuth2 = "keyring-auth2"
			By("granting auth-delegator to VAULT'S pod SA and configuring a reviewer-less mount")
			crb := fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: e2e-selfreview-%s}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: system:auth-delegator}
subjects: [{kind: ServiceAccount, name: default, namespace: e2e-vault}]
`, krAuth2)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(crb)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "clusterrolebinding",
					"e2e-selfreview-"+krAuth2, "--ignore-not-found")
				_, _ = utils.Run(cmd)
				cmd = exec.Command("kubectl", "delete", "nomadcluster", krAuth2, "-n", namespace,
					"--ignore-not-found", "--timeout=3m")
				_, _ = utils.Run(cmd)
				cmd = exec.Command("kubectl", "delete", "pvc", "-n", namespace,
					"-l", "app.kubernetes.io/instance="+krAuth2, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})
			_, err = vaultCmd("vault auth enable -path=kubernetes-selfreview kubernetes || true")
			Expect(err).NotTo(HaveOccurred())
			// No token_reviewer_jwt: Vault self-reviews with the login JWT.
			_, err = vaultCmd("vault write auth/kubernetes-selfreview/config " +
				"kubernetes_host=https://kubernetes.default.svc " +
				"kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
			Expect(err).NotTo(HaveOccurred())
			// No audience param: legacy SA tokens carry the apiserver audience.
			_, err = vaultCmd(fmt.Sprintf(
				"vault write auth/kubernetes-selfreview/role/nomad-keyring "+
					"bound_service_account_names=%s bound_service_account_namespaces=%s "+
					"token_policies=nomad-transit token_ttl=1h", krAuth2, namespace))
			Expect(err).NotTo(HaveOccurred())

			By("creating the cluster (login defers until the SA token Secret exists)")
			cr := fmt.Sprintf(`apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  license:
    secretName: nomad-license
  server:
    acl:
      enabled: false
    keyrings:
    - name: primary
      transit:
        address: "http://vault.e2e-vault.svc.cluster.local:8200"
        keyName: nomad-keyring
        mountPath: transit/
        auth:
          method: kubernetes
          mount: kubernetes-selfreview
          kubernetes:
            role: nomad-keyring
            # vector 2: long-lived user-minted SA token
            serviceAccountTokenSecretRef:
              name: %s-sa-jwt
  services:
    external:
      type: NodePort
`, krAuth2, namespace, krAuth2)
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(cr)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("creating a legacy long-lived SA token once the operator creates the SA")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "serviceaccount", krAuth2, "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
			legacyToken := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s-sa-jwt
  namespace: %s
  annotations:
    kubernetes.io/service-account.name: %s
type: kubernetes.io/service-account-token
`, krAuth2, namespace, krAuth2)
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(legacyToken)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for Ready via self-review login")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", krAuth2, "-n", namespace,
					"-o", "jsonpath={.status.keyring.phase} {.status.keyring.active[0]}")
				out, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(Equal("Ready primary"))
			}, 6*time.Minute, 10*time.Second).Should(Succeed())

			By("proving the wrapper works end to end")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "exec", krAuth2+"-0", "-n", namespace, "--",
					"nomad", "var", "put", "-force", "e2e/selfreview", "v=echo123")
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
			}, 3*time.Minute, 10*time.Second).Should(Succeed())
		})

		// EXTERNAL-VAULT variant of reviewer-less kubernetes auth:
		// disable_local_ca_jwt=true makes the plugin ignore its pod
		// credentials (exactly the external-Vault code path), so the
		// CLIENT's login JWT performs the TokenReview — the CLUSTER's
		// SA carries system:auth-delegator, and the JWT must be a valid
		// apiserver credential (long-lived legacy token).
		It("logs in via client-JWT review (external-Vault semantics)", func() {
			const krAuth4 = "keyring-auth4"
			By("granting auth-delegator to the CLUSTER SA and configuring an external-style mount")
			crb := fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: e2e-clientreview-%s}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: system:auth-delegator}
subjects: [{kind: ServiceAccount, name: %s, namespace: %s}]
`, krAuth4, krAuth4, namespace)
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(crb)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "clusterrolebinding",
					"e2e-clientreview-"+krAuth4, "--ignore-not-found")
				_, _ = utils.Run(cmd)
				cmd = exec.Command("kubectl", "delete", "nomadcluster", krAuth4, "-n", namespace,
					"--ignore-not-found", "--timeout=3m")
				_, _ = utils.Run(cmd)
				cmd = exec.Command("kubectl", "delete", "pvc", "-n", namespace,
					"-l", "app.kubernetes.io/instance="+krAuth4, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})
			_, err = vaultCmd("vault auth enable -path=kubernetes-external kubernetes || true")
			Expect(err).NotTo(HaveOccurred())
			// disable_local_ca_jwt: no pod-credential adoption; with no
			// token_reviewer_jwt either, the CLIENT JWT reviews itself.
			_, err = vaultCmd("vault write auth/kubernetes-external/config " +
				"kubernetes_host=https://kubernetes.default.svc " +
				"kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt " +
				"disable_local_ca_jwt=true")
			Expect(err).NotTo(HaveOccurred())
			_, err = vaultCmd(fmt.Sprintf(
				"vault write auth/kubernetes-external/role/nomad-keyring "+
					"bound_service_account_names=%s bound_service_account_namespaces=%s "+
					"token_policies=nomad-transit token_ttl=1h", krAuth4, namespace))
			Expect(err).NotTo(HaveOccurred())

			By("creating the cluster (vector 2 source; login defers until the token Secret exists)")
			cr := fmt.Sprintf(`apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  license:
    secretName: nomad-license
  server:
    acl:
      enabled: false
    keyrings:
    - name: primary
      transit:
        address: "http://vault.e2e-vault.svc.cluster.local:8200"
        keyName: nomad-keyring
        mountPath: transit/
        auth:
          method: kubernetes
          mount: kubernetes-external
          kubernetes:
            role: nomad-keyring
            serviceAccountTokenSecretRef:
              name: %s-sa-jwt
  services:
    external:
      type: NodePort
`, krAuth4, namespace, krAuth4)
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(cr)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("creating the legacy SA token once the operator creates the SA")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "serviceaccount", krAuth4, "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
			legacyToken := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s-sa-jwt
  namespace: %s
  annotations:
    kubernetes.io/service-account.name: %s
type: kubernetes.io/service-account-token
`, krAuth4, namespace, krAuth4)
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(legacyToken)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for Ready via client-JWT review")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", krAuth4, "-n", namespace,
					"-o", "jsonpath={.status.keyring.phase} {.status.keyring.active[0]}")
				out, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(Equal("Ready primary"))
			}, 6*time.Minute, 10*time.Second).Should(Succeed())

			By("proving the wrapper works end to end")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "exec", krAuth4+"-0", "-n", namespace, "--",
					"nomad", "var", "put", "-force", "e2e/clientreview", "v=golf012")
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
			}, 3*time.Minute, 10*time.Second).Should(Succeed())
		})

		// Mode 3 of the Vault-side matrix: the jwt auth method verifies
		// the SA JWT signature directly against the cluster's JWKS — no
		// TokenReview, no auth-delegator for anyone. Pairs with the
		// DEFAULT ephemeral TokenRequest source. Harness prerequisite:
		// anonymous OIDC discovery (one CRB) + the cluster CA.
		It("logs in via the jwt method against cluster JWKS", func() {
			const krAuth3 = "keyring-auth3"
			By("exposing OIDC discovery anonymously and configuring the jwt mount")
			crb := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: e2e-oidc-discovery}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: system:service-account-issuer-discovery}
subjects: [{apiGroup: rbac.authorization.k8s.io, kind: Group, name: "system:unauthenticated"}]
`
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(crb)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "clusterrolebinding", "e2e-oidc-discovery", "--ignore-not-found")
				_, _ = utils.Run(cmd)
				cmd = exec.Command("kubectl", "delete", "nomadcluster", krAuth3, "-n", namespace,
					"--ignore-not-found", "--timeout=3m")
				_, _ = utils.Run(cmd)
				cmd = exec.Command("kubectl", "delete", "pvc", "-n", namespace,
					"-l", "app.kubernetes.io/instance="+krAuth3, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})
			issuer, err := exec.Command("sh", "-c",
				`kubectl get --raw /.well-known/openid-configuration | `+
					`python3 -c 'import json,sys; print(json.load(sys.stdin)["issuer"])'`).Output()
			Expect(err).NotTo(HaveOccurred())
			_, err = vaultCmd("vault auth enable -path=jwt jwt || true")
			Expect(err).NotTo(HaveOccurred())
			_, err = vaultCmd(fmt.Sprintf(
				"vault write auth/jwt/config oidc_discovery_url=%q "+
					`oidc_discovery_ca_pem=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`,
				strings.TrimSpace(string(issuer))))
			Expect(err).NotTo(HaveOccurred())
			_, err = vaultCmd(fmt.Sprintf(
				"vault write auth/jwt/role/nomad-keyring role_type=jwt user_claim=sub "+
					"bound_audiences=vault bound_subject=system:serviceaccount:%s:%s "+
					"token_policies=nomad-transit token_ttl=1h", namespace, krAuth3))
			Expect(err).NotTo(HaveOccurred())

			By("creating the cluster with the jwt method and the default ephemeral source")
			cr := fmt.Sprintf(`apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  license:
    secretName: nomad-license
  server:
    acl:
      enabled: false
    keyrings:
    - name: primary
      transit:
        address: "http://vault.e2e-vault.svc.cluster.local:8200"
        keyName: nomad-keyring
        mountPath: transit/
        auth:
          method: jwt
          mount: jwt
          jwt:
            role: nomad-keyring
  services:
    external:
      type: NodePort
`, krAuth3, namespace)
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(cr)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for Ready via jwt login")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", krAuth3, "-n", namespace,
					"-o", "jsonpath={.status.keyring.phase} {.status.keyring.active[0]}")
				out, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(Equal("Ready primary"))
			}, 6*time.Minute, 10*time.Second).Should(Succeed())

			By("proving the wrapper works end to end")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "exec", krAuth3+"-0", "-n", namespace, "--",
					"nomad", "var", "put", "-force", "e2e/jwt", "v=foxtrot789")
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
			}, 3*time.Minute, 10*time.Second).Should(Succeed())
		})
	})

	// Keyring lifecycle (neo-3xe): enable aead->transit on a live
	// cluster, prove DR (snapshot restores + decrypts on a fresh
	// cluster; redacted aead snapshot does NOT), then disable back to
	// aead. Slow lane: runs nightly, skipped on the PR lane.
	Context("Keyring lifecycle (neo-3xe)", Ordered, func() {
		const krA, krB = "keyring-a", "keyring-b"

		nomadExec := func(pod string, args ...string) (string, error) {
			cmd := exec.Command("kubectl", append([]string{"exec", pod + "-0", "-n", namespace, "--", "nomad"}, args...)...)
			return utils.Run(cmd)
		}
		clusterCR := func(name string, keyrings string) string {
			return fmt.Sprintf(`apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 1
  license:
    secretName: nomad-license
  server:
    acl:
      enabled: false
%s  services:
    external:
      type: NodePort
`, name, namespace, keyrings)
		}
		transitKeyrings := `    keyrings:
    - name: primary
      transit:
        address: "http://vault.e2e-vault.svc.cluster.local:8200"
        keyName: nomad-keyring
        mountPath: transit/
        auth:
          method: token
          token:
            secretRef:
              name: keyring-vault-token
`

		BeforeAll(func() {
			// Vault dev lives in its own UNLABELLED namespace: the
			// operator namespace enforces restricted PSS, which the
			// Vault image's entrypoint (root, IPC_LOCK) does not meet.
			By("deploying a Vault dev pod with a transit key")
			cmd := exec.Command("kubectl", "create", "ns", "e2e-vault")
			_, _ = utils.Run(cmd)
			vaultYAML := `apiVersion: v1
kind: Pod
metadata: {name: vault, namespace: e2e-vault, labels: {app: vault}}
spec:
  containers:
  - name: vault
    image: hashicorp/vault:1.18
    args: ["server", "-dev", "-dev-root-token-id=e2e-root", "-dev-listen-address=0.0.0.0:8200"]
---
apiVersion: v1
kind: Service
metadata: {name: vault, namespace: e2e-vault}
spec:
  selector: {app: vault}
  ports: [{port: 8200, targetPort: 8200}]
`
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(vaultYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			cmd = exec.Command("kubectl", "wait", "--for=condition=Ready", "pod/vault", "-n", "e2e-vault", "--timeout=120s")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "exec", "vault", "-n", "e2e-vault", "--", "sh", "-c",
					"export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=e2e-root; "+
						"vault secrets enable transit || true; vault write -f transit/keys/nomad-keyring")
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
			}, 90*time.Second, 5*time.Second).Should(Succeed())
			cmd = exec.Command("kubectl", "create", "secret", "generic", "keyring-vault-token",
				"-n", namespace, "--from-literal=VAULT_TOKEN=e2e-root")
			_, _ = utils.Run(cmd)
		})

		AfterAll(func() {
			for _, name := range []string{krA, krB} {
				cmd := exec.Command("kubectl", "delete", "nomadcluster", name, "-n", namespace,
					"--ignore-not-found", "--timeout=3m")
				_, _ = utils.Run(cmd)
			}
			// Retained data PVCs poison reruns: an adopted PVC carries
			// old Raft/keyring state into a "fresh" cluster.
			for _, name := range []string{krA, krB} {
				cmd := exec.Command("kubectl", "delete", "pvc", "-n", namespace,
					"-l", "app.kubernetes.io/instance="+name, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			}
			cmd := exec.Command("kubectl", "delete", "ns", "e2e-vault", "--ignore-not-found", "--timeout=2m")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "secret/keyring-vault-token", "-n", namespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("enables transit mid-life, proves DR both ways, and disables", func() {
			By("creating an aead cluster and writing a Variable")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(clusterCR(krA, ""))
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				out, err := nomadExec(krA, "var", "put", "-force", "e2e/secret", "dr_value=charlie789")
				g.Expect(err).NotTo(HaveOccurred(), out)
			}, 6*time.Minute, 10*time.Second).Should(Succeed())

			By("saving aead snapshots (full and redacted) for the DR proofs")
			_, err = nomadExec(krA, "operator", "snapshot", "save", "/tmp/aead.snap")
			Expect(err).NotTo(HaveOccurred())
			_, err = nomadExec(krA, "operator", "snapshot", "save", "-redact", "/tmp/aead-redacted.snap")
			Expect(err).NotTo(HaveOccurred())
			// Copy out NOW: the migration's rolling restart replaces the
			// pod and wipes /tmp.
			for _, f := range []string{"aead.snap", "aead-redacted.snap"} {
				cmd = exec.Command("sh", "-c", fmt.Sprintf(
					"kubectl exec %s-0 -n %s -- cat /tmp/%s > /tmp/e2e-%s", krA, namespace, f, f))
				_, err = utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
			}

			By("enabling the transit keyring and waiting for migration to complete")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(clusterCR(krA, transitKeyrings))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", krA, "-n", namespace,
					"-o", "jsonpath={.status.keyring.phase} {.status.keyring.active[0]}")
				out, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(Equal("Ready primary"))
			}, 8*time.Minute, 10*time.Second).Should(Succeed())

			By("verifying the pre-migration Variable survived the migration")
			out, err := nomadExec(krA, "var", "get", "e2e/secret")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("charlie789"))

			By("saving a KMS-cluster snapshot")
			_, err = nomadExec(krA, "operator", "snapshot", "save", "/tmp/kms.snap")
			Expect(err).NotTo(HaveOccurred())
			cmd = exec.Command("sh", "-c", fmt.Sprintf(
				"kubectl exec %s-0 -n %s -- cat /tmp/kms.snap > /tmp/e2e-kms.snap", krA, namespace))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("booting a fresh transit cluster for the DR proofs")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(clusterCR(krB, transitKeyrings))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", krB, "-n", namespace,
					"-o", "jsonpath={.status.keyring.phase}")
				out, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(Equal("Ready"))
			}, 6*time.Minute, 10*time.Second).Should(Succeed())

			By("NEGATIVE: a redacted aead snapshot must NOT decrypt on a virgin cluster")
			cmd = exec.Command("sh", "-c", fmt.Sprintf(
				"kubectl exec -i %s-0 -n %s -- sh -c 'cat > /tmp/aead-redacted.snap' < /tmp/e2e-aead-redacted.snap",
				krB, namespace))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			_, err = nomadExec(krB, "operator", "snapshot", "restore", "/tmp/aead-redacted.snap")
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				out, err := nomadExec(krB, "var", "get", "e2e/secret")
				// The specific decrypt-failure signature — NOT a vacuous
				// "secret absent" (which an unready cluster also produces).
				g.Expect(err).To(HaveOccurred())
				g.Expect(out+err.Error()).To(ContainSubstring("no such key"),
					"redacted snapshot must fail decryption for lack of key material, got: %s", out)
			}, 2*time.Minute, 10*time.Second).Should(Succeed())

			By("POSITIVE: the KMS snapshot restores and decrypts on the fresh cluster")
			cmd = exec.Command("sh", "-c", fmt.Sprintf(
				"kubectl exec -i %s-0 -n %s -- sh -c 'cat > /tmp/kms.snap' < /tmp/e2e-kms.snap", krB, namespace))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			_, err = nomadExec(krB, "operator", "snapshot", "restore", "/tmp/kms.snap")
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				out, err := nomadExec(krB, "var", "get", "e2e/secret")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(ContainSubstring("charlie789"))
			}, 2*time.Minute, 10*time.Second).Should(Succeed())

			By("disabling the keyring on the original cluster (back to aead)")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(clusterCR(krA, ""))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", krA, "-n", namespace,
					"-o", "jsonpath={.status.keyring.phase} {.status.keyring.active[0]}")
				out, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(Equal("Ready aead"))
			}, 8*time.Minute, 10*time.Second).Should(Succeed())
			out, err = nomadExec(krA, "var", "get", "e2e/secret")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("charlie789"))
		})
	})

	// Rolling Nomad version upgrade with the quorum floor asserted at
	// every poll. Slow lane: runs nightly, skipped on the PR lane by
	// container name.
	Context("Nomad version upgrade (neo-6xm.1)", Ordered, func() {
		const upgradeClusterName = "upgrade-test"
		// Overridable for the nightly matrix. Major.minor tags serve
		// each line's latest patch — HashiCorp's recommended upgrade
		// origin — so the matrix self-maintains as patches ship.
		fromTag := envOr("UPGRADE_FROM", "1.11-ent")
		toTag := envOr("UPGRADE_TO", "2.0-ent")

		upgradeClusterCR := fmt.Sprintf(`apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: %s
  namespace: %s
spec:
  replicas: 3
  image:
    repository: hashicorp/nomad
    tag: %q
  license:
    secretName: nomad-license
  services:
    external:
      type: LoadBalancer
      loadBalancerIP: "10.0.0.6"
  server:
    acl:
      enabled: true
`, upgradeClusterName, namespace, fromTag)

		AfterAll(func() {
			cmd := exec.Command("kubectl", "delete", "nomadcluster", upgradeClusterName,
				"-n", namespace, "--ignore-not-found", "--wait=true", "--timeout=3m")
			_, _ = utils.Run(cmd)
		})

		It("rolls a 3-replica cluster to the next Nomad version without losing quorum", func() {
			By(fmt.Sprintf("creating a 3-replica cluster on %s", fromTag))
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(upgradeClusterCR)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for the cluster to be Ready with healthy autopilot")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", upgradeClusterName, "-n", namespace,
					"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].status} {.status.autopilot.healthy}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True true"))
			}, 12*time.Minute, 10*time.Second).Should(Succeed())

			By(fmt.Sprintf("patching spec.image.tag to %s", toTag))
			cmd = exec.Command("kubectl", "patch", "nomadcluster", upgradeClusterName, "-n", namespace,
				"--type=merge", "-p", fmt.Sprintf(`{"spec":{"image":{"tag":%q}}}`, toTag))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("rolling through the upgrade with the quorum floor asserted at every poll")
			// The structural no-quorum-loss guarantee: with 3 replicas
			// and PDB/rolling-update pacing, at most one server is ever
			// down — readyReplicas must never drop below 2 while the
			// roll progresses to completion.
			deadline := time.Now().Add(15 * time.Minute)
			for {
				Expect(time.Now().Before(deadline)).To(BeTrue(), "upgrade roll did not complete within 15m")

				cmd := exec.Command("kubectl", "get", "statefulset", upgradeClusterName, "-n", namespace,
					"-o", "jsonpath={.status.readyReplicas} {.status.updatedReplicas} "+
						"{.status.currentRevision} {.status.updateRevision}")
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				var ready, updated int
				var current, update string
				_, _ = fmt.Sscanf(output, "%d %d %s %s", &ready, &updated, &current, &update)

				Expect(ready).To(BeNumerically(">=", 2),
					"quorum floor violated: %d/3 ready during the roll", ready)

				if ready == 3 && updated == 3 && current == update && current != "" {
					break
				}
				time.Sleep(5 * time.Second)
			}

			By("verifying every pod runs the target image")
			cmd = exec.Command("kubectl", "get", "pods", "-n", namespace,
				"-l", "app.kubernetes.io/instance="+upgradeClusterName,
				"-o", "jsonpath={.items[*].spec.containers[0].image}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			images := strings.Fields(output)
			Expect(images).To(HaveLen(3))
			for _, img := range images {
				Expect(img).To(Equal("hashicorp/nomad:" + toTag))
			}

			By("verifying the upgraded cluster converged: version, quorum, leader")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", upgradeClusterName, "-n", namespace,
					"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].status} `+
						`{.status.autopilot.healthy} {.status.autopilot.voters} {.status.nomadVersion}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				parts := strings.Fields(output)
				g.Expect(parts).To(HaveLen(4))
				g.Expect(parts[0]).To(Equal("True"), "Ready after upgrade")
				g.Expect(parts[1]).To(Equal("true"), "autopilot healthy after upgrade")
				g.Expect(parts[2]).To(Equal("3"), "3 voters after upgrade")
				g.Expect(parts[3]).To(HavePrefix(strings.TrimSuffix(toTag, "-ent")),
					"status.nomadVersion should report the new version line")
			}, 8*time.Minute, 10*time.Second).Should(Succeed())

			By("verifying a leader exists")
			cmd = exec.Command("kubectl", "get", "nomadcluster", upgradeClusterName, "-n", namespace,
				"-o", "jsonpath={.status.leaderAddress}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "leaderAddress must be populated after the upgrade")
		})
	})

	// neo-6xm.2: HA operator topology — leader election exists in the
	// deployment but failover had never been exercised. Runs LAST: it
	// kills the operator leader mid-suite.
	Context("Operator leader failover (neo-6xm.2)", Ordered, func() {
		const deployName = "nomad-enterprise-operator-controller-manager"
		const leaseName = "42388956.hashicorp.com"

		AfterAll(func() {
			By("restoring the single-replica operator deployment")
			cmd := exec.Command("kubectl", "scale", "deployment", deployName, "-n", namespace, "--replicas=1")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "nomadcluster", "failover-canary",
				"-n", namespace, "--ignore-not-found", "--timeout=2m")
			_, _ = utils.Run(cmd)
		})

		It("fails over to a standby replica and keeps reconciling", func() {
			By("scaling the operator to 2 replicas (leader + standby)")
			cmd := exec.Command("kubectl", "scale", "deployment", deployName, "-n", namespace, "--replicas=2")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "deployment", deployName, "-n", namespace,
					"-o", "jsonpath={.status.readyReplicas}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("2"))
			}, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("identifying the current leader from the election Lease")
			cmd = exec.Command("kubectl", "get", "lease", leaseName, "-n", namespace,
				"-o", "jsonpath={.spec.holderIdentity}")
			oldHolder, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(oldHolder).NotTo(BeEmpty())
			// holderIdentity is "<pod-name>_<uuid>"
			leaderPod := strings.Split(oldHolder, "_")[0]

			By(fmt.Sprintf("deleting the leader pod %s", leaderPod))
			cmd = exec.Command("kubectl", "delete", "pod", leaderPod, "-n", namespace, "--wait=false")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("waiting for the standby to acquire the Lease")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "lease", leaseName, "-n", namespace,
					"-o", "jsonpath={.spec.holderIdentity}")
				newHolder, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(newHolder).NotTo(BeEmpty())
				g.Expect(newHolder).NotTo(Equal(oldHolder), "lease should transfer to the standby")
				g.Expect(strings.Split(newHolder, "_")[0]).NotTo(Equal(leaderPod))
			}, 2*time.Minute, 3*time.Second).Should(Succeed())

			By("proving the new leader reconciles: a canary CR gets its status set")
			// A missing-Secret canary parks at LicenseSecretNotFound in
			// one reconcile — a liveness probe needing no Nomad boot.
			// NodePort matters: a LoadBalancer canary would wait on an
			// IP forever and never reach the license check.
			canary := fmt.Sprintf(`apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: failover-canary
  namespace: %s
spec:
  replicas: 1
  license:
    secretName: no-such-secret
  services:
    external:
      type: NodePort
`, namespace)
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(canary)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", "failover-canary", "-n", namespace,
					"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].reason}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("LicenseSecretNotFound"),
					"the post-failover leader should reconcile the canary CR")
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
		})
	})
})

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	// Temporary file to store the token request
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		// Execute kubectl command to create the token
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		// Parse the JSON output to extract the token
		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() string {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	metricsOutput, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
	Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
	return metricsOutput
}

// base64Encode returns the base64-encoded string of the given bytes.
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}
