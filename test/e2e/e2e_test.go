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

// testClusterCR is the NomadCluster CR applied during reconciliation tests.
// Uses replicas=1 to minimise Kind resource usage, loadBalancerIP to bypass
// AdvertisePhase LB wait, and disables TLS to reduce dependencies.
// Audit is enabled to exercise that feature path.
const testClusterCR = `apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: test-cluster
  namespace: nomad-enterprise-operator-system
spec:
  replicas: 1
  image:
    repository: hashicorp/nomad
    tag: "1.11-ent"
  license:
    secretName: nomad-license
  services:
    external:
      type: LoadBalancer
      loadBalancerIP: "10.0.0.1"
  server:
    acl:
      enabled: true
    audit:
      enabled: true
      format: json
      rotateDuration: "24h"
      rotateMaxFiles: 10
`

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the baseline security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=baseline")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")

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

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
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
				g.Expect(output).To(ContainSubstring("controller-runtime.metrics\tServing metrics server"),
					"Metrics server not yet started")
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
				{"configmap", testClusterName + "-config"},
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
				{"{.spec.template.spec.containers[0].image}", "hashicorp/nomad:1.11-ent", "container image"},
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
			Expect(output).To(Equal("/v1/agent/health?type=server"), "wrong liveness probe path")

			By("verifying readiness probe")
			cmd = exec.Command("kubectl", "get", "sts", testClusterName, "-n", namespace,
				"-o", `jsonpath={.spec.template.spec.containers[0].readinessProbe.httpGet.path}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("/v1/agent/health?type=server"), "wrong readiness probe path")

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
			cmd := exec.Command("kubectl", "get", "configmap", testClusterName+"-config", "-n", namespace,
				`-o`, `jsonpath={.data.server\.hcl}`)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("server {"), "missing server block")
			Expect(output).To(ContainSubstring("bootstrap_expect = 1"), "wrong bootstrap_expect")
			Expect(output).To(ContainSubstring(`region`), "missing region")
			Expect(output).To(ContainSubstring(`"global"`), "missing global region value")
			Expect(output).To(ContainSubstring("encrypt ="), "missing gossip encrypt key")
			Expect(output).To(ContainSubstring("acl {"), "missing acl block")

			By("verifying audit configuration in HCL")
			Expect(output).To(ContainSubstring("audit {"), "missing audit block")
			Expect(output).To(ContainSubstring(`sink "file"`), "missing audit sink")
			Expect(output).To(ContainSubstring(`"json"`), "missing audit format")
			Expect(output).To(ContainSubstring(`"24h"`), "missing audit rotate_duration")
			Expect(output).To(ContainSubstring("10"), "missing audit rotate_max_files")

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

			By("verifying StatefulSetReady condition is True")
			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				`-o`, `jsonpath={.status.conditions[?(@.type=="StatefulSetReady")].status}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("True"))

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

		It("should set infrastructure status conditions", func() {
			type conditionCheck struct {
				condType string
				expected string
			}
			checks := []conditionCheck{
				{"GossipKeyReady", "True"},
				{"ServicesReady", "True"},
				{"AdvertiseResolved", "True"},
			}
			for _, c := range checks {
				cmd := exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
					"-o", fmt.Sprintf(`jsonpath={.status.conditions[?(@.type=="%s")].status}`, c.condType))
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())
				Expect(output).To(Equal(c.expected), "condition %s should be %s", c.condType, c.expected)
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
					`-o`, `jsonpath={.status.conditions[?(@.type=="ACLBootstrapped")].status}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "ACL not yet bootstrapped")
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
		})

		It("should enrich status with Nomad API data", func() {
			By("waiting for license status to be populated")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
					`-o`, `jsonpath={.status.conditions[?(@.type=="LicenseValid")].status}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "LicenseValid condition not yet True")
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
					`-o`, `jsonpath={.status.conditions[?(@.type=="AutopilotHealthy")].reason}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				// With replicas=1, autopilot reports NoFailureTolerance (healthy but no redundancy)
				g.Expect(output).To(BeElementOf("QuorumHealthy", "NoFailureTolerance"),
					"AutopilotHealthy condition not yet set")
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

			By("verifying leader ID is populated")
			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.leaderID}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty(), "leaderID should be populated")

			By("verifying currentReplicas is set")
			cmd = exec.Command("kubectl", "get", "nomadcluster", testClusterName, "-n", namespace,
				"-o", "jsonpath={.status.currentReplicas}")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(Equal("1"), "currentReplicas should be 1")
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
			Expect(output).To(Equal("hashicorp/nomad:1.11-ent"), "snapshot agent should use same image as cluster")

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
				{"configmap", testClusterName + "-config"},
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
    tag: "1.11-ent"
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

		It("should create operator client certificate secret", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secret", opTLSClusterName+"-operator-client", "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Operator client cert secret not yet created")
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
				cmd := exec.Command("kubectl", "get", "configmap", opTLSClusterName+"-config", "-n", namespace,
					`-o`, `jsonpath={.data.server\.hcl}`)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("tls {"), "missing tls block")
				g.Expect(output).To(ContainSubstring(`cert_file = "/nomad/tls/tls.crt"`), "wrong cert_file path")
				g.Expect(output).To(ContainSubstring(`key_file  = "/nomad/tls/tls.key"`), "wrong key_file path")
				g.Expect(output).To(ContainSubstring("verify_server_hostname = true"), "missing verify_server_hostname")
				g.Expect(output).To(ContainSubstring("verify_https_client    = true"), "missing verify_https_client")
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
    tag: "1.11-ent"
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

		It("should create operator client certificate secret", func() {
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secret", userCAClusterName+"-operator-client", "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Operator client cert secret not yet created")
			}).Should(Succeed())
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
