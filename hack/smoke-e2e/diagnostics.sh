#!/usr/bin/env bash
# diagnostics.sh — dump kind cluster state when smoke-e2e fails.
# Called from .github/workflows/smoke-e2e.yml in an `if: failure()` step
# so reviewers can triage from the workflow log without re-running.
#
# Inputs (positional):
#   $1: sample namespace (e.g. neo-smoke)
#   $2: NomadCluster name (e.g. nomad)

set -uo pipefail

NS=${1:-neo-smoke}
CLUSTER=${2:-nomad}

echo "=== NomadCluster status ==="
kubectl -n "${NS}" get "nomadcluster/${CLUSTER}" -o yaml || true
echo
echo "=== StatefulSet ==="
kubectl -n "${NS}" describe "statefulset/${CLUSTER}" || true
echo
echo "=== Pods ==="
kubectl -n "${NS}" get pods -o wide || true
kubectl -n "${NS}" describe pods || true
echo
echo "=== Nomad pod logs (current + previous) ==="
# The StatefulSet pods run a single `nomad` container. Capture both the
# current and the previous (post-restart) logs so a readiness-probe failure
# or crash surfaces its cause in the workflow log without a re-run.
for pod in $(kubectl -n "${NS}" get pods \
  -l "app.kubernetes.io/instance=${CLUSTER}" \
  -o name 2>/dev/null); do
  echo "--- ${pod} (current) ---"
  kubectl -n "${NS}" logs "${pod}" -c nomad --tail=200 || true
  echo "--- ${pod} (previous) ---"
  kubectl -n "${NS}" logs "${pod}" -c nomad --previous --tail=200 || true
done
echo
echo "=== EndpointSlices ==="
kubectl -n "${NS}" get endpointslices -o wide || true
echo
echo "=== In-pod peer DNS + effective retry_join ==="
# Distinguishes "DNS is broken" from "Nomad stopped retrying" (GH #11):
# resolvable peers alongside a stale join attempt implicate the joiner.
replicas=$(kubectl -n "${NS}" get "statefulset/${CLUSTER}" \
  -o jsonpath='{.spec.replicas}' 2>/dev/null || echo 0)
for pod in $(kubectl -n "${NS}" get pods \
  -l "app.kubernetes.io/instance=${CLUSTER}" \
  -o name 2>/dev/null); do
  echo "--- ${pod} peer lookups ---"
  for i in $(seq 0 $((replicas - 1))); do
    fqdn="${CLUSTER}-${i}.${CLUSTER}-headless.${NS}.svc.cluster.local"
    kubectl -n "${NS}" exec "${pod#pod/}" -c nomad -- getent hosts "${fqdn}" \
      || echo "UNRESOLVED: ${fqdn}"
  done
  echo "--- ${pod} effective retry_join (self-filtered) ---"
  kubectl -n "${NS}" exec "${pod#pod/}" -c nomad -- \
    grep -A "$((replicas + 4))" server_join /nomad/config-runtime/server.hcl || true
done
echo
echo "=== Secrets (names only) ==="
kubectl -n "${NS}" get secrets || true
echo
echo "=== PVCs ==="
kubectl -n "${NS}" get pvc || true
echo
echo "=== Operator logs (last 200 lines) ==="
kubectl -n nomad-enterprise-operator-system logs \
  -l control-plane=controller-manager --tail=200 || true
