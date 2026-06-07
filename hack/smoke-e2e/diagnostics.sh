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
echo "=== Secrets (names only) ==="
kubectl -n "${NS}" get secrets || true
echo
echo "=== PVCs ==="
kubectl -n "${NS}" get pvc || true
echo
echo "=== Operator logs (last 200 lines) ==="
kubectl -n nomad-enterprise-operator-system logs \
  -l control-plane=controller-manager --tail=200 || true
