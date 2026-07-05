#!/usr/bin/env bash
# Fleet-scale load test for the OPERATOR (neo-31u).
#
# Real kind cluster, real Nomad Enterprise servers; the measurement
# target is the operator: reconcile throughput, workqueue behaviour,
# and process resources under fleet waves. Nomad-side behaviour is the
# e2e suite's job, not this rig's.
#
# Usage: N=10 ./test/load/loadtest.sh   (or: make test-load LOAD_N=10)
set -euo pipefail

N="${N:-10}"
NS="${NS:-nomad-load}"
OPERATOR_NS="nomad-enterprise-operator-system"
KIND_CLUSTER="${KIND_CLUSTER:-nomad-enterprise-operator-test-e2e}"
IMG="${IMG:-example.com/nomad-enterprise-operator:v0.0.1}"
LICENSE="${LICENSE:-test/e2e/testdata/nomad.hclic}"
SOAK_SECONDS="${SOAK_SECONDS:-120}"
OUT="${OUT:-test/load/results-$(date +%Y%m%d-%H%M%S).txt}"

say() { printf '\n== %s ==\n' "$*"; }

# --- metrics scrape (operator's own endpoint; no metrics-server needed).
# Uses a dedicated harness SA bound to the deployed metrics-reader
# ClusterRole — the operator's own SA is deliberately NOT authorized to
# scrape itself.
ensure_scraper() {
  kubectl -n "$OPERATOR_NS" create serviceaccount loadtest-metrics 2>/dev/null || true
  kubectl create clusterrolebinding loadtest-metrics-reader     --clusterrole=nomad-enterprise-operator-metrics-reader     --serviceaccount="$OPERATOR_NS:loadtest-metrics" 2>/dev/null || true
}

scrape() {
  local label="$1"
  local token
  token=$(kubectl -n "$OPERATOR_NS" create token loadtest-metrics --duration=15m 2>/dev/null)
  kubectl -n "$OPERATOR_NS" port-forward deploy/nomad-enterprise-operator-controller-manager 18443:8443 >/dev/null 2>&1 &
  local pf=$!
  sleep 2
  {
    echo "--- scrape: $label @ $(date -u +%H:%M:%S) ---"
    curl -sk -H "Authorization: Bearer $token" https://127.0.0.1:18443/metrics 2>/dev/null |
      grep -E '^(workqueue_depth|workqueue_queue_duration_seconds_(sum|count)|workqueue_adds_total|process_resident_memory_bytes|process_cpu_seconds_total|controller_runtime_reconcile_total|controller_runtime_reconcile_time_seconds_(sum|count)|nomad_operator_nomad_api_requests_total)' |
      grep -vE '_bucket' | sort
  } >> "$OUT" || echo "(scrape failed for $label)" >> "$OUT"
  kill $pf 2>/dev/null || true
  wait $pf 2>/dev/null || true
}

# --- environment (idempotent; reuses the e2e conventions)
say "environment"
kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER" || kind create cluster --name "$KIND_CLUSTER"
docker image inspect "$IMG" >/dev/null 2>&1 || make docker-build IMG="$IMG"
kind load docker-image "$IMG" --name "$KIND_CLUSTER"
kubectl create namespace "$OPERATOR_NS" 2>/dev/null || true
make install >/dev/null
make deploy IMG="$IMG" >/dev/null
kubectl -n "$OPERATOR_NS" create secret generic nomad-license \
  --from-file=license="$LICENSE" 2>/dev/null || true
kubectl -n "$OPERATOR_NS" rollout status deploy/nomad-enterprise-operator-controller-manager --timeout=180s >/dev/null
kubectl create namespace "$NS" 2>/dev/null || true
kubectl -n "$NS" create secret generic nomad-license \
  --from-file=license="$LICENSE" 2>/dev/null || true

ensure_scraper
echo "load test: N=$N ns=$NS soak=${SOAK_SECONDS}s $(date -u)" > "$OUT"
scrape "baseline"

# --- scenario 1: create wave (thundering herd through the worker pool)
say "create wave: $N clusters"
wave_start=$(date +%s)
for i in $(seq 1 "$N"); do
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: load-$i
  namespace: $NS
spec:
  replicas: 1
  license:
    secretName: nomad-license
  persistence:
    size: ""
  services:
    external:
      type: NodePort
EOF
done

# per-cluster time-to-Ready
declare -a ready_at
pending=$N
deadline=$(( $(date +%s) + 1200 ))
while [ "$pending" -gt 0 ] && [ "$(date +%s)" -lt "$deadline" ]; do
  pending=0
  for i in $(seq 1 "$N"); do
    [ -n "${ready_at[$i]:-}" ] && continue
    phase=$(kubectl -n "$NS" get nomadcluster "load-$i" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    if [ "$phase" = "Running" ]; then
      ready_at[$i]=$(( $(date +%s) - wave_start ))
    else
      pending=$(( pending + 1 ))
    fi
  done
  [ "$pending" -gt 0 ] && sleep 5
done

{
  echo "--- create wave: per-cluster seconds to Running ---"
  for i in $(seq 1 "$N"); do echo "load-$i ${ready_at[$i]:-TIMEOUT}"; done
  printf 'wave wall-clock: %ss, still-pending: %s\n' "$(( $(date +%s) - wave_start ))" "$pending"
} >> "$OUT"
scrape "post-create-wave"

# --- scenario 2: steady-state soak
say "soak ${SOAK_SECONDS}s"
sleep "$SOAK_SECONDS"
scrape "post-soak"

# --- scenario 3: delete wave (finalizer fan-out)
say "delete wave"
del_start=$(date +%s)
kubectl -n "$NS" delete nomadcluster --all --wait=true --timeout=15m >/dev/null
{
  echo "--- delete wave ---"
  printf 'delete wall-clock: %ss\n' "$(( $(date +%s) - del_start ))"
} >> "$OUT"
scrape "post-delete-wave"

say "results: $OUT"
grep -E "wave wall-clock|delete wall-clock|still-pending" "$OUT"
