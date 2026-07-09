#!/usr/bin/env bash
# kind-up.sh — bring up a kind cluster with metallb wired into the docker
# bridge subnet so LoadBalancer Services can be allocated an IP.
#
# Driven by .github/workflows/smoke-e2e.yml; safe to run locally for
# repro purposes provided `docker`, `kind`, and `kubectl` are on PATH.
#
# Environment overrides (with defaults):
#
#   KIND_CLUSTER     — kind cluster name              (neo-smoke)
#   KIND_K8S_IMAGE   — kindest/node image tag          (kindest/node:v1.31.0)
#   METALLB_VERSION  — metallb release to install      (v0.14.8)
#
# Layout / order:
#
#   1. create the kind cluster
#   2. install metallb manifests
#   3. wait for metallb pods Ready
#   4. compute the docker `kind` bridge subnet's high-half /28 range and
#      apply an IPAddressPool + L2Advertisement so Services get a routable
#      IP from the host. This is the canonical kind+metallb recipe from
#      https://kind.sigs.k8s.io/docs/user/loadbalancer/.

set -euo pipefail

KIND_CLUSTER=${KIND_CLUSTER:-neo-smoke}
KIND_K8S_IMAGE=${KIND_K8S_IMAGE:-kindest/node:v1.31.0}
METALLB_VERSION=${METALLB_VERSION:-v0.14.8}

echo "[kind-up] cluster=${KIND_CLUSTER} image=${KIND_K8S_IMAGE} metallb=${METALLB_VERSION}"

if ! kind get clusters | grep -qx "${KIND_CLUSTER}"; then
  kind create cluster --name "${KIND_CLUSTER}" --image "${KIND_K8S_IMAGE}" --wait 120s
else
  echo "[kind-up] cluster already exists, reusing"
fi

kubectl cluster-info --context "kind-${KIND_CLUSTER}"

# metallb install + readiness gate
kubectl apply -f "https://raw.githubusercontent.com/metallb/metallb/${METALLB_VERSION}/config/manifests/metallb-native.yaml"
kubectl -n metallb-system wait --for=condition=Ready pods --all --timeout=180s

# Compute the docker kind-bridge subnet and reserve its high /28 for
# metallb. Example: kind bridge 172.18.0.0/16 → 172.18.255.200-172.18.255.250.
# The kind network is dual-stack on some hosts (GHA runners list the
# IPv6 subnet FIRST), so select the IPv4 entry explicitly — the pool
# arithmetic below is IPv4-only.
subnet=$(docker network inspect kind \
  --format '{{ range .IPAM.Config }}{{ println .Subnet }}{{ end }}' \
  | grep -m1 -E '^[0-9]+\.')
if [ -z "${subnet}" ]; then
  echo "[kind-up] no IPv4 subnet on the docker kind bridge" >&2
  exit 1
fi
base=${subnet%/*}
IFS=. read -r o1 o2 _ _ <<<"${base}"
pool_start="${o1}.${o2}.255.200"
pool_end="${o1}.${o2}.255.250"
echo "[kind-up] metallb pool ${pool_start}-${pool_end} (from kind bridge ${subnet})"

cat <<EOF | kubectl apply -f -
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: neo-smoke-pool
  namespace: metallb-system
spec:
  addresses:
  - ${pool_start}-${pool_end}
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: neo-smoke-l2
  namespace: metallb-system
spec:
  ipAddressPools:
  - neo-smoke-pool
EOF

echo "[kind-up] cluster ready with metallb LoadBalancer support"
