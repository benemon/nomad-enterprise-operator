[![E2E Tests](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/test-e2e.yml/badge.svg)](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/test-e2e.yml)
[![Lint](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/lint.yml/badge.svg)](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/lint.yml)
[![Tests](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/test.yml/badge.svg)](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/test.yml)

# nomad-enterprise-operator

> **Community Project** - This operator is not maintained or supported by
> HashiCorp. It is an independent community project. The `nomad.hashicorp.com`
> API group used by CRDs in this project is a structural identifier inherited
> from the Nomad ecosystem, not an endorsement or affiliation.

A Kubernetes operator for deploying and managing HashiCorp Nomad Enterprise server clusters on OpenShift and Kubernetes.

## Description

The Nomad Enterprise Operator manages the full lifecycle of Nomad Enterprise server clusters through two custom resources: `NomadCluster` and `NomadSnapshot`. A `NomadCluster` resource deploys a Nomad server cluster as a StatefulSet with configurable replicas (1, 3, or 5), handling TLS certificate generation, ACL bootstrapping, gossip encryption, persistent storage, and Prometheus monitoring. On OpenShift, it can also create Routes for external access. A `NomadSnapshot` resource manages automated Nomad snapshots with support for local, S3, GCS, and Azure Blob storage backends.

## Getting Started

### Prerequisites
- Go v1.25.0+
- Docker v17.03+
- kubectl v1.11.3+
- Access to a Kubernetes v1.11.3+ cluster

### Container Images

All images are published to quay.io:

| Image | Description |
|-------|-------------|
| `quay.io/benjamin_holmes/nomad-enterprise-operator:v<version>` | Operator controller |
| `quay.io/benjamin_holmes/nomad-enterprise-operator-bundle:v<version>` | OLM bundle |
| `quay.io/benjamin_holmes/nomad-enterprise-operator-catalog:v<version>` | OLM catalog |

### Install on OpenShift (OLM)

1. Create a CatalogSource to make the operator available in OperatorHub:

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: nomad-enterprise-operator-catalog
  namespace: openshift-marketplace
spec:
  sourceType: grpc
  image: quay.io/benjamin_holmes/nomad-enterprise-operator-catalog:v0.0.1
  displayName: Nomad Enterprise Operator
  publisher: benemon
  updateStrategy:
    registryPoll:
      interval: 30m
```

2. Create a Subscription to install the operator:

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: nomad-enterprise-operator
  namespace: <target-namespace>
spec:
  channel: alpha
  name: nomad-enterprise-operator
  source: nomad-enterprise-operator-catalog
  sourceNamespace: openshift-marketplace
  installPlanApproval: Automatic
```

Alternatively, once the CatalogSource is created, the operator appears in
the OpenShift console under **OperatorHub** and can be installed from the UI.

### Install with YAML manifests

Build and apply the consolidated installer:

```sh
make build-installer IMG=quay.io/benjamin_holmes/nomad-enterprise-operator:v0.0.1
kubectl apply -f dist/install.yaml
```

### To Deploy for Development

**Build and push your image:**

```sh
make docker-build docker-push IMG=quay.io/benjamin_holmes/nomad-enterprise-operator:v0.0.1
```

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster:**

```sh
make deploy IMG=quay.io/benjamin_holmes/nomad-enterprise-operator:v0.0.1
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create sample custom resources:**

```sh
kubectl apply -k config/samples/
```

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the CRDs from the cluster:**

```sh
make uninstall
```

**Undeploy the controller from the cluster:**

```sh
make undeploy
```

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/benemon/nomad-enterprise-operator).

Run `make help` for more information on all available `make` targets.

## License

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

