[![E2E Tests](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/test-e2e.yml/badge.svg)](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/test-e2e.yml)
[![Lint](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/lint.yml/badge.svg)](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/lint.yml)
[![Tests](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/test.yml/badge.svg)](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/test.yml)

# nomad-enterprise-operator

> **Community Project** - This operator is not maintained or supported by
> HashiCorp. It is an independent community project. The `nomad.hashicorp.com`
> API group used by CRDs in this project is a structural identifier inherited
> from the Nomad ecosystem, not an endorsement or affiliation.

// TODO(user): Add simple overview of use/purpose

## Description
// TODO(user): An in-depth paragraph about your project and overview of use

## Getting Started

### Prerequisites
- go version v1.24.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

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

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

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

