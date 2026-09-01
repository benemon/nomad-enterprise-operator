# Getting started

## Prerequisites

- Go v1.26+ (development only)
- Docker v20.10+
- kubectl v1.28+
- Access to a Kubernetes v1.28+ cluster (matches the CSV's
  minKubeVersion; the CRD CEL validation rules need a modern apiserver)
- A Nomad Enterprise license


## Container Images

All images are published to quay.io:

| Image | Description |
|-------|-------------|
| `quay.io/benjamin_holmes/nomad-enterprise-operator:v<version>` | Operator controller |
| `quay.io/benjamin_holmes/nomad-enterprise-operator-bundle:v<version>` | OLM bundle |
| `quay.io/benjamin_holmes/nomad-enterprise-operator-catalog:v<version>` | OLM catalog |

## Install on OpenShift (OLM)

1. Create a CatalogSource to make the operator available in OperatorHub:

    ```yaml
    apiVersion: operators.coreos.com/v1alpha1
    kind: CatalogSource
    metadata:
      name: nomad-enterprise-operator-catalog
      namespace: openshift-marketplace
    spec:
      sourceType: grpc
      image: quay.io/benjamin_holmes/nomad-enterprise-operator-catalog:v<version>
      displayName: Nomad Enterprise Operator
      publisher: benemon
      updateStrategy:
        registryPoll:
          interval: 30m
    ```

2. Create a namespace and OperatorGroup for the operator:

    ```yaml
    apiVersion: v1
    kind: Namespace
    metadata:
      name: nomad-enterprise-operator-system
    ---
    apiVersion: operators.coreos.com/v1
    kind: OperatorGroup
    metadata:
      name: nomad-enterprise-operator
      namespace: nomad-enterprise-operator-system
    spec:
      targetNamespaces:
        - nomad-enterprise-operator-system
    ```

3. Create a Subscription to install the operator:

    ```yaml
    apiVersion: operators.coreos.com/v1alpha1
    kind: Subscription
    metadata:
      name: nomad-enterprise-operator
      namespace: nomad-enterprise-operator-system
    spec:
      channel: alpha
      name: nomad-enterprise-operator
      source: nomad-enterprise-operator-catalog
      sourceNamespace: openshift-marketplace
      installPlanApproval: Automatic
    ```

Alternatively, once the CatalogSource is created, the operator appears in
the OpenShift console under **OperatorHub** and can be installed from the UI.
The suggested namespace `nomad-enterprise-operator-system` will be pre-filled.

## Install with YAML manifests

For clusters without OLM, each release attaches a consolidated `install.yaml`
containing the CRDs, RBAC, and operator Deployment pinned to that release's
image. The manifest is self-contained - no webhooks, no cert-manager. Apply it
directly:

```sh
kubectl apply -f https://github.com/benemon/nomad-enterprise-operator/releases/download/v<version>/install.yaml
```

To track the newest release instead of a pinned version, substitute
`releases/latest/download/install.yaml`.

To build the installer from a source checkout (for unreleased changes), pin the
image explicitly - the Makefile default is a placeholder version that was never
published:

```sh
make build-installer IMG=quay.io/benjamin_holmes/nomad-enterprise-operator:v<version>
kubectl apply -f dist/install.yaml
```

## Minimal Example

The only required field is `license`. Everything else uses sensible defaults (3 replicas, ACLs enabled, auto-generated gossip key, 10Gi persistent storage):

```yaml
apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: nomad
spec:
  license:
    secretName: nomad-license
```

On kind or any cluster without a load-balancer implementation, also set
`spec.services.external.type: NodePort` - the default (`LoadBalancer`)
waits indefinitely for an IP. The CI-tested quickstart at
[config/samples/minimal/nomadcluster.yaml](https://github.com/benemon/nomad-enterprise-operator/blob/main/config/samples/minimal/nomadcluster.yaml)
carries this and is verified end-to-end on every nightly run.

## Uninstall

```sh
kubectl delete -k config/samples/
make uninstall
make undeploy
```


## Complete example

A production NomadCluster with TLS, ACLs, Vault workload identity, a
snapshot schedule, and a managed autoscaler:

```yaml
apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: nomad-enterprise
spec:
  replicas: 3
  image:
    repository: hashicorp/nomad
    tag: "2.0.5-ent"
  license:
    secretName: nomad-license
  server:
    acl:
      enabled: true
    audit:
      enabled: true
    vaults:
    - defaultIdentity:
        audiences: ["vault.io"]
        ttl: "1h"
  persistence:
    size: 10Gi
  resources:
    limits:
      cpu: "2"
      memory: 2Gi
    requests:
      cpu: 500m
      memory: 1Gi
---
apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadSnapshot
metadata:
  name: hourly-backup
spec:
  clusterRef:
    name: nomad-enterprise
  schedule:
    interval: "1h"
    retain: 24
  target:
    local:
      size: 10Gi
---
apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadAutoscaler
metadata:
  name: autoscaler
spec:
  clusterRef:
    name: nomad-enterprise
  replicas: 2
  namespaces:
    - default
  monitoring:
    enabled: true
```

