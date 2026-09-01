[![E2E Tests](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/test-e2e.yml/badge.svg)](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/test-e2e.yml)
[![Lint](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/lint.yml/badge.svg)](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/lint.yml)
[![Tests](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/test.yml/badge.svg)](https://github.com/benemon/nomad-enterprise-operator/actions/workflows/test.yml)

# nomad-enterprise-operator

> **Community project** - this operator is not maintained or supported by
> HashiCorp. It is an independent community project. The
> `nomad.hashicorp.com` API group used by CRDs in this project is a
> structural identifier inherited from the Nomad ecosystem, not an
> endorsement or affiliation.

A Kubernetes operator for deploying and managing HashiCorp Nomad
Enterprise server clusters on OpenShift and Kubernetes.

Running a Nomad control plane means owning certificate issuance and
rotation, gossip and root-key custody, ACL bootstrap, audit logging,
snapshots, and upgrades. This operator makes that lifecycle declarative
through three custom resources:

- **`NomadCluster`** - a production-shaped server cluster: mTLS
  everywhere, ACLs bootstrapped automatically, audit logging, external
  KMS keyrings, Vault workload identity, Pod Security `restricted`.
- **`NomadSnapshot`** - scheduled or one-shot Raft snapshots to a local
  PVC, S3, GCS, or Azure Blob storage.
- **`NomadAutoscaler`** - managed Nomad Autoscaler agents, including
  Dynamic Application Sizing.

The operator manages server clusters only - Nomad clients run outside
Kubernetes and are out of scope. See
[architectural boundaries](https://benemon.github.io/nomad-enterprise-operator/#architectural-boundaries).

## Quick start

The only required field is a Nomad Enterprise license. Everything else
defaults sensibly (3 replicas, ACLs enabled, auto-generated gossip key,
10Gi persistent storage):

```yaml
apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: nomad
spec:
  license:
    secretName: nomad-license
```

Install on OpenShift via OLM, or on any cluster from the release
manifest:

```sh
kubectl apply -f https://github.com/benemon/nomad-enterprise-operator/releases/latest/download/install.yaml
```

Full installation options, the CRD references, guides for TLS,
keyrings, workload identity, monitoring and scaling, the runbooks, and
the security material - including the
[threat model](docs/threat-model/README.md) - are in the
**[documentation](https://benemon.github.io/nomad-enterprise-operator/)**.

## Contributing

Bugs and feature requests are welcome as GitHub issues. The design
principles, test bar, and local gates are in
[CONTRIBUTING.md](CONTRIBUTING.md).

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
