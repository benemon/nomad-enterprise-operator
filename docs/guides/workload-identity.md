# Vault workload identity

Nomad servers refuse any job carrying a `vault {}` block unless the
server configuration declares the Vault cluster:

> Error submitting job: Unexpected response code: 500 (rpc error:
> \* Vault "default" not enabled but used in the job)

`spec.server.vaults` declares those clusters. The flow is
**secret-free by design**: under workload identity federation the
servers never authenticate to Vault - declaring the cluster is enough
to admit jobs and to stamp a default identity into them. Connection
and auth settings (`address`, `namespace`, `jwt_auth_backend_path`,
TLS) are client-side configuration, and Nomad clients are outside the
operator's scope (see
[Architectural boundaries](../index.md#architectural-boundaries)).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.vaults[].name` | `string` | `default` | Cluster name jobs reference via `vault.cluster`; `default` serves jobs that do not specify one. Unique, ≤63 chars |
| `server.vaults[].defaultIdentity` | `object` | | Identity injected into tasks whose `vault` block declares no `identity` of its own |
| `server.vaults[].defaultIdentity.audiences` | `[]string` | | Required within `defaultIdentity`; must match the JWT auth method's `bound_audiences` |
| `server.vaults[].defaultIdentity.ttl` | `string` | | Identity JWT validity (Nomad duration, e.g. `"1h"`). Unset means no expiry - set it to bound the replay window |
| `server.vaults[].defaultIdentity.extraClaims` | `map` | | Extra identity claims; values may use Nomad interpolation (`${job.id}`, `${alloc.id}`, ...) |

`defaultIdentity` is what removes per-job boilerplate. Declaring:

```yaml
spec:
  server:
    vaults:
    - defaultIdentity:
        audiences: ["vault.io"]
        ttl: "1h"
```

lets a job consume Vault secrets with nothing but a role and a
template - no `identity` block anywhere:

```hcl
job "web" {
  group "app" {
    task "server" {
      driver = "docker"

      vault {
        role = "web" # jwt auth role bound to this job's identity claims
      }

      template {
        data        = <<EOH
{{ with secret "secret/data/web" }}API_KEY={{ .Data.data.api_key }}{{ end }}
EOH
        destination = "secrets/app.env"
        env         = true
      }
    }
  }
}
```

Multiple entries and non-`default` names are Nomad Enterprise
capabilities; a job selects one with `vault { cluster = "secondary" }`,
and a job naming an undeclared cluster is rejected at submission.

**The identity JWT is never exposed to tasks by default.** The
cluster-wide default deliberately omits Nomad's `env`/`file` identity
options: making every defaulted task hold a login-capable credential
is the wrong altitude for a cluster setting. A task that needs the raw
JWT (app-side Vault login, or presenting it to a JWKS-validating third
party) declares its own jobspec `identity` block, which takes
precedence over the default.

**Setting or changing `spec.server.vaults` rolls the server
StatefulSet** (rendered config change), like every server-config
field.

Vault-side prerequisites (outside the operator): a `jwt` auth method
whose `jwks_url` points at the cluster's JWKS endpoint -
`https://<name>-internal.<namespace>.svc.cluster.local:4646/.well-known/jwks.json`
with `jwks_ca_pem` set to the cluster CA - plus roles and policies
bound to the identity claims (`nomad_namespace`, `nomad_job_id`, and
any `extraClaims`). Client-side, each cluster name maps to an address
in the Nomad client's own `vault` stanza.


