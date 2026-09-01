# Keyrings

Nomad's root encryption keys - which protect Variables and sign
workload identities - are wrapped by a **keyring**. The default (`aead`)
stores its key-encryption key **in cleartext inside Raft**, which means
every Raft snapshot carries usable key material:

> **Snapshot custody is key custody.** On an `aead` cluster (the
> default), anyone who can read a snapshot - including the object-store
> bucket a `NomadSnapshot` uploads to - can decrypt that cluster's
> Variables and mint workload identities. Configure an external KMS
> keyring before treating snapshot storage as anything less than a
> copy of your keys.

With an external KMS keyring, only *wrapped* keys ride Raft: snapshots
remain complete for disaster recovery and are safe at rest - a restore
decrypts if and only if the restoring cluster can reach the KMS.

Four providers are supported, singly or as an HA set (every listed
keyring wraps new keys; any one reachable keyring unwraps):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.keyrings[].name` | `string` | | Entry name (unique, ≤63 chars) |
| `server.keyrings[].awskms` | `object` | | AWS KMS: `kmsKeyID` (required), `region`, `endpoint`, `credentialsSecretRef` |
| `server.keyrings[].azurekeyvault` | `object` | | Azure Key Vault / Managed HSM: `vaultName`, `keyName`, `tenantID` (required), `environment`, `resource`, `credentialsSecretRef` |
| `server.keyrings[].gcpckms` | `object` | | GCP Cloud KMS: `project`, `region`, `keyRing`, `cryptoKey` (all required), `credentialsSecretRef` |
| `server.keyrings[].transit` | `object` | | Vault transit: `address`, `keyName`, `mountPath` (required), `namespace`, `keyIDPrefix`, `tlsServerName`, `caSecretRef`, `clientCertSecretRef`, `auth` (required) |

When `credentialsSecretRef` is set, the keyring uses static
credentials from the referenced Secret, and rotating that Secret rolls
the server pods automatically. When it is omitted, the cloud SDKs fall
back to ambient identity - but only **node-level** identities (EC2
instance roles, GKE node service accounts, Azure VM managed identity)
work without extra wiring. Pod-level identity needs platform metadata
the CRD does not yet expose: IRSA and GKE Workload Identity require
annotating the operator-created ServiceAccount out-of-band and then
rolling the server pods (the credential-injection webhooks act at pod
admission), and Azure Workload Identity is not currently usable - it
requires a pod label the operator does not render. Same-type HA pairs
- two AWS KMS keys in different regions or accounts, two Azure vaults,
two GCP keys - carry their credentials per entry, so each member of
the pair may use a different identity.

**Changing the keyring set is a live migration.** Enable, disable,
provider change, and HA expand/contract all follow the same
operator-managed cycle: render the union of old and new keyrings, roll
the servers, rotate every root key under the new set, remove the old
keys, retire the demoted keyrings, and roll once more.
`status.keyring` reports `phase` (`Ready`, `Introducing`, `Rotating`,
`Retiring`, `Degraded`), the `active` and `retiring` sets,
`retirementPending` while old keys await removal, and `tokenExpiry`
when the operator manages a Vault token. Once rotation under the new
set succeeds, the phase is `Ready`; old-key removal continues in the
background while `retiring` remains populated.

On live clusters, old-key retirement follows workload-identity claim
expiry. Identities without TTLs can defer retirement until their
workloads churn, so set identity TTLs as the
`server.vaults[].defaultIdentity.ttl` examples below model. The operator
reports the remaining old-key count in `retirementPending` and emits a
debounced Normal `KeyringRetirementPending` Event. `Degraded` means
the state machine is settled but Nomad itself reports the keyring
inoperable - config delivery is not initialization, so the operator
probes Nomad's own key list and emits a `KeyringNotInitialized` Warning
Event naming the cause (typically unreachable KMS or a bad CA). A
cluster with keyrings removed parks on an explicit `aead` keyring
permanently - its keys are not loadable by the implicit default, so the
operator never collapses back.

**Editing an entry in place (same `name`) is a credential fix, not a
migration.** The operator replaces the entry (emitting a
`KeyringEntryUpdated` Event), re-renders, and rolls - no key rotation
runs, because the wrapper is unchanged. Consequently,
changing where an entry points - a different Vault, mount, or key -
must be done under a **new entry name** so the old wrapper retires
through the migration cycle and existing root keys are re-wrapped;
editing the target in place would leave previously wrapped keys
unloadable.

## Transit authentication (`transit.auth`)

The transit provider authenticates to Vault through one of **four
credential vectors**, selected by `auth.method`. The structure mirrors
the Vault Secrets Operator's `VaultAuth` (`method: token` is our
extension - VSO has no static-token method):

```yaml
# 1. Long-lived Vault token, minted and rotated by you
auth:
  method: token
  token:
    secretRef:
      name: my-vault-token        # Secret key: VAULT_TOKEN

# 2. Long-lived Kubernetes ServiceAccount token, minted by you,
#    exchanged for a Vault token at a kubernetes auth mount
auth:
  method: kubernetes
  mount: kubernetes
  kubernetes:
    role: nomad-keyring
    serviceAccountTokenSecretRef:
      name: my-sa-jwt             # Secret key: token

# 3. Ephemeral ServiceAccount token (RECOMMENDED) - the operator mints
#    a short-lived, audience-bound TokenRequest JWT for the cluster's
#    own ServiceAccount, uses it once to log in, and never stores it
auth:
  method: kubernetes
  mount: kubernetes
  kubernetes:
    role: nomad-keyring
    audiences: ["vault"]          # default
    tokenExpirationSeconds: 600   # default

# 4. ServiceAccount token validated as a JWT (no TokenReview) - the
#    jwt auth mount verifies the signature against the cluster's JWKS
auth:
  method: jwt
  mount: jwt
  jwt:
    role: nomad-keyring           # same source choice as kubernetes:
                                  # ephemeral default, or secretRef
```

For the login methods (2–4) the operator logs in per entry, renews the
token on the reconcile heartbeat (no pod restart), and re-mints on
failure or revocation (rolls pods). For `method: token` the lifecycle
is yours; rotating your Secret rolls the pods. In every vector the
resolved token is rendered inline into that entry's keyring block -
see below.

Transit HA works across **independent Vault clusters**: each entry
carries its own `address` and its own `auth` (any vector), so either
Vault surviving keeps the cluster's keys decryptable. Give each entry
a distinct `keyIDPrefix` - Nomad's wrapped-key disambiguation. Each
entry's resolved token is rendered inline into that entry's keyring
block in the generated server configuration, which the operator stores
as a Secret (the same custody class as the gossip key it also
carries); tokens never appear in the `NomadCluster` manifest.

## Who needs `system:auth-delegator`

The kubernetes auth method validates ServiceAccount tokens via the
TokenReview API, and the identity making that call needs the
`system:auth-delegator` ClusterRole. Which identity that is depends on
the Vault mount configuration - **the operator never creates
ClusterRoleBindings**; grant it per this table:

| Mount configuration | TokenReview caller | Grant `auth-delegator` to |
|---------------------|--------------------|---------------------------|
| `token_reviewer_jwt` configured | that JWT's identity | the reviewer's ServiceAccount |
| No reviewer JWT; Vault runs in Kubernetes (default `disable_local_ca_jwt=false`) | Vault's own pod ServiceAccount | Vault's pod ServiceAccount |
| No reviewer JWT; Vault outside Kubernetes (or `disable_local_ca_jwt=true`) | the client's login JWT | the **cluster's** ServiceAccount - and the login JWT must be API-server-valid (vector 2, or vector 3 with API-server audience) |
| `jwt` auth method | nobody (JWKS signature check) | nobody |

The API-server-valid caveat in the last row is load-bearing: the
operator's default `audiences` is `["vault"]` (VSO convention), and a
`vault`-audience JWT cannot authenticate to the apiserver to perform
its own TokenReview - login fails with `permission denied`. Against
external Vault, either set `audiences: ["https://kubernetes.default.svc"]`
(and the matching `audience` on the Vault role), or configure a
`token_reviewer_jwt` on the auth method. Verified live against Vault
Enterprise on OpenShift.

A denied TokenReview surfaces on the cluster as the
`KeyringVaultReviewerDenied` condition reason with this table's
remediation.


