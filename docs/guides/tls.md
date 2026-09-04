# TLS and trust

mTLS is always enabled - no configuration is required. The operator automatically:

- Generates a self-signed ECDSA P-256 CA (or uses a user-provided CA)
- Issues server certificates with the Nomad SANs: `server.<region>.nomad`, a wildcard covering every server pod (`*.<cluster>-headless.<ns>.svc.cluster.local`), and the internal service FQDNs. The wildcard keeps the certificate identical at every replica count, so scaling never re-issues it
- Distributes a CA bundle ConfigMap for external consumers
- Rotates certificates approaching expiry (30-day warning window)
- Configures `verify_server_hostname = true` in the Nomad HCL for RPC mTLS
- Sets `verify_https_client = false` - the HTTP API is TLS-encrypted but does not require client certificates, allowing the UI, CLI, and OpenShift Routes to connect without distributing client certs. ACLs handle authorization
- Sets OpenShift Routes to `reencrypt` termination with the CA as `destinationCACertificate`

**A documented divergence from the validated design.** For load
balancers in front of Nomad, the guidance is:

> Use TLS passthrough - the load balancer forwards encrypted traffic
> without terminating it, and Nomad terminates TLS itself.

*- HashiCorp Validated Design: Nomad Enterprise Solution Design Guide*

The operator's OpenShift Route deliberately uses `reencrypt` instead:
the Route terminates with a platform (or user-supplied) certificate
and re-establishes TLS to Nomad, verifying the cluster CA as
`destinationCACertificate`. Traffic stays encrypted on every segment
- the difference is a verified re-termination at the Route rather
than blind passthrough - and in exchange the Route gets platform
hostname routing and certificate management. Clients that require an
unterminated TLS session to Nomad should use the external
LoadBalancer/NodePort Service directly rather than the Route.

## Generated Secrets

The operator creates the following resources in the cluster namespace:

| Resource | Kind | Description |
|----------|------|-------------|
| `<cluster>-ca` | Secret | CA certificate and private key (`tls.crt`, `tls.key`). Not created when using a user-provided CA |
| `<cluster>-tls` | Secret | Server certificate and key (`tls.crt`, `tls.key`, `ca.crt`) |
| `<cluster>-ca-bundle` | ConfigMap | CA certificate for external consumers |
| `<cluster>-config` | Secret | Rendered `server.hcl` - Secret-class because it carries the gossip encryption key and any inline keyring credentials |
| `<cluster>-keyring-token` | Secret | Operator-minted Vault tokens for keyring login vectors, one key per entry (operator-internal; pods consume tokens via the rendered config) |

## Operator-managed CA (default)

A minimal CR gets full mTLS with zero TLS configuration:

```yaml
apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: nomad
spec:
  license:
    secretName: nomad-license
```

**CA lifetime and rotation.** The operator-generated CA is valid for
**2 years** - deliberately short so a leaked or compromised CA key has a
bounded blast radius (the CA private key lives in a namespace Secret;
anyone who can read it can mint certificates trusted by the cluster
until the CA expires). **The operator rotates it automatically**: 30
days before expiry it introduces a new CA and walks the cluster through
a zero-trust-gap rollover -

1. *Introduce*: a new CA is generated and every pod is rolled onto a
   trust bundle containing **both** CAs (a `CARotationStarted` Event
   marks this).
2. *Cutover*: once every pod trusts both, the new CA becomes the
   signer, server certificates are reissued from it, and pods roll
   again (`CARotationCompleted`). The old CA's private key is
   destroyed; its certificate stays in the trust bundle.
3. *Retire*: when the old CA certificate finally expires it drops out
   of the trust bundle on its own.

Every rotation stage serves a trust union covering both CAs (pinned by
the rotation tests), and rotation state lives in the `<cluster>-ca`
Secret rather than operator memory, so an operator restart resumes the
rotation from the recorded stage. Status signals:

- `status.certificateAuthority.expiryTime` - when the active CA expires.
- `status.certificateAuthority.renewalRequiredBy` - for
  operator-generated CAs, when rotation will start; for **user-provided
  CAs**, when *you* must renew - the operator never rotates a CA it
  does not own, and instead emits a one-shot `CARenewalRequired`
  Warning Event when this deadline passes. The `Ready` condition stays
  `True` either way.

To force an early rotation, delete the `<cluster>-ca` Secret; the
operator generates a fresh CA and reissues server certificates on the
next reconcile (this hard-cut path skips the dual-trust overlap - plan
a rolling restart).

## User-provided CA

Supply your own CA and the operator issues certificates from it. The CA secret must contain a certificate and private key.

```yaml
apiVersion: nomad.hashicorp.com/v1alpha1
kind: NomadCluster
metadata:
  name: nomad
spec:
  license:
    secretName: nomad-license
  server:
    tls:
      ca:
        secretName: my-ca-secret  # must contain tls.crt and tls.key
```


## Trust bundle (`spec.trustBundle`)

The Nomad Enterprise operand image ships without CA roots. Cloud
keyrings (`awskms`, `azurekeyvault`, and `gcpckms`) and cloud snapshot
targets therefore need a trust bundle to verify public TLS endpoints.
The operator mounts the selected ConfigMap into server and snapshot-agent
pods as `/etc/ssl/certs/ca-certificates.crt`.

On OpenShift, leave `spec.trustBundle` unset. When
`spec.openshift.enabled: true`, the operator creates
`<cluster>-trust-bundle` with
`config.openshift.io/inject-trusted-cabundle: "true"`; the OpenShift
network operator injects the platform trust bundle. Note that the
injected bundle carries public roots and proxy CAs, not the OpenShift
service CA - endpoints presenting service-serving certificates (for
example an in-cluster S3-compatible `.svc` endpoint as a snapshot
target) will fail verification. If you need the full chain, render your
own bundle (for example the injected bundle concatenated with your
namespace's `openshift-service-ca.crt`) and reference it as a custom
ConfigMap like any other bundle. On other platforms,
reference a ConfigMap containing your CA bundle, or bake CA roots into a
custom operand image. Changing bundle content changes the server pod
checksum and rolls the StatefulSet.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `trustBundle.configMapRef.name` | `string` | | ConfigMap in the NomadCluster namespace containing the CA bundle |
| `trustBundle.key` | `string` | `ca-bundle.crt` | ConfigMap key containing the PEM bundle |

Transit keyrings can still use `caSecretRef` as a per-entry override.
Private CA roots shared across providers can instead be consolidated in
the trust bundle.


