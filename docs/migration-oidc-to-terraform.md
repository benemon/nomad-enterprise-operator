# Migrating OIDC configuration from the operator to Terraform

Earlier versions of the Nomad Enterprise Operator reconciled OIDC
authentication via `spec.oidc`: the operator created a Keycloak realm
(through the Keycloak operator's `KeycloakRealmImport` CR) and configured
Nomad's ACL auth method, policies, roles, and binding rules.

That integration has been removed. The operator no longer owns any OIDC
resources, the `spec.oidc` field no longer exists in the CRD schema, and
CRs that still set `spec.oidc.*` are **rejected at admission** by schema
validation.

The replacement is the
[Terraform Provider for Nomad](https://registry.terraform.io/providers/hashicorp/nomad/latest),
which manages the same Nomad-side resources declaratively and works with
any OIDC identity provider — not just Keycloak.

## Why the change

- The operator's OIDC reconciliation was a one-shot bootstrap with weak
  drift correction: `KeycloakRealmImport` creates a realm on first apply
  but never updates or deletes it.
- The Terraform provider covers the full lifecycle (create, update,
  destroy, plan-time diff) of `nomad_acl_auth_method`,
  `nomad_acl_binding_rule`, `nomad_acl_role`, and `nomad_acl_policy`.
- Removing the integration drops the operator's runtime dependency on the
  Keycloak operator and its PostgreSQL requirement.

## What the operator still does

ACL bootstrap is unchanged: the operator still bootstraps Nomad's ACL
system and stores the bootstrap token in the `<cluster>-acl-bootstrap`
Secret. Terraform uses that token (or a management token derived from it)
to manage auth methods.

## Migration steps

### 1. Capture your current OIDC state

If your cluster was configured by the operator's old `spec.oidc` support,
the relevant Nomad-side resources are:

```bash
export NOMAD_ADDR=https://<your-cluster>:4646
export NOMAD_TOKEN=$(kubectl get secret <cluster>-acl-bootstrap -o jsonpath='{.data.secret-id}' | base64 -d)

nomad acl auth-method list
nomad acl binding-rule list
nomad acl role list
nomad acl policy list
```

Note the auth method name (the operator created it as `keycloak`), the
binding rules attached to it, and the roles/policies they reference.

### 2. Express the same configuration in Terraform

Worked example, equivalent to the operator's previous default behaviour
(a `keycloak` auth method with a `nomad-admins` group bound to an
admin-equivalent role):

```hcl
terraform {
  required_providers {
    nomad = {
      source  = "hashicorp/nomad"
      version = "~> 2.0"
    }
  }
}

provider "nomad" {
  address   = "https://nomad.example.com:4646"
  secret_id = var.nomad_management_token
}

resource "nomad_acl_auth_method" "keycloak" {
  name           = "keycloak"
  type           = "OIDC"
  token_locality = "local"
  max_token_ttl  = "1h"
  default        = true

  config {
    oidc_discovery_url = "https://keycloak.example.com/realms/nomad"
    oidc_client_id     = "nomad"
    oidc_client_secret = var.oidc_client_secret
    bound_audiences    = ["nomad"]
    oidc_scopes        = ["openid", "profile", "groups"]

    allowed_redirect_uris = [
      "https://nomad.example.com:4646/oidc/callback",
      "https://nomad.example.com:4646/ui/settings/tokens",
    ]

    list_claim_mappings = {
      groups = "roles"
    }

    # Only needed when the IdP's TLS certificate is signed by a
    # private CA (the old spec.oidc.discoveryCA equivalent):
    # discovery_ca_pem = [file("${path.module}/keycloak-ca.pem")]
  }
}

resource "nomad_acl_policy" "admin" {
  name = "oidc-admin"

  rules_hcl = <<-EOT
    namespace "*" {
      policy = "write"
    }
    operator {
      policy = "write"
    }
    agent {
      policy = "write"
    }
    node {
      policy = "write"
    }
  EOT
}

resource "nomad_acl_role" "admins" {
  name = "nomad-admins"

  policy {
    name = nomad_acl_policy.admin.name
  }
}

resource "nomad_acl_binding_rule" "admins" {
  auth_method = nomad_acl_auth_method.keycloak.name
  selector    = "\"/nomad-admins\" in list.roles"
  bind_type   = "role"
  bind_name   = nomad_acl_role.admins.name
}
```

### 3. Import existing resources (avoid recreation)

If the operator already created the auth method and binding rules in
Nomad, import them instead of letting Terraform recreate them:

```bash
terraform import nomad_acl_auth_method.keycloak keycloak
terraform import nomad_acl_policy.admin oidc-admin
# Roles and binding rules import by ID — list them first:
nomad acl role list
nomad acl binding-rule list
terraform import nomad_acl_role.admins <role-id>
terraform import nomad_acl_binding_rule.admins <rule-id>
```

Run `terraform plan` and reconcile any diffs before applying.

### 4. Remove `spec.oidc` from your NomadCluster CRs

After upgrading the operator, any stored CR that still carries
`spec.oidc` will fail validation on its next update. Remove the block:

```bash
kubectl patch nomadcluster <name> --type=json \
  -p '[{"op": "remove", "path": "/spec/oidc"}]'
```

(If the field is already absent — e.g. the CR was created after the
upgrade — this returns an error you can ignore.)

### 5. Clean up orphaned Kubernetes resources

The operator no longer deletes its previously created OIDC artefacts on
cluster deletion. If you are not importing them into Terraform, remove
them manually:

```bash
# The realm import CR (realm itself must be deleted in Keycloak admin):
kubectl delete keycloakrealmimport <cluster-realm-name> --ignore-not-found

# The generated OIDC client secret:
kubectl delete secret <cluster>-oidc-client --ignore-not-found
```

The Keycloak realm is **not** deleted by removing the
`KeycloakRealmImport` CR — delete it via the Keycloak admin console or
API if it is no longer needed.

## Field mapping reference

| Old `spec.oidc` field | Terraform equivalent |
|---|---|
| `oidc.enabled` | (presence of `nomad_acl_auth_method`) |
| `oidc.keycloakRef.name` | n/a — provider talks to Nomad, not Keycloak |
| `oidc.realm` | `config.oidc_discovery_url` (realm is part of the URL) |
| `oidc.discoveryCA.secretName`/`secretKey` | `config.discovery_ca_pem` |
| `oidc.bindingRules[].keycloakGroup` | `nomad_acl_binding_rule.selector` |
| `oidc.bindingRules[].nomadRole` | `nomad_acl_binding_rule.bind_name` + `nomad_acl_role` |
| `oidc.bindingRules[].policyRules` | `nomad_acl_policy.rules_hcl` |
