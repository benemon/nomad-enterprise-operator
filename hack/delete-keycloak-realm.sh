#!/usr/bin/env bash
# Deletes a Keycloak realm directly from PostgreSQL.
# Usage: ./hack/delete-keycloak-realm.sh <realm-id> [namespace] [postgres-pod]
#
# Keycloak's import is not idempotent and can leave ghost realms that the
# admin API refuses to delete. This script bypasses Keycloak and removes the
# realm plus all child rows in a single transaction.

set -euo pipefail

REALM_ID="${1:?Usage: $0 <realm-id> [namespace] [postgres-pod]}"
NAMESPACE="${2:-nomad-operator-demo}"
PG_POD="${3:-$(kubectl get pods -n "$NAMESPACE" -l name=postgresql -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")}"

if [[ -z "$PG_POD" ]]; then
  # fallback: find any postgresql pod
  PG_POD="$(kubectl get pods -n "$NAMESPACE" --no-headers | grep postgresql | grep Running | awk '{print $1}' | head -1)"
fi

if [[ -z "$PG_POD" ]]; then
  echo "ERROR: could not find a PostgreSQL pod in namespace $NAMESPACE" >&2
  exit 1
fi

echo "Deleting realm '$REALM_ID' via $PG_POD in namespace $NAMESPACE"

kubectl exec -n "$NAMESPACE" "$PG_POD" -- psql -U keycloak -d keycloak -c "
BEGIN;

-- Components
DELETE FROM component_config WHERE component_id IN (SELECT id FROM component WHERE realm_id = '$REALM_ID');
DELETE FROM component WHERE realm_id = '$REALM_ID';

-- Auth flows
DELETE FROM authenticator_config WHERE realm_id = '$REALM_ID';
DELETE FROM authentication_execution WHERE realm_id = '$REALM_ID';
DELETE FROM authentication_flow WHERE realm_id = '$REALM_ID';

-- Client scopes
DELETE FROM protocol_mapper_config WHERE protocol_mapper_id IN (SELECT id FROM protocol_mapper WHERE client_scope_id IN (SELECT id FROM client_scope WHERE realm_id = '$REALM_ID'));
DELETE FROM protocol_mapper WHERE client_scope_id IN (SELECT id FROM client_scope WHERE realm_id = '$REALM_ID');
DELETE FROM client_scope_role_mapping WHERE scope_id IN (SELECT id FROM client_scope WHERE realm_id = '$REALM_ID');
DELETE FROM client_scope_attributes WHERE scope_id IN (SELECT id FROM client_scope WHERE realm_id = '$REALM_ID');
DELETE FROM client_scope WHERE realm_id = '$REALM_ID';

-- Clients
DELETE FROM protocol_mapper_config WHERE protocol_mapper_id IN (SELECT id FROM protocol_mapper WHERE client_id IN (SELECT id FROM client WHERE realm_id = '$REALM_ID'));
DELETE FROM protocol_mapper WHERE client_id IN (SELECT id FROM client WHERE realm_id = '$REALM_ID');
DELETE FROM client_attributes WHERE client_id IN (SELECT id FROM client WHERE realm_id = '$REALM_ID');
DELETE FROM redirect_uris WHERE client_id IN (SELECT id FROM client WHERE realm_id = '$REALM_ID');
DELETE FROM web_origins WHERE client_id IN (SELECT id FROM client WHERE realm_id = '$REALM_ID');
DELETE FROM scope_mapping WHERE client_id IN (SELECT id FROM client WHERE realm_id = '$REALM_ID');
DELETE FROM client_scope_client WHERE client_id IN (SELECT id FROM client WHERE realm_id = '$REALM_ID');
DELETE FROM client_node_registrations WHERE client_id IN (SELECT id FROM client WHERE realm_id = '$REALM_ID');
DELETE FROM client_initial_access WHERE realm_id = '$REALM_ID';
DELETE FROM client WHERE realm_id = '$REALM_ID';

-- Roles
DELETE FROM composite_role WHERE child_role IN (SELECT id FROM keycloak_role WHERE realm = '$REALM_ID');
DELETE FROM composite_role WHERE composite IN (SELECT id FROM keycloak_role WHERE realm = '$REALM_ID');
DELETE FROM keycloak_role WHERE realm = '$REALM_ID';

-- Users
DELETE FROM user_group_membership WHERE user_id IN (SELECT id FROM user_entity WHERE realm_id = '$REALM_ID');
DELETE FROM user_role_mapping WHERE user_id IN (SELECT id FROM user_entity WHERE realm_id = '$REALM_ID');
DELETE FROM user_required_action WHERE user_id IN (SELECT id FROM user_entity WHERE realm_id = '$REALM_ID');
DELETE FROM credential WHERE user_id IN (SELECT id FROM user_entity WHERE realm_id = '$REALM_ID');
DELETE FROM user_attribute WHERE user_id IN (SELECT id FROM user_entity WHERE realm_id = '$REALM_ID');
DELETE FROM federated_identity WHERE user_id IN (SELECT id FROM user_entity WHERE realm_id = '$REALM_ID');
DELETE FROM user_consent_client_scope WHERE user_consent_id IN (SELECT id FROM user_consent WHERE user_id IN (SELECT id FROM user_entity WHERE realm_id = '$REALM_ID'));
DELETE FROM user_consent WHERE user_id IN (SELECT id FROM user_entity WHERE realm_id = '$REALM_ID');
DELETE FROM user_entity WHERE realm_id = '$REALM_ID';

-- Groups
DELETE FROM group_role_mapping WHERE group_id IN (SELECT id FROM keycloak_group WHERE realm_id = '$REALM_ID');
DELETE FROM group_attribute WHERE group_id IN (SELECT id FROM keycloak_group WHERE realm_id = '$REALM_ID');
DELETE FROM keycloak_group WHERE realm_id = '$REALM_ID';

-- Identity providers
DELETE FROM identity_provider_mapper WHERE realm_id = '$REALM_ID';
DELETE FROM identity_provider WHERE realm_id = '$REALM_ID';

-- Federation
DELETE FROM user_federation_mapper WHERE realm_id = '$REALM_ID';
DELETE FROM user_federation_provider WHERE realm_id = '$REALM_ID';

-- Required actions
DELETE FROM required_action_provider WHERE realm_id = '$REALM_ID';

-- Realm direct children
DELETE FROM default_client_scope WHERE realm_id = '$REALM_ID';
DELETE FROM realm_attribute WHERE realm_id = '$REALM_ID';
DELETE FROM realm_default_groups WHERE realm_id = '$REALM_ID';
DELETE FROM realm_enabled_event_types WHERE realm_id = '$REALM_ID';
DELETE FROM realm_events_listeners WHERE realm_id = '$REALM_ID';
DELETE FROM realm_required_credential WHERE realm_id = '$REALM_ID';
DELETE FROM realm_smtp_config WHERE realm_id = '$REALM_ID';
DELETE FROM realm_supported_locales WHERE realm_id = '$REALM_ID';
DELETE FROM realm_localizations WHERE realm_id = '$REALM_ID';

-- Realm
DELETE FROM realm WHERE id = '$REALM_ID';

-- Master-realm orphans: Keycloak creates a service client (<realm>-realm) and
-- a default-roles-<realm> role in the master realm when a realm is created.
-- These are not cleaned up by deleting the realm's own rows.

-- default-roles-<realm> role (may have empty realm field)
DELETE FROM composite_role WHERE child_role IN (SELECT id FROM keycloak_role WHERE name = 'default-roles-$REALM_ID');
DELETE FROM composite_role WHERE composite IN (SELECT id FROM keycloak_role WHERE name = 'default-roles-$REALM_ID');
DELETE FROM keycloak_role WHERE name = 'default-roles-$REALM_ID';

-- <realm>-realm service client in master
DELETE FROM composite_role WHERE child_role IN (SELECT id FROM keycloak_role WHERE client IN (SELECT id FROM client WHERE client_id = '${REALM_ID}-realm'));
DELETE FROM composite_role WHERE composite IN (SELECT id FROM keycloak_role WHERE client IN (SELECT id FROM client WHERE client_id = '${REALM_ID}-realm'));
DELETE FROM keycloak_role WHERE client IN (SELECT id FROM client WHERE client_id = '${REALM_ID}-realm');
DELETE FROM scope_mapping WHERE client_id IN (SELECT id FROM client WHERE client_id = '${REALM_ID}-realm');
DELETE FROM client_scope_client WHERE client_id IN (SELECT id FROM client WHERE client_id = '${REALM_ID}-realm');
DELETE FROM protocol_mapper_config WHERE protocol_mapper_id IN (SELECT id FROM protocol_mapper WHERE client_id IN (SELECT id FROM client WHERE client_id = '${REALM_ID}-realm'));
DELETE FROM protocol_mapper WHERE client_id IN (SELECT id FROM client WHERE client_id = '${REALM_ID}-realm');
DELETE FROM client_attributes WHERE client_id IN (SELECT id FROM client WHERE client_id = '${REALM_ID}-realm');
DELETE FROM redirect_uris WHERE client_id IN (SELECT id FROM client WHERE client_id = '${REALM_ID}-realm');
DELETE FROM web_origins WHERE client_id IN (SELECT id FROM client WHERE client_id = '${REALM_ID}-realm');
DELETE FROM client WHERE client_id = '${REALM_ID}-realm';

COMMIT;
"

echo "Deleting KeycloakRealmImport CRs..."
kubectl delete keycloakrealmimport -n "$NAMESPACE" --all 2>/dev/null || true

echo "Restarting Keycloak to clear caches..."
kubectl delete pod keycloak-0 -n "$NAMESPACE" 2>/dev/null || true

echo "Done."
