#!/usr/bin/env bash
# Seeds a Keycloak realm with groups and test users matching the default OIDC binding rules.
# Usage: ./hack/seed-keycloak-users.sh [realm] [namespace]

set -euo pipefail

REALM="${1:-nomad-enterprise}"
NAMESPACE="${2:-nomad-operator-demo}"
KC_POD="keycloak-0"
CFG="/tmp/kcadm-seed.config"

# Discover admin credentials from the initial-admin secret
ADMIN_USER=$(kubectl get secret keycloak-initial-admin -n "$NAMESPACE" -o jsonpath='{.data.username}' | base64 -d)
ADMIN_PASS=$(kubectl get secret keycloak-initial-admin -n "$NAMESPACE" -o jsonpath='{.data.password}' | base64 -d)

echo "Authenticating to Keycloak as $ADMIN_USER"
kubectl exec -n "$NAMESPACE" "$KC_POD" -- /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 --realm master \
  --user "$ADMIN_USER" --password "$ADMIN_PASS" \
  --config "$CFG"

# --- Groups ---
echo "Creating groups..."
ADMINS_ID=$(kubectl exec -n "$NAMESPACE" "$KC_POD" -- /opt/keycloak/bin/kcadm.sh create groups \
  --config "$CFG" -r "$REALM" -s name=nomad-admins 2>&1 | grep -o "'[^']*'" | tr -d "'")
echo "  nomad-admins: $ADMINS_ID"

READERS_ID=$(kubectl exec -n "$NAMESPACE" "$KC_POD" -- /opt/keycloak/bin/kcadm.sh create groups \
  --config "$CFG" -r "$REALM" -s name=nomad-readers 2>&1 | grep -o "'[^']*'" | tr -d "'")
echo "  nomad-readers: $READERS_ID"

# --- Admin user ---
echo "Creating user: nomad-admin (password: nomad-admin)"
ADMIN_UID=$(kubectl exec -n "$NAMESPACE" "$KC_POD" -- /opt/keycloak/bin/kcadm.sh create users \
  --config "$CFG" -r "$REALM" \
  -s username=nomad-admin \
  -s email=admin@nomad.local \
  -s firstName=Nomad \
  -s lastName=Admin \
  -s enabled=true \
  -s emailVerified=true \
  -s 'credentials=[{"type":"password","value":"nomad-admin","temporary":false}]' 2>&1 | grep -o "'[^']*'" | tr -d "'")
echo "  user id: $ADMIN_UID"

kubectl exec -n "$NAMESPACE" "$KC_POD" -- /opt/keycloak/bin/kcadm.sh update "users/$ADMIN_UID/groups/$ADMINS_ID" \
  --config "$CFG" -r "$REALM" \
  -s realm="$REALM" -s userId="$ADMIN_UID" -s groupId="$ADMINS_ID" -n
echo "  added to nomad-admins"

# --- Reader user ---
echo "Creating user: nomad-reader (password: nomad-reader)"
READER_UID=$(kubectl exec -n "$NAMESPACE" "$KC_POD" -- /opt/keycloak/bin/kcadm.sh create users \
  --config "$CFG" -r "$REALM" \
  -s username=nomad-reader \
  -s email=reader@nomad.local \
  -s firstName=Nomad \
  -s lastName=Reader \
  -s enabled=true \
  -s emailVerified=true \
  -s 'credentials=[{"type":"password","value":"nomad-reader","temporary":false}]' 2>&1 | grep -o "'[^']*'" | tr -d "'")
echo "  user id: $READER_UID"

kubectl exec -n "$NAMESPACE" "$KC_POD" -- /opt/keycloak/bin/kcadm.sh update "users/$READER_UID/groups/$READERS_ID" \
  --config "$CFG" -r "$REALM" \
  -s realm="$REALM" -s userId="$READER_UID" -s groupId="$READERS_ID" -n
echo "  added to nomad-readers"

echo ""
echo "Done. Test users:"
echo "  nomad-admin  / nomad-admin   -> group: nomad-admins"
echo "  nomad-reader / nomad-reader  -> group: nomad-readers"
