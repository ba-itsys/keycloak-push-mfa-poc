#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/confirm-login.sh <confirm-token>

Environment overrides:
  TOKEN_ENDPOINT           OIDC token endpoint (default: http://localhost:8080/realms/push-mfa/protocol/openid-connect/token)
  DEVICE_STATE_DIR         Directory storing device state from enroll.sh (default: scripts/device-state)
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -ne 1 ]]; then
  usage
  exit $([[ $# -eq 1 ]] && [[ ${1:-} != "-h" && ${1:-} != "--help" ]] && echo 1 || echo 0)
fi

CONFIRM_TOKEN=$1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEVICE_STATE_DIR=${DEVICE_STATE_DIR:-"$REPO_ROOT/scripts/device-state"}

if [[ ! -d "$DEVICE_STATE_DIR" ]]; then
  echo "error: device state directory '$DEVICE_STATE_DIR' does not exist" >&2
  exit 1
fi

b64urlencode() {
  python3 -c "import base64, sys; data = sys.stdin.buffer.read(); print(base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii'))"
}

b64urldecode() {
  python3 -c 'import sys, base64
s = sys.stdin.read().strip()
s += "=" * (-len(s) % 4)  # fix missing padding
sys.stdout.buffer.write(base64.urlsafe_b64decode(s))'
}

echo ">> Decoding confirm token"
CONFIRM_PAYLOAD=$(echo -n "$CONFIRM_TOKEN" | cut -d'.' -f2 | b64urldecode)

if [[ -z $CONFIRM_PAYLOAD ]]; then
  echo "error: invalid confirm token" >&2
  exit 1
fi

PSEUDONYMOUS_ID=$(echo "$CONFIRM_PAYLOAD" | jq -r '.sub')
CHALLENGE_ID=$(echo "$CONFIRM_PAYLOAD" | jq -r '.cid // empty')
if [[ -z $PSEUDONYMOUS_ID || $PSEUDONYMOUS_ID == "null" ]]; then
  echo "error: confirm token missing pseudonymous user id" >&2
  exit 1
fi

if [[ -z $CHALLENGE_ID || $CHALLENGE_ID == "null" ]]; then
  echo "error: confirm token missing challenge id" >&2
  exit 1
fi

STATE_FILE="$DEVICE_STATE_DIR/${PSEUDONYMOUS_ID}.json"
if [[ ! -f "$STATE_FILE" ]]; then
  echo "error: no device state found for pseudonymous id '$PSEUDONYMOUS_ID' ($STATE_FILE)" >&2
  exit 1
fi

STATE=$(cat "$STATE_FILE")
USER_ID=$(echo "$STATE" | jq -r '.userId')
CLIENT_ID=$(echo "$STATE" | jq -r '.clientId')
CLIENT_SECRET=$(echo "$STATE" | jq -r '.clientSecret')
PRIVATE_KEY_B64=$(echo "$STATE" | jq -r '.privateKey')
KID=$(echo "$STATE" | jq -r '.keyId // "push-device-client-key"')
TOKEN_ENDPOINT_DEFAULT=$(echo "$STATE" | jq -r '.tokenEndpoint')
TOKEN_ENDPOINT=${TOKEN_ENDPOINT:-$TOKEN_ENDPOINT_DEFAULT}

if [[ -z $USER_ID || -z $CLIENT_ID || -z $CLIENT_SECRET || -z $PRIVATE_KEY_B64 ]]; then
  echo "error: device state missing required fields" >&2
  exit 1
fi

KEY_FILE="$DEVICE_STATE_DIR/${PSEUDONYMOUS_ID}.key"
python3 - "$PRIVATE_KEY_B64" "$KEY_FILE" <<'PY'
import base64, sys
data = sys.argv[1]
path = sys.argv[2]
with open(path, 'wb') as fh:
    fh.write(base64.b64decode(data))
PY

echo ">> Requesting device access token"
DEVICE_TOKEN=$(curl -s -X POST "$TOKEN_ENDPOINT" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "grant_type=client_credentials" | jq -r '.access_token')

if [[ -z ${DEVICE_TOKEN:-} || ${DEVICE_TOKEN} == "null" ]]; then
  echo "error: failed to obtain device token" >&2
  exit 1
fi

EXPIRY=$(($(date +%s) + 120))
LOGIN_PAYLOAD=$(jq -n \
  --arg cid "$CHALLENGE_ID" \
  --arg sub "$USER_ID" \
  --arg exp "$EXPIRY" \
  '{"cid": $cid, "sub": $sub, "exp": ($exp|tonumber)}')

LOGIN_HEADER_B64=$(printf '{"alg":"RS256","kid":"%s","typ":"JWT"}' "$KID" | b64urlencode)
LOGIN_PAYLOAD_B64=$(printf '%s' "$LOGIN_PAYLOAD" | b64urlencode)
LOGIN_SIGNATURE_B64=$(printf '%s' "$LOGIN_HEADER_B64.$LOGIN_PAYLOAD_B64" | openssl dgst -binary -sha256 -sign "$KEY_FILE" | b64urlencode)
DEVICE_LOGIN_TOKEN="$LOGIN_HEADER_B64.$LOGIN_PAYLOAD_B64.$LOGIN_SIGNATURE_B64"

APPROVE_PAYLOAD=$(jq -n \
  --arg token "$DEVICE_LOGIN_TOKEN" \
  '{"token": $token}')

REALM_BASE=$(echo "$TOKEN_ENDPOINT" | sed 's#/protocol/.*##')
RESPOND_URL="$REALM_BASE/push-mfa/login/challenges/$CHALLENGE_ID/respond"
echo ">> Responding to challenge"
curl -s -X POST \
  -H "Authorization: Bearer $DEVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$APPROVE_PAYLOAD" \
  "$RESPOND_URL" | jq
