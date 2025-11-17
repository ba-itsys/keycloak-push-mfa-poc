#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/enroll.sh <enrollment-token>

Environment overrides:
  REALM_BASE               Realm base URL (default: http://localhost:8080/realms/push-mfa)
  ENROLL_COMPLETE_URL      Enrollment completion endpoint (default: <REALM_BASE>/push-mfa/enroll/complete)
  DEVICE_TYPE              Device type stored with the credential (default: ios)
  FIREBASE_ID              Firebase/FCM identifier (default: mock-fcm-token)
  PSEUDONYMOUS_ID          Pseudonymous user identifier (default: generated UUID)
  DEVICE_ID                Unique device id stored with the credential (default: generated UUID)
  DEVICE_LABEL             Display label stored with the credential (default: "Demo Phone")
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -ne 1 ]]; then
  usage
  exit $([[ $# -eq 1 ]] && [[ ${1:-} != "-h" && ${1:-} != "--help" ]] && echo 1 || echo 0)
fi

ENROLL_TOKEN=$1

if ! python3 - <<'PY' >/dev/null 2>&1; then
import importlib.util
import sys
sys.exit(0 if importlib.util.find_spec("cryptography") else 1)
PY
  echo "error: Python module 'cryptography' is required (install via 'python3 -m pip install --user cryptography')" >&2
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


REALM_BASE=${REALM_BASE:-http://localhost:8080/realms/push-mfa}
ENROLL_COMPLETE_URL=${ENROLL_COMPLETE_URL:-$REALM_BASE/push-mfa/enroll/complete}
DEVICE_TYPE=${DEVICE_TYPE:-ios}
FIREBASE_ID=${FIREBASE_ID:-mock-fcm-token}
PSEUDONYMOUS_ID=${PSEUDONYMOUS_ID:-$(python3 - <<'PY'
import uuid
print(f"device-alias-{uuid.uuid4()}")
PY
)}
DEVICE_ID=${DEVICE_ID:-$(python3 - <<'PY'
import uuid
print(f"device-{uuid.uuid4()}")
PY
)}
DEVICE_KEY_ID=${DEVICE_KEY_ID:-$(python3 - <<'PY'
import uuid
print(f"device-key-{uuid.uuid4()}")
PY
)}
DEVICE_LABEL=${DEVICE_LABEL:-Demo Phone}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEVICE_STATE_DIR=${DEVICE_STATE_DIR:-"$REPO_ROOT/scripts/device-state"}
mkdir -p "$DEVICE_STATE_DIR"
DEVICE_PRIVATE_KEY_PATH="$DEVICE_STATE_DIR/${PSEUDONYMOUS_ID}.key"
DEVICE_PUBLIC_KEY_PATH="$DEVICE_STATE_DIR/${PSEUDONYMOUS_ID}.pub"

WORKDIR=$(mktemp -d)
cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

pushd "$WORKDIR" >/dev/null

echo ">> Decoding enrollment challenge"
ENROLL_PAYLOAD=$(echo -n "$ENROLL_TOKEN" | cut -d'.' -f2 | b64urldecode)
ENROLLMENT_ID=$(echo "$ENROLL_PAYLOAD" | jq -r '.enrollmentId')
ENROLL_NONCE=$(echo "$ENROLL_PAYLOAD" | jq -r '.nonce')
USER_ID=$(echo "$ENROLL_PAYLOAD" | jq -r '.sub')

if [[ -z $ENROLLMENT_ID || -z $ENROLL_NONCE || -z $USER_ID ]]; then
  echo "error: unable to extract enrollmentId/nonce/sub from challenge" >&2
  exit 1
fi

echo "   enrollmentId: $ENROLLMENT_ID"
echo "   userId      : $USER_ID"

echo ">> Generating device key pair"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$DEVICE_PRIVATE_KEY_PATH" >/dev/null 2>&1
openssl rsa -pubout -in "$DEVICE_PRIVATE_KEY_PATH" -out "$DEVICE_PUBLIC_KEY_PATH" >/dev/null 2>&1

echo ">> Building JWK from public key"
DEVICE_PUBLIC_KEY_PATH="$DEVICE_PUBLIC_KEY_PATH" DEVICE_KEY_ID="$DEVICE_KEY_ID" python3 - <<'PY' > device-jwk.json
import json, base64, os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

with open(os.environ['DEVICE_PUBLIC_KEY_PATH'], 'rb') as f:
    key = serialization.load_pem_public_key(f.read(), backend=default_backend())

numbers = key.public_numbers()

def b64(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')

jwk = {
    "kty": "RSA",
    "n": b64(numbers.n),
    "e": b64(numbers.e),
    "alg": "RS256",
    "use": "sig",
    "kid": os.environ.get("DEVICE_KEY_ID", "push-device-client-key")
}

print(json.dumps(jwk))
PY

EXPIRY=$(($(date +%s) + 300))
echo ">> Preparing enrollment response JWT"
ENROLL_PAYLOAD_JSON=$(jq -n \
  --arg enrollmentId "$ENROLLMENT_ID" \
  --arg nonce "$ENROLL_NONCE" \
  --arg sub "$USER_ID" \
  --arg deviceType "$DEVICE_TYPE" \
  --arg firebaseId "$FIREBASE_ID" \
  --arg pseudonymousUserId "$PSEUDONYMOUS_ID" \
  --arg deviceId "$DEVICE_ID" \
  --arg deviceLabel "$DEVICE_LABEL" \
  --arg exp "$EXPIRY" \
  --argjson cnf "$(jq -c '{"jwk": .}' device-jwk.json)" \
  '{"enrollmentId": $enrollmentId, "nonce": $nonce, "sub": $sub, "deviceType": $deviceType, "firebaseId": $firebaseId, "pseudonymousUserId": $pseudonymousUserId, "deviceId": $deviceId, "deviceLabel": $deviceLabel, "exp": ($exp|tonumber), "cnf": $cnf}')

ENROLL_HEADER_B64=$(printf '{"alg":"RS256","kid":"%s","typ":"JWT"}' "$DEVICE_KEY_ID" | b64urlencode)
ENROLL_PAYLOAD_B64=$(printf '%s' "$ENROLL_PAYLOAD_JSON" | b64urlencode)
ENROLL_SIGNATURE_B64=$(printf '%s' "$ENROLL_HEADER_B64.$ENROLL_PAYLOAD_B64" | openssl dgst -binary -sha256 -sign "$DEVICE_PRIVATE_KEY_PATH" | b64urlencode)
DEVICE_ENROLL_TOKEN="$ENROLL_HEADER_B64.$ENROLL_PAYLOAD_B64.$ENROLL_SIGNATURE_B64"

echo ">> Submitting enrollment reply"
echo $ENROLL_PAYLOAD_JSON
ENROLL_RESPONSE=$(curl -s -X POST \
  -H "Authorization: Bearer $DEVICE_ENROLL_TOKEN" \
  "$ENROLL_COMPLETE_URL")

echo "$ENROLL_RESPONSE" | jq

PRIVATE_KEY_B64=$(base64 < "$DEVICE_PRIVATE_KEY_PATH" | tr -d '\n')
PUBLIC_KEY_B64=$(base64 < "$DEVICE_PUBLIC_KEY_PATH" | tr -d '\n')
STATE_FILE="$DEVICE_STATE_DIR/${PSEUDONYMOUS_ID}.json"

PUBLIC_JWK=$(cat device-jwk.json)

jq -n \
  --arg userId "$USER_ID" \
  --arg pseudonymousUserId "$PSEUDONYMOUS_ID" \
  --arg deviceId "$DEVICE_ID" \
  --arg realmBase "$REALM_BASE" \
  --arg privateKey "$PRIVATE_KEY_B64" \
  --arg publicKey "$PUBLIC_KEY_B64" \
  --arg deviceType "$DEVICE_TYPE" \
  --arg firebaseId "$FIREBASE_ID" \
  --arg keyId "$DEVICE_KEY_ID" \
  --arg deviceLabel "$DEVICE_LABEL" \
  --argjson publicJwk "$PUBLIC_JWK" \
  '{userId:$userId, pseudonymousUserId:$pseudonymousUserId, deviceId:$deviceId, realmBase:$realmBase, privateKey:$privateKey, publicKey:$publicKey, deviceType:$deviceType, firebaseId:$firebaseId, keyId:$keyId, deviceLabel:$deviceLabel, publicJwk:$publicJwk}' > "$STATE_FILE"

echo ">> Device state stored in $STATE_FILE"
popd >/dev/null
