# Keycloak Push MFA Extension

## Introduction

:warning: This is a proof-of-concept implementation intended for educational purposes only. Do not use in production environments.

This project extends Keycloak with a push-style second factor that mimics passkey primitives. After initial enrollment, the mobile app never receives the real user identifier from Keycloak; instead, it works with a pseudonymous id that only the app can map back to the real user. Everything is implemented with standard Keycloak SPIs plus a small JAX-RS resource exposed under `/realms/<realm>/push-mfa`.

- Build the provider: `mvn -DskipTests package`
- Run Keycloak locally (imports realm + loads provider): `docker compose up --build keycloak`
- Keycloak admin UI: <http://localhost:8080> (`admin` / `admin`)
- Test realm: `push-mfa` with the user `test / test`

## High Level Flow

1. **Enrollment challenge (RequiredAction):** Keycloak renders a QR code that encodes the realm-signed `enrollmentToken` (in this demo it uses a custom scheme: `push-mfa-login-app://?token=<enrollmentToken>`). The token is a JWT signed with the realm key and contains user id (`sub`), username, `enrollmentId`, and a Base64URL nonce.

   ```json
   {
     "_comment": "enrollmentToken payload (realm -> device)",
     "iss": "http://localhost:8080/realms/push-mfa",
     "aud": "push-mfa",
     "typ": "push-enroll-challenge",
     "sub": "87fa1c21-1b1e-4af8-98b1-1df2e90d3c3d",
     "username": "test",
     "realm": "push-mfa",
     "enrollmentId": "b15ef7f2-494c-4f03-a9b4-5b7eb4a71caa",
     "nonce": "JYlLk0d9h9zGN7kMd8n5Vw",
     "exp": 1731403200,
     "iat": 1731402900
   }
   ```

2. **Device enrollment response:** The app verifies the token using the realm JWKS, generates its own key pair and `kid`, and posts a JWT back to Keycloak that echoes the nonce and enrollment id, embeds the JWK under `cnf.jwk`, and introduces a pseudonymous user id. The JWT header uses the device `kid`; the payload looks like this:

   ```json
   {
     "_comment": "device enrollment payload (device -> realm)",
     "enrollmentId": "b15ef7f2-494c-4f03-a9b4-5b7eb4a71caa",
     "nonce": "JYlLk0d9h9zGN7kMd8n5Vw",
     "sub": "87fa1c21-1b1e-4af8-98b1-1df2e90d3c3d",
     "deviceType": "ios",
     "firebaseId": "mock-fcm-token",
     "pseudonymousUserId": "device-alias-bf7a9f52",
     "deviceLabel": "Demo Phone",
     "cnf": {
       "jwk": {
         "kty": "RSA",
         "n": "uVvbx3-...",
         "e": "AQAB",
         "alg": "RS256",
         "use": "sig",
         "kid": "device-key-31c3"
       }
     },
     "iat": 1731402910,
     "exp": 1731403200
   }
   ```

3. **Confirm token delivery:** Every login creates a fresh push challenge. Keycloak signs a `confirmToken` using the realm key and displays/logs it. This token is what would be sent via Firebase: it only contains the pseudonymous user id and the challenge id (`cid`), so the push provider learns nothing about the real user or that it is a login.

   ```json
   {
     "_comment": "confirmToken payload (realm -> device via Firebase/FCM)",
     "iss": "http://localhost:8080/realms/push-mfa",
     "sub": "device-alias-bf7a9f52",
     "typ": "1",
     "ver": "1",
     "cid": "1a6d6a0b-3385-4772-8eb8-0d2f4dbd25a4",
     "client_id": "test-app",
     "iat": 1731402960,
     "exp": 1731403260
   }
   ```

4. **Login approval:** The device looks up the confirm token’s `sub`, resolves it to the real Keycloak user id in its secure storage, and signs a JWT (`loginToken`) with the same key pair from enrollment. The payload echoes the challenge id (`cid`), the real `sub`, and the desired `action` (`approve`/`deny`) so Keycloak can fully trust the intent because it is covered by the device signature (no nonce is needed because possession of the device key already proves authenticity, and `cid` is unguessable).

   ```json
   {
     "_comment": "login approval payload (device -> realm)",
     "cid": "1a6d6a0b-3385-4772-8eb8-0d2f4dbd25a4",
     "sub": "87fa1c21-1b1e-4af8-98b1-1df2e90d3c3d",
     "action": "approve",
     "exp": 1731403020
   }
   ```

5. **Browser wait + polling:** The Keycloak login UI polls its own challenge store. Once the challenge is approved (or denied) the form resolves automatically. Polling `GET /login/pending` from the app is optional; the confirm token already carries the `cid`.

> This PoC demonstrates both real-time strategies: the enrollment UI listens to server-sent events (SSE) emitted for its challenge, while the login approval screen continues to use classic polling so both patterns can be evaluated side-by-side.

### Enrollment SSE details

- **Endpoint:** `GET /realms/<realm>/push-mfa/enroll/challenges/{challengeId}/events?secret=<watchSecret>` streams `text/event-stream`. The `watchSecret` is a per-challenge random value stored in `PushChallenge.watchSecret`; it prevents other sessions from observing enrollment progress.
- **Server loop:** `PushMfaResource#emitEnrollmentEvents` runs asynchronously, polls the challenge store every second, and emits a `status` event whenever the challenge state changes or an error occurs. Each event payload is JSON shaped like:

  ```json
  {
    "status": "PENDING | APPROVED | DENIED | NOT_FOUND | FORBIDDEN | INVALID | INTERRUPTED",
    "challengeId": "<uuid>",
    "expiresAt": "2025-11-14T13:16:12.902Z",
    "resolvedAt": "2025-11-14T13:16:22.180Z"
  }
  ```

  Failures (missing secret, secret mismatch, challenge not found, thread interruption, serialization errors) are logged at INFO level so pod logs provide a complete timeline for troubleshooting.

- **Client behavior:** The enrollment page (`push-register.ftl`) spins up a single `EventSource` pointed at the `eventsUrl`. When a non-`PENDING` status arrives the stream is closed and the hidden `check` form is submitted, allowing Keycloak’s RequiredAction to complete without any manual refresh. If the connection drops (pod restart, network flap) the browser’s native EventSource automatically retries; the script only logs `error` events for visibility.

- **No polling fallback:** Unlike earlier iterations the SSE client never schedules timer-based polling. If EventSource is missing (very old browsers) the script simply logs a warning, which is acceptable in this demo because enrollment is expected to run in modern browsers.

## Custom Keycloak APIs

All endpoints live under `/realms/push-mfa/push-mfa` and require a bearer token obtained by the device client (`push-device-client`) via client credentials.

### Complete enrollment

```
POST /realms/push-mfa/push-mfa/enroll/complete
Authorization: Bearer <device-service-token>
Content-Type: application/json

{
  "token": "<device-signed enrollment JWT>",
}
```

Keycloak verifies the signature using `cnf.jwk`, persists the credential (JWK, algorithm, deviceType, firebaseId, pseudonymousUserId, deviceLabel), and resolves the enrollment challenge. The `deviceLabel` is read from the JWT payload (falls back to `PushMfaConstants.USER_CREDENTIAL_DISPLAY_NAME` when absent).

```json
{
  "status": "enrolled"
}
```

### List pending login challenges

```
GET /realms/push-mfa/push-mfa/login/pending?userId=<keycloak-user-id>
Authorization: Bearer <device-service-token>
```

```json
{
  "challenges": [
    {
      "userId": "87fa1c21-1b1e-4af8-98b1-1df2e90d3c3d",
      "cid": "1a6d6a0b-3385-4772-8eb8-0d2f4dbd25a4",
      "expiresAt": "2025-11-14T13:16:12.902Z",
      "clientId": "test-app"
    }
  ]
}
```

### Approve or deny a challenge

```
POST /realms/push-mfa/push-mfa/login/challenges/{cid}/respond
Authorization: Bearer <device-service-token>
Content-Type: application/json

{
  "token": "<device-signed login JWT>",
}
```

Keycloak verifies the signature with the stored device JWK, ensures `cid`/`sub` match, and inspects the signed `action` claim. `"action": "approve"` marks the challenge as approved; `"action": "deny"` marks it as denied. Any other value is rejected.

```json
{ "status": "approved" }
```

## App Implementation Notes

- **Realm verification:** Enrollment starts when the app scans the QR code and reads `enrollmentToken`. Verify the JWT with the realm JWKS (`/realms/push-mfa/protocol/openid-connect/certs`) before trusting its contents.
- **Device key material:** Generate a key pair per device, select a unique `kid`, and keep the private key in the device secure storage. Persist and exchange the public component exclusively as a JWK (the same document posted in `cnf.jwk`).
- **State to store locally:** pseudonymous user id ↔ real Keycloak user id mapping, the device key pair, the `kid`, `deviceType`, `firebaseId`, preferred `deviceLabel`, and any metadata needed to post to Keycloak again.
- **Confirm token handling:** When the confirm token arrives through Firebase (or when the user copies it from the waiting UI), decode the JWT, extract `cid` and `sub`, and either call `/login/pending` (optional) or immediately sign the login approval JWT and post it to `/login/challenges/{cid}/respond`.
- **Error handling:** Enrollment and login requests return structured error responses (`400`, `403`, or `404`) when the JWTs are invalid, expired, or mismatched. Surface those errors to the user to re-trigger the flow if necessary.
- **Key rotation / Firebase changes:** Rotating the device key pair or updating the `firebaseId` would require dedicated Keycloak endpoints to update the stored credential; those flows are out of scope for this PoC, so the workaround is to delete the credential and re-enroll.

With these primitives an actual mobile app UI or automation can be layered on top without depending on helper shell scripts.

## Security Guarantees and Mobile Obligations

### Security guarantees provided by the extension

- **Signed artifacts end-to-end:** Enrollment and confirm tokens are JWTs signed by realm keys, and device responses are signed with the device key pair. Every hop is authenticated and tamper-evident.
- **Challenge binding:** Enrollment tokens embed a nonce plus enrollment id, and login approvals reference the opaque challenge id (`cid`), so replaying a response for a different user or challenge fails.
- **Limited data exposure:** Confirm tokens carry only the pseudonymous user id and challenge id, preventing the push channel from learning the user’s identity or whether a login succeeded.
- **Short-lived state:** Challenge lifetime equals every token’s `exp`, so an attacker has at most ~2 minutes to replay data even if transport is intercepted.
- **Key continuity:** The stored `cnf.jwk` couples future approvals to the same hardware-backed key, giving Keycloak a stable signal that a response truly came from the enrolled device.

### Obligations for the mobile application

- **Verify every JWT:** Check issuer, audience, signature, and `exp` on enrollment and confirm tokens before acting. Fetch the realm JWKS over HTTPS and cache it defensively.
- **Protect the device key pair:** Generate it with high-entropy sources, store the private key in Secure Enclave/Keystore/KeyChain, and never export it. Rotate/re-enroll immediately if compromise is suspected.
- **Enforce challenge integrity:** When a confirm token arrives, compare the `cid`, `sub`, and `client_id` against locally stored state and discard anything unexpected or expired.
- **Secure transport:** Call the Keycloak endpoints only over TLS, validate certificates (no user-controlled CA overrides), and pin if your threat model requires it.
- **Harden local state:** Keep the pseudonymous ↔ real user mapping, firebase identifiers, and enrollment metadata in encrypted storage with OS-level protection.
- **Surface errors to users:** Treat 4xx responses (expired, invalid signature, nonce mismatch) as security events, notifying the user and requiring a fresh enrollment or login attempt rather than silently retrying.
