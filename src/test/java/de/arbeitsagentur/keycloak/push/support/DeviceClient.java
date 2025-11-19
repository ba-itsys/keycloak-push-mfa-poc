package de.arbeitsagentur.keycloak.push.support;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public final class DeviceClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DEVICE_CLIENT_ID = "push-device-client";
    private static final String DEVICE_CLIENT_SECRET = "device-client-secret";

    private final URI realmBase;
    private final URI tokenEndpoint;
    private final DeviceState state;
    private final HttpClient http =
            HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
    private String accessToken;

    public DeviceClient(URI baseUri, DeviceState state) {
        this.realmBase = baseUri.resolve("/realms/push-mfa/");
        this.tokenEndpoint = realmBase.resolve("protocol/openid-connect/token");
        this.state = state;
    }

    public DeviceState state() {
        return state;
    }

    public void completeEnrollment(String enrollmentToken) throws Exception {
        SignedJWT enrollment = SignedJWT.parse(enrollmentToken);
        JWTClaimsSet claims = enrollment.getJWTClaimsSet();
        state.setUserId(claims.getSubject());
        JWTClaimsSet deviceClaims = new JWTClaimsSet.Builder()
                .claim("enrollmentId", claims.getStringClaim("enrollmentId"))
                .claim("nonce", claims.getStringClaim("nonce"))
                .claim("sub", state.userId())
                .claim("deviceType", "ios")
                .claim("pushProviderId", state.pushProviderId())
                .claim("pushProviderType", state.pushProviderType())
                .claim("pseudonymousUserId", state.pseudonymousId())
                .claim("deviceId", state.deviceId())
                .claim("deviceLabel", state.deviceLabel())
                .expirationTime(java.util.Date.from(Instant.now().plusSeconds(300)))
                .claim("cnf", Map.of("jwk", state.signingKey().publicJwk().toJSONObject()))
                .build();
        SignedJWT deviceToken = sign(deviceClaims);

        HttpRequest request = HttpRequest.newBuilder(realmBase.resolve("push-mfa/enroll/complete"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(MAPPER.createObjectNode()
                        .put("token", deviceToken.serialize())
                        .toString()))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "Enrollment failed: " + response.body());
    }

    public void respondToChallenge(String confirmToken, String challengeId) throws Exception {
        ensureAccessToken();
        SignedJWT confirm = SignedJWT.parse(confirmToken);
        String cid = Objects.requireNonNullElse(confirm.getJWTClaimsSet().getStringClaim("cid"), challengeId);
        JWTClaimsSet loginClaims = new JWTClaimsSet.Builder()
                .claim("cid", cid)
                .claim("sub", state.userId())
                .claim("deviceId", state.deviceId())
                .claim("action", "approve")
                .expirationTime(java.util.Date.from(Instant.now().plusSeconds(120)))
                .build();
        SignedJWT loginToken = sign(loginClaims);

        URI respondUri = realmBase.resolve("push-mfa/login/challenges/" + cid + "/respond");
        HttpRequest request = HttpRequest.newBuilder(respondUri)
                .header("Authorization", "DPoP " + accessToken)
                .header("DPoP", createDpopProof("POST", respondUri))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(MAPPER.createObjectNode()
                        .put("token", loginToken.serialize())
                        .toString()))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "Respond failed: " + response.body());
        assertEquals("approved", MAPPER.readTree(response.body()).path("status").asText());
    }

    public String updatePushProvider(String pushProviderId, String pushProviderType) throws Exception {
        ensureAccessToken();
        URI updateUri = realmBase.resolve("push-mfa/device/push-provider");
        var body = MAPPER.createObjectNode()
                .put("pushProviderId", pushProviderId)
                .put("pushProviderType", pushProviderType);
        HttpRequest request = HttpRequest.newBuilder(updateUri)
                .header("Authorization", "DPoP " + accessToken)
                .header("DPoP", createDpopProof("PUT", updateUri))
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "Update push provider failed: " + response.body());
        JsonNode result = MAPPER.readTree(response.body());
        String status = result.path("status").asText();
        if ("updated".equalsIgnoreCase(status)) {
            state.updatePushProvider(pushProviderId, pushProviderType);
        }
        return status;
    }

    public String rotateDeviceKey(DeviceSigningKey newKey) throws Exception {
        ensureAccessToken();
        URI rotateUri = realmBase.resolve("push-mfa/device/rotate-key");
        JsonNode jwkNode = MAPPER.readTree(newKey.publicJwk().toJSONString());
        var body = MAPPER.createObjectNode();
        body.set("publicKeyJwk", jwkNode);
        body.put("algorithm", newKey.algorithm().getName());
        HttpRequest request = HttpRequest.newBuilder(rotateUri)
                .header("Authorization", "DPoP " + accessToken)
                .header("DPoP", createDpopProof("PUT", rotateUri))
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "Rotate key failed: " + response.body());
        JsonNode result = MAPPER.readTree(response.body());
        String status = result.path("status").asText();
        if ("rotated".equalsIgnoreCase(status)) {
            state.updateKey(newKey);
            accessToken = null;
        }
        return status;
    }

    private SignedJWT sign(JWTClaimsSet claims) throws Exception {
        DeviceSigningKey signingKey = state.signingKey();
        JWSHeader header = new JWSHeader.Builder(signingKey.algorithm())
                .type(JOSEObjectType.JWT)
                .keyID(signingKey.keyId())
                .build();
        SignedJWT token = new SignedJWT(header, claims);
        token.sign(signingKey.signer());
        return token;
    }

    private void ensureAccessToken() throws Exception {
        if (accessToken != null) {
            return;
        }
        HttpRequest request = HttpRequest.newBuilder(tokenEndpoint)
                .header("DPoP", createDpopProof("POST", tokenEndpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials&client_id="
                        + urlEncode(DEVICE_CLIENT_ID) + "&client_secret=" + urlEncode(DEVICE_CLIENT_SECRET)))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), () -> "Token request failed: " + response.body());
        JsonNode json = MAPPER.readTree(response.body());
        accessToken = json.path("access_token").asText();
        if (accessToken != null && !accessToken.isBlank()) {
            var jwt = SignedJWT.parse(accessToken);
            System.err.println("Access token claims: " + jwt.getJWTClaimsSet().toJSONObject());
        }
        assertNotNull(accessToken);
    }

    private String createDpopProof(String method, URI uri) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htm", method)
                .claim("htu", uri.toString())
                .claim("sub", state.userId())
                .claim("deviceId", state.deviceId())
                .claim("iat", Instant.now().getEpochSecond())
                .claim("jti", UUID.randomUUID().toString())
                .build();
        DeviceSigningKey signingKey = state.signingKey();
        SignedJWT proof = new SignedJWT(
                new JWSHeader.Builder(signingKey.algorithm())
                        .type(new JOSEObjectType("dpop+jwt"))
                        .jwk(signingKey.publicJwk())
                        .keyID(signingKey.keyId())
                        .build(),
                claims);
        proof.sign(signingKey.signer());
        return proof.serialize();
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
