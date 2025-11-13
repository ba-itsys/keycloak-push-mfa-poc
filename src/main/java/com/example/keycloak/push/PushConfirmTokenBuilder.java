package com.example.keycloak.push;

import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSBuilder.EncodingBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.net.URI;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

final class PushConfirmTokenBuilder {

    private PushConfirmTokenBuilder() {
    }

    static String build(KeycloakSession session,
                        RealmModel realm,
                        String pseudonymousUserId,
                        String challengeId,
                        Instant challengeExpiresAt,
                        URI baseUri,
                        String clientId) {
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256.toString());
        if (key == null || key.getPrivateKey() == null) {
            throw new IllegalStateException("No active signing key for realm");
        }

        URI issuer = UriBuilder.fromUri(baseUri)
            .path("realms")
            .path(realm.getName())
            .build();

        Map<String, Object> payload = new HashMap<>();
        payload.put("iss", issuer.toString());
        payload.put("sub", pseudonymousUserId);
        payload.put("typ", PushMfaConstants.PUSH_MESSAGE_TYPE);
        payload.put("ver", PushMfaConstants.PUSH_MESSAGE_VERSION);
        payload.put("cid", challengeId);
        if (clientId != null) {
            payload.put("client_id", clientId);
        }
        Instant issuedAt = Instant.now();
        payload.put("iat", issuedAt.getEpochSecond());
        payload.put("exp", challengeExpiresAt.getEpochSecond());

        Algorithm algorithm = Algorithm.RS256;
        if (key.getAlgorithm() != null) {
            for (Algorithm candidate : Algorithm.values()) {
                if (candidate.toString().equalsIgnoreCase(key.getAlgorithm())) {
                    algorithm = candidate;
                    break;
                }
            }
        }

        PrivateKey privateKey = (PrivateKey) key.getPrivateKey();
        EncodingBuilder builder = new JWSBuilder()
            .kid(key.getKid())
            .type("JWT")
            .jsonContent(payload);

        return builder.sign(algorithm, privateKey);
    }
}
