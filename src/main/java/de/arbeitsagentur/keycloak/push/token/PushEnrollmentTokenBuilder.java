package de.arbeitsagentur.keycloak.push.token;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSBuilder.EncodingBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public final class PushEnrollmentTokenBuilder {

    private PushEnrollmentTokenBuilder() {}

    public static String build(
            KeycloakSession session, RealmModel realm, UserModel user, PushChallenge challenge, URI baseUri) {
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256.toString());
        if (key == null || key.getPrivateKey() == null) {
            throw new IllegalStateException("No active signing key for realm");
        }

        URI issuer =
                UriBuilder.fromUri(baseUri).path("realms").path(realm.getName()).build();

        Map<String, Object> payload = new HashMap<>();
        payload.put("iss", issuer.toString());
        payload.put("aud", "push-mfa");
        payload.put("sub", user.getId());
        payload.put("username", user.getUsername());
        payload.put("realm", realm.getName());
        payload.put("enrollmentId", challenge.getId());
        payload.put("nonce", PushChallengeStore.encodeNonce(challenge.getNonce()));
        payload.put("exp", challenge.getExpiresAt().getEpochSecond());
        payload.put("iat", Instant.now().getEpochSecond());
        payload.put("typ", "push-enroll-challenge");

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
        EncodingBuilder encodingBuilder =
                new JWSBuilder().kid(key.getKid()).type("JWT").jsonContent(payload);

        return encodingBuilder.sign(algorithm, privateKey);
    }
}
