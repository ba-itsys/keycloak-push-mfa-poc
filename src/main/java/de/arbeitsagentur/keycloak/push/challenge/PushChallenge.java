package de.arbeitsagentur.keycloak.push.challenge;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

public final class PushChallenge {

    public enum Type {
        ENROLLMENT,
        AUTHENTICATION
    }

    private final String id;
    private final String realmId;
    private final String userId;
    private final byte[] nonce;
    private final String credentialId;
    private final String clientId;
    private final String watchSecret;
    private final String rootSessionId;
    private final Instant expiresAt;
    private final Type type;
    private final PushChallengeStatus status;
    private final Instant createdAt;
    private final Instant resolvedAt;

    public PushChallenge(
            String id,
            String realmId,
            String userId,
            byte[] nonce,
            String credentialId,
            String clientId,
            String watchSecret,
            String rootSessionId,
            Instant expiresAt,
            Type type,
            PushChallengeStatus status,
            Instant createdAt,
            Instant resolvedAt) {
        this.id = Objects.requireNonNull(id);
        this.realmId = Objects.requireNonNull(realmId);
        this.userId = Objects.requireNonNull(userId);
        this.nonce = Arrays.copyOf(Objects.requireNonNull(nonce), nonce.length);
        this.credentialId = credentialId;
        this.clientId = clientId;
        this.watchSecret = watchSecret;
        this.rootSessionId = rootSessionId;
        this.expiresAt = Objects.requireNonNull(expiresAt);
        this.type = Objects.requireNonNull(type);
        this.status = Objects.requireNonNull(status);
        this.createdAt = Objects.requireNonNull(createdAt);
        this.resolvedAt = resolvedAt;
    }

    public String getId() {
        return id;
    }

    public String getRealmId() {
        return realmId;
    }

    public String getUserId() {
        return userId;
    }

    public byte[] getNonce() {
        return Arrays.copyOf(nonce, nonce.length);
    }

    public String getCredentialId() {
        return credentialId;
    }

    public String getClientId() {
        return clientId;
    }

    public String getWatchSecret() {
        return watchSecret;
    }

    public String getRootSessionId() {
        return rootSessionId;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Type getType() {
        return type;
    }

    public PushChallengeStatus getStatus() {
        return status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getResolvedAt() {
        return resolvedAt;
    }
}
