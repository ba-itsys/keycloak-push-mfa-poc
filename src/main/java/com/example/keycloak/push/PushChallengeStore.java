package com.example.keycloak.push;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.utils.KeycloakModelUtils;

public class PushChallengeStore {

    private static final String CHALLENGE_PREFIX = "push-mfa:challenge:";
    private static final String USER_INDEX_PREFIX = "push-mfa:user-index:";

    private final KeycloakSession session;
    private final SingleUseObjectProvider singleUse;

    public PushChallengeStore(KeycloakSession session) {
        this.session = Objects.requireNonNull(session);
        this.singleUse = Objects.requireNonNull(session.singleUseObjects());
    }

    public PushChallenge create(String realmId,
                                String userId,
                                byte[] nonceBytes,
                                PushChallenge.Type type,
                                Duration ttl,
                                String credentialId) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(ttl);
        String id = KeycloakModelUtils.generateId();

        Map<String, String> data = new HashMap<>();
        data.put("realmId", realmId);
        data.put("userId", userId);
        data.put("nonce", encodeNonce(nonceBytes));
        data.put("expiresAt", expiresAt.toString());
        data.put("type", type.name());
        data.put("status", PushChallengeStatus.PENDING.name());
        data.put("createdAt", now.toString());
        if (credentialId != null) {
            data.put("credentialId", credentialId);
        }

        long ttlSeconds = Math.max(1L, ttl.toSeconds());

        singleUse.put(challengeKey(id), ttlSeconds, data);

        if (type == PushChallenge.Type.AUTHENTICATION) {
            replaceAuthenticationIndex(realmId, userId, id, expiresAt, ttlSeconds);
        }

        return new PushChallenge(id, realmId, userId, nonceBytes, credentialId, expiresAt, type, PushChallengeStatus.PENDING, now, null);
    }

    public Optional<PushChallenge> get(String challengeId) {
        Map<String, String> data = singleUse.get(challengeKey(challengeId));
        if (data == null) {
            return Optional.empty();
        }

        PushChallenge challenge = fromMap(challengeId, data);
        if (challenge == null) {
            singleUse.remove(challengeKey(challengeId));
            return Optional.empty();
        }

        if (challenge.getStatus() == PushChallengeStatus.PENDING && Instant.now().isAfter(challenge.getExpiresAt())) {
            challenge = markExpired(challengeId, data);
        }

        return Optional.ofNullable(challenge);
    }

    public void resolve(String challengeId, PushChallengeStatus status) {
        Map<String, String> data = singleUse.get(challengeKey(challengeId));
        if (data == null) {
            return;
        }

        PushChallenge updated = updateStatus(challengeId, data, status);
        if (updated != null && updated.getType() == PushChallenge.Type.AUTHENTICATION) {
            removeAuthenticationIndex(updated.getRealmId(), updated.getUserId(), false);
        }
    }

    public void remove(String challengeId) {
        Map<String, String> data = singleUse.remove(challengeKey(challengeId));
        if (data == null) {
            return;
        }

        if (isAuthentication(data)) {
            String realmId = data.get("realmId");
            String userId = data.get("userId");
            if (realmId != null && userId != null) {
                removeAuthenticationIndex(realmId, userId, false);
            }
        }
    }

    public List<PushChallenge> findPendingForUser(String realmId, String userId) {
        Map<String, String> index = singleUse.get(userIndexKey(realmId, userId));
        if (index == null) {
            return List.of();
        }

        String challengeId = index.get("challengeId");
        if (challengeId == null) {
            singleUse.remove(userIndexKey(realmId, userId));
            return List.of();
        }

        Optional<PushChallenge> challenge = get(challengeId);
        if (challenge.isPresent() && challenge.get().getStatus() == PushChallengeStatus.PENDING) {
            return List.of(challenge.get());
        }

        singleUse.remove(userIndexKey(realmId, userId));
        return List.of();
    }

    public int countPendingAuthentication(String realmId, String userId) {
        return findPendingForUser(realmId, userId).size();
    }

    private PushChallenge updateStatus(String challengeId, Map<String, String> data, PushChallengeStatus status) {
        Map<String, String> updated = new HashMap<>(data);
        Instant now = Instant.now();
        updated.put("status", status.name());
        updated.put("resolvedAt", now.toString());
        singleUse.replace(challengeKey(challengeId), updated);
        return fromMap(challengeId, updated);
    }

    private PushChallenge markExpired(String challengeId, Map<String, String> data) {
        PushChallenge expired = updateStatus(challengeId, data, PushChallengeStatus.EXPIRED);
        if (expired != null && expired.getType() == PushChallenge.Type.AUTHENTICATION) {
            removeAuthenticationIndex(expired.getRealmId(), expired.getUserId(), false);
        }
        return expired;
    }

    private void replaceAuthenticationIndex(String realmId,
                                             String userId,
                                             String challengeId,
                                             Instant expiresAt,
                                             long ttlSeconds) {
        Map<String, String> previous = singleUse.remove(userIndexKey(realmId, userId));
        if (previous != null) {
            String previousId = previous.get("challengeId");
            if (previousId != null && !previousId.equals(challengeId)) {
                singleUse.remove(challengeKey(previousId));
            }
        }

        Map<String, String> index = new HashMap<>();
        index.put("challengeId", challengeId);
        index.put("expiresAt", expiresAt.toString());
        singleUse.put(userIndexKey(realmId, userId), ttlSeconds, index);
    }

    private void removeAuthenticationIndex(String realmId, String userId, boolean removeChallenge) {
        Map<String, String> previous = singleUse.remove(userIndexKey(realmId, userId));
        if (!removeChallenge || previous == null) {
            return;
        }
        String previousId = previous.get("challengeId");
        if (previousId != null) {
            singleUse.remove(challengeKey(previousId));
        }
    }

    private PushChallenge fromMap(String challengeId, Map<String, String> data) {
        String realmId = data.get("realmId");
        String userId = data.get("userId");
        String nonce = data.get("nonce");
        String expiresAt = data.get("expiresAt");
        String type = data.get("type");
        String status = data.get("status");
        String createdAt = data.get("createdAt");
        String resolvedAt = data.get("resolvedAt");

        if (realmId == null || userId == null || nonce == null || expiresAt == null || type == null || status == null || createdAt == null) {
            return null;
        }

        Instant expires = Instant.parse(expiresAt);
        Instant created = Instant.parse(createdAt);
        Instant resolved = resolvedAt == null ? null : Instant.parse(resolvedAt);

        return new PushChallenge(
            challengeId,
            realmId,
            userId,
            decodeNonce(nonce),
            data.get("credentialId"),
            expires,
            PushChallenge.Type.valueOf(type),
            PushChallengeStatus.valueOf(status),
            created,
            resolved);
    }

    private boolean isAuthentication(Map<String, String> data) {
        String type = data.get("type");
        return PushChallenge.Type.AUTHENTICATION.name().equals(type);
    }

    private String challengeKey(String challengeId) {
        return CHALLENGE_PREFIX + challengeId;
    }

    private String userIndexKey(String realmId, String userId) {
        return USER_INDEX_PREFIX + realmId + ":" + userId;
    }

    private byte[] decodeNonce(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("Invalid stored challenge data", ex);
        }
    }

    public static String encodeNonce(byte[] nonceBytes) {
        return Base64.getEncoder().withoutPadding().encodeToString(nonceBytes);
    }
}
