package de.arbeitsagentur.keycloak.push.challenge;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.utils.KeycloakModelUtils;

public class PushChallengeStore {

    private static final String CHALLENGE_PREFIX = "push-mfa:challenge:";
    private static final String USER_INDEX_PREFIX = "push-mfa:user-index:";
    private static final String INDEX_CHALLENGE_IDS = "challengeIds";

    private final KeycloakSession session;
    private final SingleUseObjectProvider singleUse;

    public PushChallengeStore(KeycloakSession session) {
        this.session = Objects.requireNonNull(session);
        this.singleUse = Objects.requireNonNull(session.singleUseObjects());
    }

    public PushChallenge create(
            String realmId,
            String userId,
            byte[] nonceBytes,
            PushChallenge.Type type,
            Duration ttl,
            String credentialId,
            String clientId,
            String watchSecret,
            String rootSessionId) {
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
        if (clientId != null) {
            data.put("clientId", clientId);
        }
        if (watchSecret != null) {
            data.put("watchSecret", watchSecret);
        }
        if (rootSessionId != null) {
            data.put("rootSessionId", rootSessionId);
        }

        long ttlSeconds = Math.max(1L, ttl.toSeconds());

        singleUse.put(challengeKey(id), ttlSeconds, data);

        PushChallenge challenge = new PushChallenge(
                id,
                realmId,
                userId,
                nonceBytes,
                credentialId,
                clientId,
                watchSecret,
                rootSessionId,
                expiresAt,
                type,
                PushChallengeStatus.PENDING,
                now,
                null);

        if (type == PushChallenge.Type.AUTHENTICATION) {
            List<PushChallenge> pending = new ArrayList<>(findPendingForUser(realmId, userId));
            pending.add(challenge);
            storeAuthenticationIndex(realmId, userId, pending);
        }

        return challenge;
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

        if (challenge.getStatus() == PushChallengeStatus.PENDING
                && Instant.now().isAfter(challenge.getExpiresAt())) {
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
            refreshAuthenticationIndex(updated.getRealmId(), updated.getUserId());
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
                refreshAuthenticationIndex(realmId, userId);
            }
        }
    }

    public List<PushChallenge> findPendingForUser(String realmId, String userId) {
        Map<String, String> index = singleUse.get(userIndexKey(realmId, userId));
        if (index == null) {
            return List.of();
        }

        List<String> challengeIds = parseIndexChallengeIds(index);
        if (challengeIds.isEmpty()) {
            singleUse.remove(userIndexKey(realmId, userId));
            return List.of();
        }

        List<PushChallenge> pending = new ArrayList<>();
        for (String challengeId : challengeIds) {
            Optional<PushChallenge> challenge = get(challengeId);
            if (challenge.isPresent()) {
                PushChallenge current = challenge.get();
                if (current.getType() == PushChallenge.Type.AUTHENTICATION
                        && current.getStatus() == PushChallengeStatus.PENDING) {
                    pending.add(current);
                }
            }
        }

        storeAuthenticationIndex(realmId, userId, pending);

        return pending;
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
        return updateStatus(challengeId, data, PushChallengeStatus.EXPIRED);
    }

    private void refreshAuthenticationIndex(String realmId, String userId) {
        findPendingForUser(realmId, userId);
    }

    private void storeAuthenticationIndex(String realmId, String userId, List<PushChallenge> pending) {
        if (pending == null || pending.isEmpty()) {
            singleUse.remove(userIndexKey(realmId, userId));
            return;
        }

        Instant now = Instant.now();
        Instant maxExpiresAt = pending.stream()
                .map(PushChallenge::getExpiresAt)
                .filter(Objects::nonNull)
                .max(Instant::compareTo)
                .orElse(now);

        Map<String, String> index = new HashMap<>();
        index.put(
                INDEX_CHALLENGE_IDS,
                pending.stream()
                        .map(PushChallenge::getId)
                        .filter(Objects::nonNull)
                        .collect(Collectors.joining(",")));

        long ttlSeconds = Math.max(1L, Duration.between(now, maxExpiresAt).getSeconds() + 1);
        singleUse.put(userIndexKey(realmId, userId), ttlSeconds, index);
    }

    private List<String> parseIndexChallengeIds(Map<String, String> index) {
        String rawIds = index.get(INDEX_CHALLENGE_IDS);
        if (rawIds == null || rawIds.isBlank()) {
            return List.of();
        }
        return java.util.Arrays.stream(rawIds.split(","))
                .map(String::trim)
                .filter(id -> !id.isBlank())
                .toList();
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

        if (realmId == null
                || userId == null
                || nonce == null
                || expiresAt == null
                || type == null
                || status == null
                || createdAt == null) {
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
                data.get("clientId"),
                data.get("watchSecret"),
                data.get("rootSessionId"),
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
