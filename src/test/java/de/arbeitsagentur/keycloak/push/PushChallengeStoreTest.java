package de.arbeitsagentur.keycloak.push;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.mockito.Mockito;

class PushChallengeStoreTest {

    private static final String REALM_ID = "realm-id";
    private static final String USER_ID = "user-id";

    private InMemorySingleUseObjectProvider singleUseObjects;
    private PushChallengeStore store;

    @BeforeEach
    void setUp() {
        singleUseObjects = new InMemorySingleUseObjectProvider();
        KeycloakSession session = Mockito.mock(KeycloakSession.class);
        Mockito.when(session.singleUseObjects()).thenReturn(singleUseObjects);
        store = new PushChallengeStore(session);
    }

    @Test
    void keepsMultiplePendingChallengesForSameCredential() {
        PushChallenge first = createAuthChallenge("cred-1");
        PushChallenge second = createAuthChallenge("cred-1");

        assertEquals(2, store.countPendingAuthentication(REALM_ID, USER_ID));
        assertContainsChallenge(first.getId());
        assertContainsChallenge(second.getId());

        store.resolve(first.getId(), PushChallengeStatus.APPROVED);
        assertEquals(1, store.countPendingAuthentication(REALM_ID, USER_ID));
        assertContainsChallenge(second.getId());
    }

    @Test
    void keepsMultiplePendingChallengesForDifferentCredentials() {
        PushChallenge first = createAuthChallenge("cred-1");
        PushChallenge second = createAuthChallenge("cred-2");

        assertEquals(2, store.findPendingForUser(REALM_ID, USER_ID).size());

        store.remove(second.getId());
        assertEquals(1, store.countPendingAuthentication(REALM_ID, USER_ID));
        assertContainsChallenge(first.getId());
    }

    private PushChallenge createAuthChallenge(String credentialId) {
        return store.create(
                REALM_ID,
                USER_ID,
                new byte[] {1, 2, 3},
                PushChallenge.Type.AUTHENTICATION,
                Duration.ofSeconds(120),
                credentialId,
                "client",
                "watch-secret",
                "root-session");
    }

    private void assertContainsChallenge(String id) {
        assertTrue(store.findPendingForUser(REALM_ID, USER_ID).stream()
                .anyMatch(challenge -> id.equals(challenge.getId())));
    }

    private static final class InMemorySingleUseObjectProvider implements SingleUseObjectProvider {

        private final Map<String, Map<String, String>> data = new HashMap<>();

        @Override
        public void put(String key, long lifespanSeconds, Map<String, String> value) {
            data.put(key, new HashMap<>(value));
        }

        @Override
        public Map<String, String> get(String key) {
            Map<String, String> value = data.get(key);
            return value == null ? null : new HashMap<>(value);
        }

        @Override
        public Map<String, String> remove(String key) {
            Map<String, String> removed = data.remove(key);
            return removed == null ? null : new HashMap<>(removed);
        }

        @Override
        public boolean replace(String key, Map<String, String> value) {
            if (!data.containsKey(key)) {
                return false;
            }
            data.put(key, new HashMap<>(value));
            return true;
        }

        @Override
        public boolean putIfAbsent(String key, long lifespanSeconds) {
            if (data.containsKey(key)) {
                return false;
            }
            data.put(key, new HashMap<>());
            return true;
        }

        @Override
        public boolean contains(String key) {
            return data.containsKey(key);
        }

        @Override
        public void close() {
            // no-op
        }
    }
}
