package de.arbeitsagentur.keycloak.push;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.token.PushConfirmTokenBuilder;
import de.arbeitsagentur.keycloak.push.token.PushEnrollmentTokenBuilder;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.mockito.Mockito;

class PushTokenBuilderTest {

    private final KeycloakSession session = Mockito.mock(KeycloakSession.class);
    private final RealmModel realm = Mockito.mock(RealmModel.class);
    private final KeyManager keyManager = Mockito.mock(KeyManager.class);
    private KeyWrapper keyWrapper;

    @BeforeEach
    void setUp() throws Exception {
        Mockito.reset(session, realm, keyManager);
        keyWrapper = buildKeyWrapper("test-kid", Algorithm.RS256.toString());
        Mockito.when(session.keys()).thenReturn(keyManager);
        Mockito.when(keyManager.getActiveKey(
                        Mockito.any(), Mockito.eq(KeyUse.SIG), Mockito.eq(Algorithm.RS256.toString())))
                .thenReturn(keyWrapper);
        Mockito.when(realm.getName()).thenReturn("push-mfa");
    }

    @Test
    void confirmTokenCarriesExpectedClaims() throws Exception {
        String token = PushConfirmTokenBuilder.build(
                session,
                realm,
                "device-alias",
                "challenge-123",
                Instant.ofEpochSecond(1700000100),
                URI.create("http://localhost:8080/"),
                "test-client");

        SignedJWT jwt = SignedJWT.parse(token);
        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        assertEquals("device-alias", claims.getSubject());
        assertEquals("challenge-123", claims.getStringClaim("cid"));
        assertEquals("test-client", claims.getStringClaim("client_id"));
        assertEquals("http://localhost:8080/realms/push-mfa", claims.getIssuer());
        assertEquals(PushMfaConstants.PUSH_MESSAGE_TYPE, claims.getIntegerClaim("typ"));
        assertEquals(PushMfaConstants.PUSH_MESSAGE_VERSION, claims.getIntegerClaim("ver"));
        assertEquals(Date.from(Instant.ofEpochSecond(1700000100)), claims.getExpirationTime());
        assertEquals(keyWrapper.getKid(), jwt.getHeader().getKeyID());
        assertEquals(Algorithm.RS256.toString(), jwt.getHeader().getAlgorithm().getName());
    }

    @Test
    void enrollmentTokenIncludesEnrollmentDetails() throws Exception {
        byte[] nonce = new byte[] {1, 2, 3};
        PushChallenge challenge = new PushChallenge(
                "challenge-abc",
                "realm-id",
                "user-id",
                nonce,
                null,
                null,
                "watch-secret",
                null,
                Instant.ofEpochSecond(1700000200),
                PushChallenge.Type.ENROLLMENT,
                PushChallengeStatus.PENDING,
                Instant.now(),
                null);

        UserModel user = Mockito.mock(UserModel.class);
        Mockito.when(user.getId()).thenReturn("user-id");
        Mockito.when(user.getUsername()).thenReturn("demo-user");

        String token =
                PushEnrollmentTokenBuilder.build(session, realm, user, challenge, URI.create("http://localhost:8080/"));
        SignedJWT jwt = SignedJWT.parse(token);
        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        assertEquals("user-id", claims.getSubject());
        assertEquals("demo-user", claims.getStringClaim("username"));
        assertEquals("push-mfa", claims.getStringClaim("realm"));
        assertEquals("challenge-abc", claims.getStringClaim("enrollmentId"));
        assertEquals(PushChallengeStore.encodeNonce(nonce), claims.getStringClaim("nonce"));
        assertEquals("push-mfa", claims.getAudience().get(0));
        assertEquals(Date.from(Instant.ofEpochSecond(1700000200)), claims.getExpirationTime());
        assertNotNull(claims.getIssueTime());
        assertEquals("push-enroll-challenge", claims.getStringClaim("typ"));
    }

    private KeyWrapper buildKeyWrapper(String kid, String algorithm) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        KeyWrapper wrapper = new KeyWrapper();
        wrapper.setKid(kid);
        wrapper.setAlgorithm(algorithm);
        wrapper.setPrivateKey(pair.getPrivate());
        wrapper.setPublicKey(pair.getPublic());
        return wrapper;
    }
}
