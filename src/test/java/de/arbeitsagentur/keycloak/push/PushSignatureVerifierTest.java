package de.arbeitsagentur.keycloak.push;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.push.util.PushSignatureVerifier;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.JWSInput;

class PushSignatureVerifierTest {

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(PushSignatureVerifierTest.class.getClassLoader());
    }

    @Test
    void rsaSignatureRoundTrip() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyID("rsa-" + UUID.randomUUID())
                .algorithm(JWSAlgorithm.RS256)
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        SignedJWT jwt = signed("rsa-test", rsaKey, JWSAlgorithm.RS256);
        JWSInput input = new JWSInput(jwt.serialize());
        KeyWrapper wrapper = keyWrapper(rsaKey.toPublicJWK());
        assertTrue(PushSignatureVerifier.verify(input, wrapper));

        RSAKey otherKey = new RSAKeyGenerator(2048)
                .keyID("rsa-other-" + UUID.randomUUID())
                .algorithm(JWSAlgorithm.RS256)
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        SignedJWT forged = signed("rsa-test", otherKey, JWSAlgorithm.RS256);
        assertFalse(PushSignatureVerifier.verify(new JWSInput(forged.serialize()), wrapper));
    }

    @Test
    void ecSignatureRoundTrip() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256)
                .keyID("ec-" + UUID.randomUUID())
                .algorithm(JWSAlgorithm.ES256)
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        SignedJWT jwt = signed("ec-test", ecKey, JWSAlgorithm.ES256);
        KeyWrapper wrapper = keyWrapper(ecKey.toPublicJWK());
        assertTrue(PushSignatureVerifier.verify(new JWSInput(jwt.serialize()), wrapper));

        ECKey tamperedKey = new ECKeyGenerator(Curve.P_256)
                .keyID("ec-tampered-" + UUID.randomUUID())
                .algorithm(JWSAlgorithm.ES256)
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        SignedJWT forged = signed("ec-test", tamperedKey, JWSAlgorithm.ES256);
        assertFalse(PushSignatureVerifier.verify(new JWSInput(forged.serialize()), wrapper));
    }

    private SignedJWT signed(String subject, JWK jwk, JWSAlgorithm alg) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer("test-suite")
                .expirationTime(java.util.Date.from(Instant.now().plusSeconds(60)))
                .build();
        JWSHeader header = new JWSHeader.Builder(alg)
                .type(JOSEObjectType.JWT)
                .keyID(jwk.getKeyID())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        JWSSigner signer = jwk instanceof RSAKey rsa ? new RSASSASigner(rsa) : new ECDSASigner((ECKey) jwk);
        jwt.sign(signer);
        return jwt;
    }

    private KeyWrapper keyWrapper(JWK jwk) throws Exception {
        KeyWrapper wrapper = new KeyWrapper();
        wrapper.setKid(jwk.getKeyID());
        if (jwk instanceof RSAKey rsaKey) {
            wrapper.setType(KeyType.RSA);
            wrapper.setPublicKey(rsaKey.toRSAPublicKey());
            wrapper.setAlgorithm(
                    rsaKey.getAlgorithm() != null ? rsaKey.getAlgorithm().getName() : JWSAlgorithm.RS256.getName());
        } else if (jwk instanceof ECKey ecKey) {
            wrapper.setType(KeyType.EC);
            wrapper.setPublicKey(ecKey.toECPublicKey());
            wrapper.setAlgorithm(
                    ecKey.getAlgorithm() != null ? ecKey.getAlgorithm().getName() : JWSAlgorithm.ES256.getName());
        } else {
            throw new IllegalArgumentException("Unsupported key type");
        }
        return wrapper;
    }
}
