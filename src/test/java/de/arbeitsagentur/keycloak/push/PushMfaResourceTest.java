package de.arbeitsagentur.keycloak.push;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import de.arbeitsagentur.keycloak.push.resource.PushMfaResource;
import jakarta.ws.rs.BadRequestException;
import org.junit.jupiter.api.Test;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;

class PushMfaResourceTest {

    @Test
    void computeThumbprintMatchesNimbusForRsa() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).generate().toPublicJWK();
        String json = rsaKey.toJSONString();
        String expected = rsaKey.computeThumbprint().toString();
        String actual = PushMfaResource.computeJwkThumbprint(json);
        assertEquals(expected, actual);
    }

    @Test
    void computeThumbprintMatchesNimbusForEc() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate().toPublicJWK();
        String json = ecKey.toJSONString();
        String expected = ecKey.computeThumbprint().toString();
        String actual = PushMfaResource.computeJwkThumbprint(json);
        assertEquals(expected, actual);
    }

    @Test
    void ensureKeyMatchesRejectsMismatchedAlgorithm() {
        KeyWrapper rsa = new KeyWrapper();
        rsa.setType(KeyType.RSA);
        rsa.setAlgorithm("RS256");
        assertThrows(BadRequestException.class, () -> PushMfaResource.ensureKeyMatchesAlgorithm(rsa, "ES256"));
    }

    @Test
    void ensureKeyMatchesRejectsCurveMismatch() {
        KeyWrapper ec = new KeyWrapper();
        ec.setType(KeyType.EC);
        ec.setAlgorithm("ES256");
        ec.setCurve("P-384");
        assertThrows(BadRequestException.class, () -> PushMfaResource.ensureKeyMatchesAlgorithm(ec, "ES256"));
    }
}
