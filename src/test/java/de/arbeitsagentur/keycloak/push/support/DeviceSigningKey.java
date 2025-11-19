package de.arbeitsagentur.keycloak.push.support;

import com.nimbusds.jose.JWSAlgorithm;
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
import java.util.UUID;

public final class DeviceSigningKey {

    private final JWK key;
    private final JWSAlgorithm algorithm;
    private final JWSSigner signer;

    private DeviceSigningKey(JWK key, JWSAlgorithm algorithm, JWSSigner signer) {
        this.key = key;
        this.algorithm = algorithm;
        this.signer = signer;
    }

    public static DeviceSigningKey generate(DeviceKeyType type) throws Exception {
        return switch (type) {
            case RSA -> generateRsa();
            case ECDSA -> generateEcdsa();
        };
    }

    public static DeviceSigningKey generateRsa() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyID("device-key-" + UUID.randomUUID())
                .algorithm(JWSAlgorithm.RS256)
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        return new DeviceSigningKey(rsaKey, JWSAlgorithm.RS256, new RSASSASigner(rsaKey));
    }

    public static DeviceSigningKey generateEcdsa() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256)
                .keyID("device-key-" + UUID.randomUUID())
                .algorithm(JWSAlgorithm.ES256)
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        return new DeviceSigningKey(ecKey, JWSAlgorithm.ES256, new ECDSASigner(ecKey));
    }

    public JWK publicJwk() {
        return key.toPublicJWK();
    }

    public String keyId() {
        return key.getKeyID();
    }

    public JWSSigner signer() {
        return signer;
    }

    public JWSAlgorithm algorithm() {
        return algorithm;
    }
}
