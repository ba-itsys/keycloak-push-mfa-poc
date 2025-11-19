package de.arbeitsagentur.keycloak.push.credential;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;

public class PushCredentialData {

    private final String publicKeyJwk;
    private final String algorithm;
    private final long createdAt;
    private final String deviceType;
    private final String pushProviderId;
    private final String pushProviderType;
    private final String pseudonymousUserId;
    private final String deviceId;

    @JsonCreator
    public PushCredentialData(
            @JsonProperty("publicKeyJwk") String publicKeyJwk,
            @JsonProperty("algorithm") String algorithm,
            @JsonProperty("createdAt") long createdAt,
            @JsonProperty("deviceType") String deviceType,
            @JsonProperty("pushProviderId") String pushProviderId,
            @JsonProperty("pushProviderType") String pushProviderType,
            @JsonProperty("pseudonymousUserId") String pseudonymousUserId,
            @JsonProperty("deviceId") String deviceId) {
        this.publicKeyJwk = publicKeyJwk;
        this.algorithm = algorithm;
        this.createdAt = createdAt;
        this.deviceType = deviceType;
        this.pushProviderId = pushProviderId;
        this.pushProviderType = (pushProviderType == null || pushProviderType.isBlank())
                ? PushMfaConstants.DEFAULT_PUSH_PROVIDER_TYPE
                : pushProviderType;
        this.pseudonymousUserId = pseudonymousUserId;
        this.deviceId = deviceId;
    }

    public String getPublicKeyJwk() {
        return publicKeyJwk;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public String getDeviceType() {
        return deviceType;
    }

    public String getPushProviderId() {
        return pushProviderId;
    }

    public String getPushProviderType() {
        return pushProviderType;
    }

    public String getPseudonymousUserId() {
        return pseudonymousUserId;
    }

    public String getDeviceId() {
        return deviceId;
    }
}
