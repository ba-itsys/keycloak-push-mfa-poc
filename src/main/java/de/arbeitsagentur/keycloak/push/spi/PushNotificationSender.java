package de.arbeitsagentur.keycloak.push.spi;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.Provider;

/**
 * SPI used to deliver push confirmation messages to enrolled devices.
 */
public interface PushNotificationSender extends Provider {

    void send(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            String confirmToken,
            String pseudonymousUserId,
            String challengeId,
            String clientId);
}
