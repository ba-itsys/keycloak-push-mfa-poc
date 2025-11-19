package de.arbeitsagentur.keycloak.push.spi;

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import de.arbeitsagentur.keycloak.push.util.TokenLogHelper;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

final class LoggingPushNotificationSender implements PushNotificationSender {

    private static final Logger LOG = Logger.getLogger(LoggingPushNotificationSender.class);

    @Override
    public void send(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            String confirmToken,
            String pseudonymousUserId,
            String challengeId,
            String clientId) {
        LOG.infof(
                "Simulated push {realm=%s,user=%s,version=%d,type=%d,pseudonymousUserId=%s,challengeId=%s,clientId=%s}",
                realm.getName(),
                user.getUsername(),
                PushMfaConstants.PUSH_MESSAGE_VERSION,
                PushMfaConstants.PUSH_MESSAGE_TYPE,
                pseudonymousUserId,
                challengeId,
                clientId);
        TokenLogHelper.logJwt("confirm-token", confirmToken);
    }

    @Override
    public void close() {
        // no-op
    }
}
