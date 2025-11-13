package com.example.keycloak.push;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public final class PushNotificationService {

    private static final Logger LOG = Logger.getLogger(PushNotificationService.class);

    private PushNotificationService() {
    }

    public static void notifyDevice(KeycloakSession session,
                                    RealmModel realm,
                                    UserModel user,
                                    String confirmToken,
                                    String pseudonymousUserId,
                                    String challengeId,
                                    String clientId) {
        LOG.infof("Simulated Firebase push {realm=%s,user=%s,version=%s,type=%s,pseudonymousUserId=%s,challengeId=%s,clientId=%s}",
            realm.getName(),
            user.getUsername(),
            PushMfaConstants.PUSH_MESSAGE_VERSION,
            PushMfaConstants.PUSH_MESSAGE_TYPE,
            pseudonymousUserId,
            challengeId,
            clientId);
        TokenLogHelper.logJwt("confirm-token", confirmToken);
    }
}
