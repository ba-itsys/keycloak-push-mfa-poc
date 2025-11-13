package com.example.keycloak.push;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.List;
import java.util.Optional;

public class PushMfaAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(PushMfaAuthenticator.class);
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        List<CredentialModel> credentials = PushCredentialService.getActiveCredentials(context.getUser());
        if (credentials.isEmpty()) {
            LOG.infof("User %s attempted push MFA without registered device", context.getUser().getId());
            context.success();
            return;
        }

        CredentialModel credential = credentials.get(0);
        PushCredentialData credentialData = PushCredentialService.readCredentialData(credential);
        if (credentialData == null || credentialData.getPseudonymousUserId() == null) {
            LOG.warn("Push credential missing pseudonymous user id; skipping push MFA");
            context.success();
            return;
        }

        PushChallengeStore challengeStore = new PushChallengeStore(context.getSession());
        int pendingChallenges = challengeStore.countPendingAuthentication(context.getRealm().getId(), context.getUser().getId());
        if (pendingChallenges >= PushMfaConstants.MAX_PENDING_AUTH_CHALLENGES) {
            LOG.debugf("User %s already has %d pending push challenges; refusing new one",
                context.getUser().getId(), pendingChallenges);
            context.failureChallenge(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR,
                context.form().setError("push-mfa-too-many-challenges")
                    .createErrorPage(Response.Status.TOO_MANY_REQUESTS));
            return;
        }
        byte[] challengeBytes = new byte[0];

        PushChallenge pushChallenge = challengeStore.create(
            context.getRealm().getId(),
            context.getUser().getId(),
            challengeBytes,
            PushChallenge.Type.AUTHENTICATION,
            PushMfaConstants.CHALLENGE_TTL,
            credential.getId());

        authSession.setAuthNote(PushMfaConstants.CHALLENGE_NOTE, pushChallenge.getId());

        String clientId = context.getAuthenticationSession().getClient() != null
            ? context.getAuthenticationSession().getClient().getClientId()
            : null;
        String confirmToken = PushConfirmTokenBuilder.build(
            context.getSession(),
            context.getRealm(),
            credentialData.getPseudonymousUserId(),
            pushChallenge.getId(),
            pushChallenge.getExpiresAt(),
            context.getUriInfo().getBaseUri(),
            clientId);

        LOG.debugf("Push message prepared {version=%s,type=%s,pseudonymousUserId=%s}",
            PushMfaConstants.PUSH_MESSAGE_VERSION,
            PushMfaConstants.PUSH_MESSAGE_TYPE,
            credentialData.getPseudonymousUserId());

        PushNotificationService.notifyDevice(
            context.getSession(),
            context.getRealm(),
            context.getUser(),
            confirmToken,
            credentialData.getPseudonymousUserId(),
            pushChallenge.getId(),
            clientId);
        showWaitingForm(context, pushChallenge.getId(), credentialData, confirmToken);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        PushChallengeStore challengeStore = new PushChallengeStore(context.getSession());
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String challengeId = authSession.getAuthNote(PushMfaConstants.CHALLENGE_NOTE);

        if (challengeId == null) {
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                context.form().setError("push-mfa-missing-challenge").createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
            return;
        }

        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        if (form.containsKey("cancel")) {
            challengeStore.resolve(challengeId, PushChallengeStatus.DENIED);
            challengeStore.remove(challengeId);
            authSession.removeAuthNote(PushMfaConstants.CHALLENGE_NOTE);
            context.forkWithErrorMessage(new FormMessage("push-mfa-cancelled-message"));
            return;
        }

        Optional<PushChallenge> challenge = challengeStore.get(challengeId);
        if (challenge.isEmpty()) {
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                context.form().setError("push-mfa-expired").createForm("push-expired.ftl"));
            authSession.removeAuthNote(PushMfaConstants.CHALLENGE_NOTE);
            return;
        }

        PushChallenge current = challenge.get();
        switch (current.getStatus()) {
            case APPROVED -> {
                challengeStore.remove(challengeId);
                authSession.removeAuthNote(PushMfaConstants.CHALLENGE_NOTE);
                context.success();
            }
            case DENIED -> {
                challengeStore.remove(challengeId);
                authSession.removeAuthNote(PushMfaConstants.CHALLENGE_NOTE);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError("push-mfa-denied").createForm("push-denied.ftl"));
            }
            case EXPIRED -> {
                challengeStore.remove(challengeId);
                authSession.removeAuthNote(PushMfaConstants.CHALLENGE_NOTE);
                context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                    context.form().setError("push-mfa-expired").createForm("push-expired.ftl"));
            }
            case PENDING -> {
                CredentialModel credentialModel = resolveCredentialForChallenge(context.getUser(), current);
                PushCredentialData credentialData = credentialModel == null ? null : PushCredentialService.readCredentialData(credentialModel);
                String clientId = context.getAuthenticationSession().getClient() != null
                    ? context.getAuthenticationSession().getClient().getClientId()
                    : null;
                String confirmToken = (credentialModel == null || credentialData == null || credentialData.getPseudonymousUserId() == null)
                    ? null
                    : PushConfirmTokenBuilder.build(
                        context.getSession(),
                        context.getRealm(),
                        credentialData.getPseudonymousUserId(),
                        current.getId(),
                        current.getExpiresAt(),
                        context.getUriInfo().getBaseUri(),
                        clientId);

                showWaitingForm(context, current.getId(), credentialData, confirmToken);
            }
            default -> throw new IllegalStateException("Unhandled push challenge status: " + current.getStatus());
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return !PushCredentialService.getActiveCredentials(user).isEmpty();
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        if (!PushCredentialService.getActiveCredentials(user).isEmpty()) {
            return;
        }

        boolean alreadyRequired = user.getRequiredActionsStream()
            .anyMatch(action -> PushMfaConstants.REQUIRED_ACTION_ID.equals(action));
        if (!alreadyRequired) {
            user.addRequiredAction(PushMfaConstants.REQUIRED_ACTION_ID);
        }
    }

    @Override
    public void close() {
        // no-op
    }

    private CredentialModel resolveCredentialForChallenge(UserModel user, PushChallenge challenge) {
        if (challenge.getCredentialId() != null) {
            CredentialModel byId = PushCredentialService.getCredentialById(user, challenge.getCredentialId());
            if (byId != null) {
                return byId;
            }
            LOG.warnf("Credential %s referenced by challenge %s not found for user %s",
                challenge.getCredentialId(),
                challenge.getId(),
                user.getId());
        }
        List<CredentialModel> credentials = PushCredentialService.getActiveCredentials(user);
        return credentials.isEmpty() ? null : credentials.get(0);
    }

    private void showWaitingForm(AuthenticationFlowContext context,
                                 String challengeId,
                                 PushCredentialData credentialData,
                                 String confirmToken) {
        context.form()
            .setAttribute("challengeId", challengeId)
            .setAttribute("pollingIntervalSeconds", 5)
            .setAttribute("pushUsername", context.getUser().getUsername())
            .setAttribute("pushConfirmToken", confirmToken)
            .setAttribute("pushPseudonymousId", credentialData != null ? credentialData.getPseudonymousUserId() : null)
            .setAttribute("pushMessageVersion", PushMfaConstants.PUSH_MESSAGE_VERSION)
            .setAttribute("pushMessageType", PushMfaConstants.PUSH_MESSAGE_TYPE);

        context.challenge(context.form().createForm("push-wait.ftl"));
    }
}
