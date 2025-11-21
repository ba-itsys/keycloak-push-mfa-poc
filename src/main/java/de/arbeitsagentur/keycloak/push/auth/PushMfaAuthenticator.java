package de.arbeitsagentur.keycloak.push.auth;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialService;
import de.arbeitsagentur.keycloak.push.service.PushNotificationService;
import de.arbeitsagentur.keycloak.push.token.PushConfirmTokenBuilder;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.sessions.AuthenticationSessionModel;

public class PushMfaAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(PushMfaAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        Duration loginChallengeTtl = parseDurationSeconds(
                config, PushMfaConstants.LOGIN_CHALLENGE_TTL_CONFIG, PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL);
        int maxPendingChallenges = parsePositiveInt(
                config,
                PushMfaConstants.MAX_PENDING_AUTH_CHALLENGES_CONFIG,
                PushMfaConstants.DEFAULT_MAX_PENDING_AUTH_CHALLENGES);

        List<CredentialModel> credentials = PushCredentialService.getActiveCredentials(context.getUser());
        if (credentials.isEmpty()) {
            LOG.infof(
                    "User %s attempted push MFA without registered device",
                    context.getUser().getId());
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
        int pendingChallenges = challengeStore.countPendingAuthentication(
                context.getRealm().getId(), context.getUser().getId());
        if (pendingChallenges >= maxPendingChallenges) {
            LOG.debugf(
                    "User %s already has %d pending push challenges (limit %d); refusing new one",
                    context.getUser().getId(), pendingChallenges, maxPendingChallenges);
            context.failureChallenge(
                    AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR,
                    context.form()
                            .setError("push-mfa-too-many-challenges")
                            .createErrorPage(Response.Status.TOO_MANY_REQUESTS));
            return;
        }
        byte[] challengeBytes = new byte[0];

        String clientId = context.getAuthenticationSession().getClient() != null
                ? context.getAuthenticationSession().getClient().getClientId()
                : null;

        String rootSessionId = context.getAuthenticationSession().getParentSession() != null
                ? context.getAuthenticationSession().getParentSession().getId()
                : null;

        String watchSecret = KeycloakModelUtils.generateId();
        PushChallenge pushChallenge = challengeStore.create(
                context.getRealm().getId(),
                context.getUser().getId(),
                challengeBytes,
                PushChallenge.Type.AUTHENTICATION,
                loginChallengeTtl,
                credential.getId(),
                clientId,
                watchSecret,
                rootSessionId);

        authSession.setAuthNote(PushMfaConstants.CHALLENGE_NOTE, pushChallenge.getId());
        authSession.setAuthNote(PushMfaConstants.CHALLENGE_WATCH_SECRET_NOTE, watchSecret);

        String confirmToken = PushConfirmTokenBuilder.build(
                context.getSession(),
                context.getRealm(),
                credentialData.getPseudonymousUserId(),
                pushChallenge.getId(),
                pushChallenge.getExpiresAt(),
                context.getUriInfo().getBaseUri(),
                clientId);

        LOG.debugf(
                "Push message prepared {version=%d,type=%d,pseudonymousUserId=%s}",
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
                clientId,
                credentialData.getPushProviderType());
        showWaitingForm(context, pushChallenge, credentialData, confirmToken);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        PushChallengeStore challengeStore = new PushChallengeStore(context.getSession());
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String challengeId = authSession.getAuthNote(PushMfaConstants.CHALLENGE_NOTE);

        if (challengeId == null) {
            context.failureChallenge(
                    AuthenticationFlowError.INTERNAL_ERROR,
                    context.form()
                            .setError("push-mfa-missing-challenge")
                            .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
            return;
        }

        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        if (form.containsKey("cancel")) {
            challengeStore.resolve(challengeId, PushChallengeStatus.DENIED);
            challengeStore.remove(challengeId);
            clearChallengeNotes(authSession);
            context.forkWithErrorMessage(new FormMessage("push-mfa-cancelled-message"));
            return;
        }

        Optional<PushChallenge> challenge = challengeStore.get(challengeId);
        if (challenge.isEmpty()) {
            context.failureChallenge(
                    AuthenticationFlowError.EXPIRED_CODE,
                    context.form().setError("push-mfa-expired").createForm("push-expired.ftl"));
            clearChallengeNotes(authSession);
            return;
        }

        PushChallenge current = challenge.get();
        switch (current.getStatus()) {
            case APPROVED -> {
                challengeStore.remove(challengeId);
                clearChallengeNotes(authSession);
                context.success();
            }
            case DENIED -> {
                challengeStore.remove(challengeId);
                clearChallengeNotes(authSession);
                context.failureChallenge(
                        AuthenticationFlowError.INVALID_CREDENTIALS,
                        context.form().setError("push-mfa-denied").createForm("push-denied.ftl"));
            }
            case EXPIRED -> {
                challengeStore.remove(challengeId);
                clearChallengeNotes(authSession);
                context.failureChallenge(
                        AuthenticationFlowError.EXPIRED_CODE,
                        context.form().setError("push-mfa-expired").createForm("push-expired.ftl"));
            }
            case PENDING -> {
                CredentialModel credentialModel = resolveCredentialForChallenge(context.getUser(), current);
                PushCredentialData credentialData =
                        credentialModel == null ? null : PushCredentialService.readCredentialData(credentialModel);
                String clientId = current.getClientId();
                if (clientId == null && context.getAuthenticationSession().getClient() != null) {
                    clientId = context.getAuthenticationSession().getClient().getClientId();
                }
                String confirmToken = (credentialModel == null
                                || credentialData == null
                                || credentialData.getPseudonymousUserId() == null)
                        ? null
                        : PushConfirmTokenBuilder.build(
                                context.getSession(),
                                context.getRealm(),
                                credentialData.getPseudonymousUserId(),
                                current.getId(),
                                current.getExpiresAt(),
                                context.getUriInfo().getBaseUri(),
                                clientId);

                showWaitingForm(context, current, credentialData, confirmToken);
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

        boolean alreadyRequired =
                user.getRequiredActionsStream().anyMatch(action -> PushMfaConstants.REQUIRED_ACTION_ID.equals(action));
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
            LOG.warnf(
                    "Credential %s referenced by challenge %s not found for user %s",
                    challenge.getCredentialId(), challenge.getId(), user.getId());
        }
        List<CredentialModel> credentials = PushCredentialService.getActiveCredentials(user);
        return credentials.isEmpty() ? null : credentials.get(0);
    }

    private void showWaitingForm(
            AuthenticationFlowContext context,
            PushChallenge challenge,
            PushCredentialData credentialData,
            String confirmToken) {
        String challengeId = challenge != null ? challenge.getId() : null;
        String watchSecret = challenge != null ? challenge.getWatchSecret() : null;
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        if ((watchSecret == null || watchSecret.isBlank()) && authSession != null) {
            watchSecret = authSession.getAuthNote(PushMfaConstants.CHALLENGE_WATCH_SECRET_NOTE);
        }

        context.form()
                .setAttribute("challengeId", challengeId)
                .setAttribute("pollingIntervalSeconds", 5)
                .setAttribute("pushUsername", context.getUser().getUsername())
                .setAttribute("pushConfirmToken", confirmToken)
                .setAttribute(
                        "pushPseudonymousId", credentialData != null ? credentialData.getPseudonymousUserId() : null)
                .setAttribute("pushMessageVersion", String.valueOf(PushMfaConstants.PUSH_MESSAGE_VERSION))
                .setAttribute("pushMessageType", String.valueOf(PushMfaConstants.PUSH_MESSAGE_TYPE));

        String watchUrl = buildChallengeWatchUrl(context, challengeId, watchSecret);
        if (watchUrl != null) {
            context.form().setAttribute("pushChallengeWatchUrl", watchUrl);
        }

        context.challenge(context.form().createForm("push-wait.ftl"));
    }

    private void clearChallengeNotes(AuthenticationSessionModel authSession) {
        if (authSession == null) {
            return;
        }
        authSession.removeAuthNote(PushMfaConstants.CHALLENGE_NOTE);
        authSession.removeAuthNote(PushMfaConstants.CHALLENGE_WATCH_SECRET_NOTE);
    }

    private String buildChallengeWatchUrl(AuthenticationFlowContext context, String challengeId, String watchSecret) {
        if (challengeId == null || watchSecret == null || watchSecret.isBlank()) {
            return null;
        }
        UriBuilder builder = context.getUriInfo()
                .getBaseUriBuilder()
                .path("realms")
                .path(context.getRealm().getName())
                .path("push-mfa")
                .path("login")
                .path("challenges")
                .path(challengeId)
                .path("events")
                .queryParam("secret", watchSecret);
        return builder.build().toString();
    }

    private Duration parseDurationSeconds(AuthenticatorConfigModel config, String key, Duration defaultValue) {
        if (config == null || config.getConfig() == null) {
            return defaultValue;
        }
        String value = config.getConfig().get(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            long seconds = Long.parseLong(value.trim());
            return seconds > 0 ? Duration.ofSeconds(seconds) : defaultValue;
        } catch (NumberFormatException ex) {
            return defaultValue;
        }
    }

    private int parsePositiveInt(AuthenticatorConfigModel config, String key, int defaultValue) {
        if (config == null || config.getConfig() == null) {
            return defaultValue;
        }
        String value = config.getConfig().get(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            return parsed > 0 ? parsed : defaultValue;
        } catch (NumberFormatException ex) {
            return defaultValue;
        }
    }
}
