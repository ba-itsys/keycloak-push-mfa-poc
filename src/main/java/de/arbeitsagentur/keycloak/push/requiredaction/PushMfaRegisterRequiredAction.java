package de.arbeitsagentur.keycloak.push.requiredaction;

import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialService;
import de.arbeitsagentur.keycloak.push.token.PushEnrollmentTokenBuilder;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import jakarta.ws.rs.core.MultivaluedMap;
import java.security.SecureRandom;
import java.util.List;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.sessions.AuthenticationSessionModel;

public class PushMfaRegisterRequiredAction implements RequiredActionProvider, RequiredActionFactory {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public String getId() {
        return PushMfaConstants.REQUIRED_ACTION_ID;
    }

    @Override
    public String getDisplayText() {
        return "Register Push MFA device";
    }

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        // Handled by authenticator setRequiredActions.
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        PushChallengeStore store = new PushChallengeStore(context.getSession());
        PushChallenge challenge = ensureWatchableChallenge(
                context, authSession, store, fetchOrCreateChallenge(context, authSession, store, false));

        String enrollmentToken = PushEnrollmentTokenBuilder.build(
                context.getSession(),
                context.getRealm(),
                context.getUser(),
                challenge,
                context.getUriInfo().getBaseUri());

        LoginFormsProvider form = context.form();
        form.setAttribute("pushUsername", context.getUser().getUsername());
        form.setAttribute("enrollmentToken", enrollmentToken);
        form.setAttribute("qrPayload", enrollmentToken);
        form.setAttribute("pushQrUri", PushMfaConstants.PUSH_APP_URI_PREFIX + enrollmentToken);
        form.setAttribute("enrollChallengeId", challenge.getId());
        form.setAttribute("pollingIntervalSeconds", 3);
        String eventsUrl = buildEnrollmentEventsUrl(context, challenge);
        if (eventsUrl != null) {
            form.setAttribute("enrollEventsUrl", eventsUrl);
        }
        context.challenge(form.createForm("push-register.ftl"));
    }

    @Override
    public void processAction(RequiredActionContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        PushChallengeStore store = new PushChallengeStore(context.getSession());

        boolean checkOnly = formData.containsKey("check");

        if (formData.containsKey("refresh")) {
            cleanupChallenge(authSession, store);
            requiredActionChallenge(context);
            return;
        }

        boolean hasCredential =
                !PushCredentialService.getActiveCredentials(context.getUser()).isEmpty();

        if (!hasCredential) {
            if (checkOnly) {
                requiredActionChallenge(context);
                return;
            }
            cleanupChallenge(authSession, store);
            PushChallenge challenge = ensureWatchableChallenge(
                    context, authSession, store, fetchOrCreateChallenge(context, authSession, store, false));
            String enrollmentToken = PushEnrollmentTokenBuilder.build(
                    context.getSession(),
                    context.getRealm(),
                    context.getUser(),
                    challenge,
                    context.getUriInfo().getBaseUri());

            LoginFormsProvider form = context.form().setError("push-mfa-registration-missing");
            form.setAttribute("pushUsername", context.getUser().getUsername());
            form.setAttribute("enrollmentToken", enrollmentToken);
            form.setAttribute("qrPayload", enrollmentToken);
            form.setAttribute("enrollChallengeId", challenge.getId());
            form.setAttribute("pollingIntervalSeconds", 5);
            String eventsUrl = buildEnrollmentEventsUrl(context, challenge);
            if (eventsUrl != null) {
                form.setAttribute("enrollEventsUrl", eventsUrl);
            }
            context.challenge(form.createForm("push-register.ftl"));
            return;
        }

        cleanupChallenge(authSession, store);
        context.success();
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
        // no-op
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return List.of();
    }

    private PushChallenge fetchOrCreateChallenge(
            RequiredActionContext context,
            AuthenticationSessionModel authSession,
            PushChallengeStore store,
            boolean forceNew) {
        PushChallenge challenge = null;
        if (!forceNew) {
            String existingId = authSession.getAuthNote(PushMfaConstants.ENROLL_CHALLENGE_NOTE);
            if (existingId != null) {
                challenge = store.get(existingId)
                        .filter(c -> c.getStatus() == PushChallengeStatus.PENDING)
                        .orElse(null);
                if (challenge == null) {
                    store.remove(existingId);
                    authSession.removeAuthNote(PushMfaConstants.ENROLL_CHALLENGE_NOTE);
                }
            }
        }

        if (challenge == null) {
            byte[] nonceBytes = new byte[PushMfaConstants.NONCE_BYTES_SIZE];
            RANDOM.nextBytes(nonceBytes);
            String watchSecret = KeycloakModelUtils.generateId();
            challenge = store.create(
                    context.getRealm().getId(),
                    context.getUser().getId(),
                    nonceBytes,
                    PushChallenge.Type.ENROLLMENT,
                    PushMfaConstants.CHALLENGE_TTL,
                    null,
                    null,
                    watchSecret,
                    null);
            authSession.setAuthNote(PushMfaConstants.ENROLL_CHALLENGE_NOTE, challenge.getId());
        }

        return challenge;
    }

    private void cleanupChallenge(AuthenticationSessionModel authSession, PushChallengeStore store) {
        String challengeId = authSession.getAuthNote(PushMfaConstants.ENROLL_CHALLENGE_NOTE);
        if (challengeId != null) {
            store.remove(challengeId);
            authSession.removeAuthNote(PushMfaConstants.ENROLL_CHALLENGE_NOTE);
        }
        authSession.removeAuthNote(PushMfaConstants.ENROLL_SSE_TOKEN_NOTE);
    }

    private PushChallenge ensureWatchableChallenge(
            RequiredActionContext context,
            AuthenticationSessionModel authSession,
            PushChallengeStore store,
            PushChallenge challenge) {
        PushChallenge ensured = challenge;
        if (ensured == null
                || ensured.getWatchSecret() == null
                || ensured.getWatchSecret().isBlank()) {
            cleanupChallenge(authSession, store);
            ensured = fetchOrCreateChallenge(context, authSession, store, true);
        }
        if (ensured.getWatchSecret() != null && !ensured.getWatchSecret().isBlank()) {
            authSession.setAuthNote(PushMfaConstants.ENROLL_SSE_TOKEN_NOTE, ensured.getWatchSecret());
        }
        return ensured;
    }

    private String buildEnrollmentEventsUrl(RequiredActionContext context, PushChallenge challenge) {
        String watchSecret = challenge.getWatchSecret();
        if (watchSecret == null || watchSecret.isBlank()) {
            return null;
        }
        return context.getUriInfo()
                .getBaseUriBuilder()
                .path("realms")
                .path(context.getRealm().getName())
                .path("push-mfa")
                .path("enroll")
                .path("challenges")
                .path(challenge.getId())
                .path("events")
                .queryParam("secret", watchSecret)
                .build()
                .toString();
    }
}
