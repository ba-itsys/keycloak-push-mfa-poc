package com.example.keycloak.push;

import jakarta.ws.rs.core.MultivaluedMap;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.security.SecureRandom;
import java.util.List;

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
        PushChallenge challenge = fetchOrCreateChallenge(context, authSession, store, false);

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
        form.setAttribute("enrollChallengeId", challenge.getId());
        form.setAttribute("pollingIntervalSeconds", 3);
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

        boolean hasCredential = !PushCredentialService.getActiveCredentials(context.getUser()).isEmpty();

        if (!hasCredential) {
            if (checkOnly) {
                requiredActionChallenge(context);
                return;
            }
            cleanupChallenge(authSession, store);
            PushChallenge challenge = fetchOrCreateChallenge(context, authSession, store, false);
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

    private PushChallenge fetchOrCreateChallenge(RequiredActionContext context,
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
            challenge = store.create(
                context.getRealm().getId(),
                context.getUser().getId(),
                nonceBytes,
                PushChallenge.Type.ENROLLMENT,
                PushMfaConstants.CHALLENGE_TTL,
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
    }
}
