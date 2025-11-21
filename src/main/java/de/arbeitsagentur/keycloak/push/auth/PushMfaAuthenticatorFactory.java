package de.arbeitsagentur.keycloak.push.auth;

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class PushMfaAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = PushMfaConstants.PROVIDER_ID;

    private static final PushMfaAuthenticator SINGLETON = new PushMfaAuthenticator();
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.ALTERNATIVE,
        AuthenticationExecutionModel.Requirement.DISABLED
    };
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        ProviderConfigProperty loginTtl = new ProviderConfigProperty();
        loginTtl.setName(PushMfaConstants.LOGIN_CHALLENGE_TTL_CONFIG);
        loginTtl.setLabel("Login challenge TTL (seconds)");
        loginTtl.setType(ProviderConfigProperty.STRING_TYPE);
        loginTtl.setHelpText("Time-to-live for login push challenges in seconds.");
        loginTtl.setDefaultValue(String.valueOf(PushMfaConstants.DEFAULT_LOGIN_CHALLENGE_TTL.toSeconds()));

        ProviderConfigProperty maxPending = new ProviderConfigProperty();
        maxPending.setName(PushMfaConstants.MAX_PENDING_AUTH_CHALLENGES_CONFIG);
        maxPending.setLabel("Max pending login challenges");
        maxPending.setType(ProviderConfigProperty.STRING_TYPE);
        maxPending.setHelpText("Maximum number of open login challenges per user.");
        maxPending.setDefaultValue(String.valueOf(PushMfaConstants.DEFAULT_MAX_PENDING_AUTH_CHALLENGES));

        CONFIG_PROPERTIES = List.of(loginTtl, maxPending);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Push MFA Challenge";
    }

    @Override
    public String getReferenceCategory() {
        return PushMfaConstants.CREDENTIAL_TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        // no-op
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    public String getHelpText() {
        return "Sends a simulated push notification that must be approved in order to finish authentication.";
    }
}
