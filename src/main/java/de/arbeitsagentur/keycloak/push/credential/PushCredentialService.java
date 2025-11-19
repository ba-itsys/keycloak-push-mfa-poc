package de.arbeitsagentur.keycloak.push.credential;

import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import java.util.List;
import java.util.stream.Collectors;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;

public final class PushCredentialService {

    private PushCredentialService() {}

    public static List<CredentialModel> getActiveCredentials(UserModel user) {
        return user.credentialManager()
                .getStoredCredentialsByTypeStream(PushMfaConstants.CREDENTIAL_TYPE)
                .collect(Collectors.toList());
    }

    public static CredentialModel createCredential(UserModel user, String label, PushCredentialData data) {
        CredentialModel model = new CredentialModel();
        model.setType(PushMfaConstants.CREDENTIAL_TYPE);
        model.setUserLabel(label);
        model.setCredentialData(PushCredentialUtils.toJson(data));
        model.setSecretData("{}");
        model.setCreatedDate(System.currentTimeMillis());
        SubjectCredentialManager manager = user.credentialManager();
        return manager.createStoredCredential(model);
    }

    public static PushCredentialData readCredentialData(CredentialModel credentialModel) {
        return PushCredentialUtils.fromJson(credentialModel.getCredentialData());
    }

    public static void updateCredential(UserModel user, CredentialModel credential, PushCredentialData data) {
        credential.setCredentialData(PushCredentialUtils.toJson(data));
        user.credentialManager().updateStoredCredential(credential);
    }

    public static CredentialModel getCredentialById(UserModel user, String credentialId) {
        if (credentialId == null || credentialId.isBlank()) {
            return null;
        }
        CredentialModel model = user.credentialManager().getStoredCredentialById(credentialId);
        if (model == null || !PushMfaConstants.CREDENTIAL_TYPE.equals(model.getType())) {
            return null;
        }
        return model;
    }
}
