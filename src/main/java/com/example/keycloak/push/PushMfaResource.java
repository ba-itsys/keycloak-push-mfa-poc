package com.example.keycloak.push;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.crypto.RSAProvider;
import org.keycloak.util.JsonSerialization;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.security.PublicKey;

@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class PushMfaResource {

    private final KeycloakSession session;
    private final PushChallengeStore challengeStore;

    public PushMfaResource(KeycloakSession session) {
        this.session = session;
        this.challengeStore = new PushChallengeStore(session);
    }

    @POST
    @Path("enroll/complete")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response completeEnrollment(EnrollmentCompleteRequest request) {
        String signedResponse = require(request.token(), "token");

        JWSInput deviceResponse;
        try {
            deviceResponse = new JWSInput(signedResponse);
        } catch (Exception ex) {
            throw new BadRequestException("Invalid enrollment token");
        }

        Algorithm algorithm = deviceResponse.getHeader().getAlgorithm();
        if (algorithm == null || !algorithm.name().startsWith("RS")) {
            throw new BadRequestException("Unsupported signature algorithm: " + algorithm);
        }

        JsonNode payload;
        try {
            payload = JsonSerialization.mapper.readTree(deviceResponse.getContent());
        } catch (Exception ex) {
            throw new BadRequestException("Unable to parse enrollment token");
        }

        String userId = require(jsonText(payload, "sub"), "sub");
        AccessToken accessToken = authenticateOrThrow();
        UserModel user = getUser(userId);

        String enrollmentId = require(jsonText(payload, "enrollmentId"), "enrollmentId");
        PushChallenge challenge = challengeStore.get(enrollmentId)
            .orElseThrow(() -> new NotFoundException("Challenge not found"));

        if (challenge.getType() != PushChallenge.Type.ENROLLMENT) {
            throw new BadRequestException("Challenge is not for enrollment");
        }

        if (!Objects.equals(challenge.getUserId(), user.getId())) {
            throw new ForbiddenException("Challenge does not belong to user");
        }

        if (challenge.getStatus() != PushChallengeStatus.PENDING) {
            throw new BadRequestException("Challenge already resolved or expired");
        }

        verifyTokenExpiration(payload.get("exp"), "enrollment token");

        String encodedNonce = require(jsonText(payload, "nonce"), "nonce");
        if (!Objects.equals(encodedNonce, PushChallengeStore.encodeNonce(challenge.getNonce()))) {
            throw new ForbiddenException("Nonce mismatch");
        }

        JsonNode cnf = payload.path("cnf");
        JsonNode jwkNode = cnf.path("jwk");
        if (jwkNode.isMissingNode() || jwkNode.isNull()) {
            throw new BadRequestException("Enrollment token is missing cnf.jwk claim");
        }

        PublicKey devicePublicKey = PushCryptoUtils.publicKeyFromJwk(jwkNode);
        if (devicePublicKey == null) {
            throw new BadRequestException("Unable to derive public key from cnf.jwk");
        }

        if (!RSAProvider.verify(deviceResponse, devicePublicKey)) {
            throw new ForbiddenException("Invalid enrollment token signature");
        }

        String deviceType = require(jsonText(payload, "deviceType"), "deviceType");
        String firebaseId = require(jsonText(payload, "firebaseId"), "firebaseId");
        String pseudonymousUserId = require(jsonText(payload, "pseudonymousUserId"), "pseudonymousUserId");

        String label = request.deviceLabel() == null || request.deviceLabel().isBlank()
            ? PushMfaConstants.USER_CREDENTIAL_DISPLAY_NAME
            : request.deviceLabel();

        PushCredentialData data = new PushCredentialData(
            jwkNode.toString(),
            algorithm.toString(),
            Instant.now().toEpochMilli(),
            deviceType,
            firebaseId,
            pseudonymousUserId);
        CredentialModel credentialModel = PushCredentialService.createCredential(user, label, data);
        challengeStore.resolve(challenge.getId(), PushChallengeStatus.APPROVED);
        
        TokenLogHelper.logJwt("enroll-device-token", request.token());

        return Response.ok(Map.of("status", "enrolled", "credentialId", credentialModel.getId())).build();
    }

    @GET
    @Path("login/pending")
    public Response listPendingChallenges(@jakarta.ws.rs.QueryParam("userId") String userId) {
        AccessToken token = authenticateOrThrow();
        UserModel user = getUser(userId);

        boolean hasCredential = !PushCredentialService.getActiveCredentials(user).isEmpty();
        if (!hasCredential) {
            return Response.ok(Map.of("challenges", List.of())).build();
        }

        List<LoginChallenge> pending = challengeStore.findPendingForUser(realm().getId(), user.getId()).stream()
            .filter(challenge -> challenge.getType() == PushChallenge.Type.AUTHENTICATION)
            .map(challenge -> new LoginChallenge(
                user.getId(),
                challenge.getId(),
                challenge.getExpiresAt()))
            .toList();
        return Response.ok(Map.of("challenges", pending)).build();
    }

    @POST
    @Path("login/challenges/{cid}/respond")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response respondToChallenge(@PathParam("cid") String cid, ChallengeRespondRequest request) {
        AccessToken token = authenticateOrThrow();
        String challengeId = require(cid, "cid");
        PushChallenge challenge = challengeStore.get(challengeId)
            .orElseThrow(() -> new NotFoundException("Challenge not found"));

        String challengeUserId = challenge.getUserId();

        if (challenge.getType() != PushChallenge.Type.AUTHENTICATION) {
            throw new BadRequestException("Challenge is not for login");
        }

        String action = Optional.ofNullable(request.action()).map(String::toLowerCase).orElse(PushMfaConstants.CHALLENGE_APPROVE);
        if (PushMfaConstants.CHALLENGE_DENY.equals(action)) {
            challengeStore.resolve(challengeId, PushChallengeStatus.DENIED);
            return Response.ok(Map.of("status", "denied")).build();
        }

        if (!PushMfaConstants.CHALLENGE_APPROVE.equals(action)) {
            throw new BadRequestException("Unsupported action: " + action);
        }

        String deviceToken = require(request.token(), "token");
        TokenLogHelper.logJwt("login-device-token", deviceToken);
        UserModel user = getUser(challengeUserId);

        JWSInput loginResponse;
        try {
            loginResponse = new JWSInput(deviceToken);
        } catch (Exception ex) {
            throw new BadRequestException("Invalid authentication token");
        }

        Algorithm algorithm = loginResponse.getHeader().getAlgorithm();
        if (algorithm == null || !algorithm.name().startsWith("RS")) {
            throw new BadRequestException("Unsupported signature algorithm: " + algorithm);
        }

        JsonNode payload;
        try {
            payload = JsonSerialization.mapper.readTree(loginResponse.getContent());
        } catch (Exception ex) {
            throw new BadRequestException("Unable to parse authentication token");
        }

        String challengeCredentialId = challenge.getCredentialId();
        CredentialModel credentialModel = challengeCredentialId == null
            ? null
            : PushCredentialService.getCredentialById(user, challengeCredentialId);
        if (credentialModel == null) {
            throw new BadRequestException("Push credential referenced by challenge is missing");
        }

        PushCredentialData data = PushCredentialService.readCredentialData(credentialModel);
        if (data == null || data.getPublicKeyJwk() == null || data.getPublicKeyJwk().isBlank()) {
            throw new BadRequestException("Stored credential missing JWK");
        }

        if (data.getAlgorithm() != null && !algorithm.toString().equalsIgnoreCase(data.getAlgorithm())) {
            throw new BadRequestException("Authentication token algorithm mismatch");
        }

        PublicKey publicKey;
        try {
            publicKey = PushCryptoUtils.publicKeyFromJwkString(data.getPublicKeyJwk());
        } catch (IllegalArgumentException ex) {
            throw new BadRequestException("Stored credential contains invalid JWK");
        }
        if (publicKey == null) {
            throw new BadRequestException("Stored credential missing public key material");
        }

        if (!RSAProvider.verify(loginResponse, publicKey)) {
            throw new ForbiddenException("Invalid authentication token signature");
        }

        verifyTokenExpiration(payload.get("exp"), "authentication token");

        String tokenChallengeId = require(jsonText(payload, "cid"), "cid");
        if (!Objects.equals(tokenChallengeId, challengeId)) {
            throw new ForbiddenException("Challenge mismatch");
        }

        String tokenSubject = require(jsonText(payload, "sub"), "sub");
        if (!Objects.equals(tokenSubject, challengeUserId)) {
            throw new ForbiddenException("Authentication token subject mismatch");
        }

        challengeStore.resolve(challengeId, PushChallengeStatus.APPROVED);
        return Response.ok(Map.of("status", "approved")).build();
    }

    private RealmModel realm() {
        return session.getContext().getRealm();
    }

    private UserModel getUser(String userId) {
        UserModel user = session.users().getUserById(realm(), userId);
        if (user == null) {
            throw new NotFoundException("User not found");
        }
        return user;
    }

    private AccessToken authenticateOrThrow() {
        AuthenticationManager.AuthResult authResult = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (authResult == null) {
            throw new NotAuthorizedException("Bearer token required");
        }
        return authResult.getToken();
    }

    private static String require(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new BadRequestException("Missing field: " + fieldName);
        }
        return value;
    }

    private static String jsonText(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        return value.asText(null);
    }

    private void verifyTokenExpiration(JsonNode expNode, String tokenDescription) {
        if (expNode == null || expNode.isNull()) {
            return;
        }
        long exp = expNode.asLong(Long.MIN_VALUE);
        if (exp != Long.MIN_VALUE && Instant.now().getEpochSecond() > exp) {
            throw new BadRequestException(tokenDescription + " expired");
        }
    }

    record EnrollmentCompleteRequest(@JsonProperty("token") String token,
                                     @JsonProperty("deviceLabel") String deviceLabel) {
    }

    record LoginChallenge(@JsonProperty("userId") String userId,
                          @JsonProperty("cid") String cid,
                          @JsonProperty("expiresAt") Instant expiresAt) {
    }

    record ChallengeRespondRequest(@JsonProperty("token") String token,
                                   @JsonProperty("action") String action) {
    }
}
