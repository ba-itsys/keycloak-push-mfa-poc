package de.arbeitsagentur.keycloak.push.resource;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import de.arbeitsagentur.keycloak.push.challenge.PushChallenge;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStatus;
import de.arbeitsagentur.keycloak.push.challenge.PushChallengeStore;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialData;
import de.arbeitsagentur.keycloak.push.credential.PushCredentialService;
import de.arbeitsagentur.keycloak.push.util.PushMfaConstants;
import de.arbeitsagentur.keycloak.push.util.PushSignatureVerifier;
import de.arbeitsagentur.keycloak.push.util.TokenLogHelper;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.sse.Sse;
import jakarta.ws.rs.sse.SseEventSink;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import org.jboss.logging.Logger;
import org.keycloak.TokenVerifier;
import org.keycloak.TokenVerifier.Predicate;
import org.keycloak.common.VerificationException;
import org.keycloak.credential.CredentialModel;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.TokenUtil;

@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class PushMfaResource {

    private static final Logger LOG = Logger.getLogger(PushMfaResource.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final KeycloakSession session;
    private final PushChallengeStore challengeStore;

    public PushMfaResource(KeycloakSession session) {
        this.session = session;
        this.challengeStore = new PushChallengeStore(session);
    }

    @GET
    @Path("enroll/challenges/{challengeId}/events")
    @Produces(MediaType.SERVER_SENT_EVENTS)
    public void streamEnrollmentEvents(
            @PathParam("challengeId") String challengeId,
            @QueryParam("secret") String secret,
            @jakarta.ws.rs.core.Context SseEventSink sink,
            @jakarta.ws.rs.core.Context Sse sse) {
        if (sink == null || sse == null) {
            return;
        }
        LOG.infof("Received enrollment SSE stream request for challenge %s", challengeId);
        CompletableFuture.runAsync(() -> emitEnrollmentEvents(challengeId, secret, sink, sse));
    }

    @POST
    @Path("enroll/complete")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response completeEnrollment(EnrollmentCompleteRequest request) {
        String deviceToken = require(request.token(), "token");
        TokenLogHelper.logJwt("enroll-device-token", deviceToken);

        JWSInput deviceResponse;
        try {
            deviceResponse = new JWSInput(deviceToken);
        } catch (Exception ex) {
            throw new BadRequestException("Invalid enrollment token");
        }

        Algorithm algorithm = deviceResponse.getHeader().getAlgorithm();
        requireSupportedAlgorithm(algorithm, "enrollment token");

        JsonNode payload;
        try {
            payload = JsonSerialization.mapper.readTree(deviceResponse.getContent());
        } catch (Exception ex) {
            throw new BadRequestException("Unable to parse enrollment token");
        }

        String userId = require(jsonText(payload, "sub"), "sub");
        UserModel user = getUser(userId);

        String enrollmentId = require(jsonText(payload, "enrollmentId"), "enrollmentId");
        PushChallenge challenge =
                challengeStore.get(enrollmentId).orElseThrow(() -> new NotFoundException("Challenge not found"));

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
        KeyWrapper deviceKey = keyWrapperFromNode(jwkNode);
        ensureKeyMatchesAlgorithm(deviceKey, algorithm.name());

        if (!PushSignatureVerifier.verify(deviceResponse, deviceKey)) {
            throw new ForbiddenException("Invalid enrollment token signature");
        }

        String deviceType = require(jsonText(payload, "deviceType"), "deviceType");
        String pushProviderId = require(jsonText(payload, "pushProviderId"), "pushProviderId");
        String pushProviderType = require(jsonText(payload, "pushProviderType"), "pushProviderType");
        String pseudonymousUserId = require(jsonText(payload, "pseudonymousUserId"), "pseudonymousUserId");
        String deviceId = require(jsonText(payload, "deviceId"), "deviceId");

        String labelClaim = jsonText(payload, "deviceLabel");
        String label =
                labelClaim == null || labelClaim.isBlank() ? PushMfaConstants.USER_CREDENTIAL_DISPLAY_NAME : labelClaim;

        PushCredentialData data = new PushCredentialData(
                jwkNode.toString(),
                algorithm.toString(),
                Instant.now().toEpochMilli(),
                deviceType,
                pushProviderId,
                pushProviderType,
                pseudonymousUserId,
                deviceId);
        CredentialModel credentialModel = PushCredentialService.createCredential(user, label, data);
        challengeStore.resolve(challenge.getId(), PushChallengeStatus.APPROVED);

        return Response.ok(Map.of("status", "enrolled")).build();
    }

    @GET
    @Path("login/pending")
    public Response listPendingChallenges(
            @jakarta.ws.rs.QueryParam("userId") String userId, @Context HttpHeaders headers, @Context UriInfo uriInfo) {
        String normalizedUserId = require(userId, "userId");
        DeviceAssertion device = authenticateDevice(headers, uriInfo, "GET");
        if (!Objects.equals(device.user().getId(), normalizedUserId)) {
            throw new ForbiddenException("Device token subject mismatch");
        }

        CredentialModel deviceCredential = device.credential();

        List<LoginChallenge> pending =
                challengeStore.findPendingForUser(realm().getId(), device.user().getId()).stream()
                        .filter(challenge -> challenge.getType() == PushChallenge.Type.AUTHENTICATION)
                        .filter(challenge -> Objects.equals(challenge.getCredentialId(), deviceCredential.getId()))
                        .filter(this::ensureAuthenticationSessionActive)
                        .map(challenge -> new LoginChallenge(
                                device.user().getId(),
                                challenge.getId(),
                                challenge.getExpiresAt().getEpochSecond(),
                                challenge.getClientId()))
                        .toList();
        return Response.ok(Map.of("challenges", pending)).build();
    }

    @POST
    @Path("login/challenges/{cid}/respond")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response respondToChallenge(
            @PathParam("cid") String cid,
            ChallengeRespondRequest request,
            @Context HttpHeaders headers,
            @Context UriInfo uriInfo) {
        String challengeId = require(cid, "cid");
        PushChallenge challenge =
                challengeStore.get(challengeId).orElseThrow(() -> new NotFoundException("Challenge not found"));

        String challengeUserId = challenge.getUserId();

        if (challenge.getType() != PushChallenge.Type.AUTHENTICATION) {
            throw new BadRequestException("Challenge is not for login");
        }

        DeviceAssertion assertion = authenticateDevice(headers, uriInfo, "POST");

        UserModel user = assertion.user();
        if (!Objects.equals(user.getId(), challengeUserId)) {
            throw new ForbiddenException("Authentication token subject mismatch");
        }

        CredentialModel credentialModel = assertion.credential();
        if (challenge.getCredentialId() != null
                && !Objects.equals(challenge.getCredentialId(), credentialModel.getId())) {
            throw new ForbiddenException("Authentication token device mismatch");
        }

        String deviceToken = require(request.token(), "token");
        TokenLogHelper.logJwt("login-device-token", deviceToken);

        JWSInput loginResponse;
        try {
            loginResponse = new JWSInput(deviceToken);
        } catch (Exception ex) {
            throw new BadRequestException("Invalid authentication token");
        }

        Algorithm algorithm = loginResponse.getHeader().getAlgorithm();
        requireSupportedAlgorithm(algorithm, "authentication token");

        JsonNode payload;
        try {
            payload = JsonSerialization.mapper.readTree(loginResponse.getContent());
        } catch (Exception ex) {
            throw new BadRequestException("Unable to parse authentication token");
        }

        String tokenAction = Optional.ofNullable(jsonText(payload, "action"))
                .map(String::toLowerCase)
                .orElse(PushMfaConstants.CHALLENGE_APPROVE);

        String tokenChallengeId = require(jsonText(payload, "cid"), "cid");
        if (!Objects.equals(tokenChallengeId, challengeId)) {
            throw new ForbiddenException("Challenge mismatch");
        }

        PushCredentialData data = assertion.credentialData();

        if (data.getAlgorithm() != null && !algorithm.toString().equalsIgnoreCase(data.getAlgorithm())) {
            throw new BadRequestException("Authentication token algorithm mismatch");
        }

        KeyWrapper publicKey = keyWrapperFromString(data.getPublicKeyJwk());
        ensureKeyMatchesAlgorithm(publicKey, algorithm.name());

        if (!PushSignatureVerifier.verify(loginResponse, publicKey)) {
            throw new ForbiddenException("Invalid authentication token signature");
        }

        verifyTokenExpiration(payload.get("exp"), "authentication token");

        String tokenSubject = require(jsonText(payload, "sub"), "sub");
        if (!Objects.equals(tokenSubject, challengeUserId)) {
            throw new ForbiddenException("Authentication token subject mismatch");
        }

        if (PushMfaConstants.CHALLENGE_DENY.equals(tokenAction)) {
            challengeStore.resolve(challengeId, PushChallengeStatus.DENIED);
            return Response.ok(Map.of("status", "denied")).build();
        }

        if (!PushMfaConstants.CHALLENGE_APPROVE.equals(tokenAction)) {
            throw new BadRequestException("Unsupported action: " + tokenAction);
        }

        challengeStore.resolve(challengeId, PushChallengeStatus.APPROVED);
        return Response.ok(Map.of("status", "approved")).build();
    }

    @GET
    @Path("login/challenges/{cid}/events")
    @Produces(MediaType.SERVER_SENT_EVENTS)
    public void streamLoginChallengeEvents(
            @PathParam("cid") String challengeId,
            @QueryParam("secret") String secret,
            @Context SseEventSink sink,
            @Context Sse sse) {
        if (sink == null || sse == null) {
            return;
        }
        LOG.infof("Received login SSE stream request for challenge %s", challengeId);
        CompletableFuture.runAsync(() -> emitLoginChallengeEvents(challengeId, secret, sink, sse));
    }

    @PUT
    @Path("device/push-provider")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response updateDevicePushProvider(
            @Context HttpHeaders headers, @Context UriInfo uriInfo, UpdatePushProviderRequest request) {
        DeviceAssertion device = authenticateDevice(headers, uriInfo, "PUT");
        String pushProviderId = require(request.pushProviderId(), "pushProviderId");
        String pushProviderType = request.pushProviderType();
        PushCredentialData current = device.credentialData();
        if (pushProviderType == null || pushProviderType.isBlank()) {
            pushProviderType = current.getPushProviderType();
        }
        if (pushProviderId.equals(current.getPushProviderId())
                && pushProviderType.equals(current.getPushProviderType())) {
            return Response.ok(Map.of("status", "unchanged")).build();
        }
        PushCredentialData updated = new PushCredentialData(
                current.getPublicKeyJwk(),
                current.getAlgorithm(),
                current.getCreatedAt(),
                current.getDeviceType(),
                pushProviderId,
                pushProviderType,
                current.getPseudonymousUserId(),
                current.getDeviceId());
        PushCredentialService.updateCredential(device.user(), device.credential(), updated);
        LOG.infof(
                "Updated push provider {type=%s} for device %s (user=%s)",
                pushProviderType, current.getDeviceId(), device.user().getId());
        return Response.ok(Map.of("status", "updated")).build();
    }

    @PUT
    @Path("device/rotate-key")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response rotateDeviceKey(
            @Context HttpHeaders headers, @Context UriInfo uriInfo, RotateDeviceKeyRequest request) {
        DeviceAssertion device = authenticateDevice(headers, uriInfo, "PUT");
        JsonNode jwkNode = Optional.ofNullable(request.publicKeyJwk())
                .orElseThrow(() -> new BadRequestException("Request missing publicKeyJwk"));
        String algorithm = require(request.algorithm(), "algorithm");
        requireSupportedAlgorithm(algorithm, "rotate-key request");
        String normalizedAlgorithm = algorithm.toUpperCase();

        KeyWrapper newKey = keyWrapperFromNode(jwkNode);
        ensureKeyMatchesAlgorithm(newKey, normalizedAlgorithm);

        PushCredentialData current = device.credentialData();
        PushCredentialData updated = new PushCredentialData(
                jwkNode.toString(),
                normalizedAlgorithm,
                Instant.now().toEpochMilli(),
                current.getDeviceType(),
                current.getPushProviderId(),
                current.getPushProviderType(),
                current.getPseudonymousUserId(),
                current.getDeviceId());
        PushCredentialService.updateCredential(device.user(), device.credential(), updated);
        LOG.infof(
                "Rotated device key for %s (user=%s)",
                current.getDeviceId(), device.user().getId());
        return Response.ok(Map.of("status", "rotated")).build();
    }

    private RealmModel realm() {
        return session.getContext().getRealm();
    }

    private UserModel userByUsername(String username) {
        UserModel user = session.users().getUserByUsername(realm(), username);
        if (user == null) {
            throw new NotFoundException("User not found");
        }
        return user;
    }

    private UserModel getUser(String userId) {
        UserModel user = session.users().getUserById(realm(), userId);
        if (user == null) {
            throw new NotFoundException("User not found");
        }
        return user;
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

    private String requireAccessToken(HttpHeaders headers) {
        if (headers == null) {
            throw new NotAuthorizedException("DPoP access token required");
        }
        String authorization = headers.getHeaderString(HttpHeaders.AUTHORIZATION);
        if (authorization == null || authorization.isBlank()) {
            throw new NotAuthorizedException("DPoP access token required");
        }
        String token;
        if (authorization.regionMatches(true, 0, "DPoP ", 0, "DPoP ".length())) {
            token = authorization.substring("DPoP ".length()).trim();
        } else if (authorization.regionMatches(true, 0, "Bearer ", 0, "Bearer ".length())) {
            token = authorization.substring("Bearer ".length()).trim();
        } else {
            throw new NotAuthorizedException("DPoP access token required");
        }
        if (token.isBlank()) {
            throw new NotAuthorizedException("DPoP access token required");
        }
        return token;
    }

    private AccessToken authenticateAccessToken(String tokenString) {
        try {
            Predicate<? super AccessToken> revocationCheck = new TokenManager.TokenRevocationCheck(session);
            TokenVerifier<AccessToken> verifier = TokenVerifier.create(tokenString, AccessToken.class)
                    .withDefaultChecks()
                    .realmUrl(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm().getName()))
                    .checkActive(true)
                    .tokenType(List.of(TokenUtil.TOKEN_TYPE_BEARER, TokenUtil.TOKEN_TYPE_DPOP))
                    .withChecks(revocationCheck);

            String kid = verifier.getHeader().getKeyId();
            String alg = verifier.getHeader().getAlgorithm().name();
            SignatureVerifierContext svc =
                    session.getProvider(SignatureProvider.class, alg).verifier(kid);
            verifier.verifierContext(svc);
            return verifier.verify().getToken();
        } catch (VerificationException ex) {
            throw new NotAuthorizedException("Invalid access token", ex);
        }
    }

    private String requireDpopProof(HttpHeaders headers) {
        if (headers == null) {
            throw new NotAuthorizedException("DPoP proof required");
        }
        String value = headers.getHeaderString("DPoP");
        if (value == null || value.isBlank()) {
            throw new NotAuthorizedException("DPoP proof required");
        }
        return value.trim();
    }

    private DeviceAssertion authenticateDevice(HttpHeaders headers, UriInfo uriInfo, String httpMethod) {
        String accessTokenString = requireAccessToken(headers);
        AccessToken accessToken = authenticateAccessToken(accessTokenString);
        String proof = requireDpopProof(headers);
        TokenLogHelper.logJwt("dpop-proof", proof);
        JWSInput dpop;
        try {
            dpop = new JWSInput(proof);
        } catch (Exception ex) {
            throw new BadRequestException("Invalid DPoP proof");
        }

        Algorithm algorithm = dpop.getHeader().getAlgorithm();
        requireSupportedAlgorithm(algorithm, "DPoP proof");

        String typ = dpop.getHeader().getType();
        if (typ == null || !"dpop+jwt".equalsIgnoreCase(typ)) {
            throw new BadRequestException("DPoP proof missing typ=dpop+jwt");
        }

        JsonNode payload;
        try {
            payload = JsonSerialization.mapper.readTree(dpop.getContent());
        } catch (Exception ex) {
            throw new BadRequestException("Unable to parse DPoP proof");
        }

        String htm = require(jsonText(payload, "htm"), "htm");
        if (!httpMethod.equalsIgnoreCase(htm)) {
            throw new ForbiddenException("DPoP proof htm mismatch");
        }

        String htu = require(jsonText(payload, "htu"), "htu");
        String actualHtu = uriInfo.getRequestUri().toString();
        if (!actualHtu.equals(htu)) {
            throw new ForbiddenException("DPoP proof htu mismatch");
        }

        long iat = payload.path("iat").asLong(Long.MIN_VALUE);
        if (iat == Long.MIN_VALUE) {
            throw new BadRequestException("DPoP proof missing iat");
        }
        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - iat) > 120) {
            throw new BadRequestException("DPoP proof expired");
        }

        String tokenSubject = require(jsonText(payload, "sub"), "sub");
        String tokenDeviceId = require(jsonText(payload, "deviceId"), "deviceId");

        UserModel user = getUser(tokenSubject);

        List<CredentialModel> credentials = PushCredentialService.getActiveCredentials(user);
        if (credentials.isEmpty()) {
            throw new ForbiddenException("Device not registered for user");
        }

        CredentialModel credential = credentials.stream()
                .filter(model -> {
                    PushCredentialData credentialData = PushCredentialService.readCredentialData(model);
                    return credentialData != null && tokenDeviceId.equals(credentialData.getDeviceId());
                })
                .findFirst()
                .orElseThrow(() -> new ForbiddenException("Device not registered for user"));

        PushCredentialData credentialData = PushCredentialService.readCredentialData(credential);
        if (credentialData == null
                || credentialData.getPublicKeyJwk() == null
                || credentialData.getPublicKeyJwk().isBlank()) {
            throw new BadRequestException("Stored credential missing JWK");
        }
        if (credentialData.getAlgorithm() != null
                && !algorithm.toString().equalsIgnoreCase(credentialData.getAlgorithm())) {
            throw new BadRequestException("DPoP algorithm mismatch");
        }

        KeyWrapper keyWrapper = keyWrapperFromString(credentialData.getPublicKeyJwk());
        ensureKeyMatchesAlgorithm(keyWrapper, algorithm.name());

        if (!PushSignatureVerifier.verify(dpop, keyWrapper)) {
            throw new ForbiddenException("Invalid DPoP proof signature");
        }

        AccessToken.Confirmation confirmation = accessToken.getConfirmation();
        if (confirmation == null
                || confirmation.getKeyThumbprint() == null
                || confirmation.getKeyThumbprint().isBlank()) {
            throw new ForbiddenException("Access token missing DPoP binding");
        }
        String expectedJkt = computeJwkThumbprint(credentialData.getPublicKeyJwk());
        if (!Objects.equals(expectedJkt, confirmation.getKeyThumbprint())) {
            throw new ForbiddenException("Access token DPoP binding mismatch");
        }

        return new DeviceAssertion(user, credential, credentialData);
    }

    public static String computeJwkThumbprint(String jwkJson) {
        try {
            JsonNode jwk = JsonSerialization.mapper.readTree(jwkJson);
            String kty = require(jwk.path("kty").asText(null), "kty");
            var canonical = JsonSerialization.mapper.createObjectNode();
            if ("RSA".equalsIgnoreCase(kty)) {
                String n = require(jwk.path("n").asText(null), "n");
                String e = require(jwk.path("e").asText(null), "e");
                canonical.put("e", e);
                canonical.put("kty", "RSA");
                canonical.put("n", n);
            } else if ("EC".equalsIgnoreCase(kty)) {
                String crv = require(jwk.path("crv").asText(null), "crv");
                String x = require(jwk.path("x").asText(null), "x");
                String y = require(jwk.path("y").asText(null), "y");
                canonical.put("crv", crv);
                canonical.put("kty", "EC");
                canonical.put("x", x);
                canonical.put("y", y);
            } else {
                throw new BadRequestException("Unsupported key type for DPoP binding");
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(JsonSerialization.mapper.writeValueAsBytes(canonical));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (BadRequestException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new BadRequestException("Unable to compute JWK thumbprint", ex);
        }
    }

    private static boolean isSupportedAlgorithmName(String algName) {
        if (algName == null || algName.isBlank()) {
            return false;
        }
        String normalized = algName.toUpperCase();
        return normalized.startsWith("RS") || normalized.startsWith("ES");
    }

    private static void requireSupportedAlgorithm(Algorithm algorithm, String context) {
        if (algorithm == null || !isSupportedAlgorithmName(algorithm.name())) {
            throw new BadRequestException("Unsupported " + context + " algorithm: " + algorithm);
        }
    }

    private static void requireSupportedAlgorithm(String algName, String context) {
        if (!isSupportedAlgorithmName(algName)) {
            throw new BadRequestException("Unsupported " + context + " algorithm: " + algName);
        }
    }

    public static void ensureKeyMatchesAlgorithm(KeyWrapper keyWrapper, String algorithm) {
        String normalizedAlg = algorithm == null ? null : algorithm.toUpperCase();
        if (normalizedAlg == null || normalizedAlg.isBlank()) {
            throw new BadRequestException("Missing algorithm");
        }
        if (keyWrapper == null) {
            throw new BadRequestException("JWK is required");
        }
        if (keyWrapper.getAlgorithm() != null && !normalizedAlg.equalsIgnoreCase(keyWrapper.getAlgorithm())) {
            throw new BadRequestException("JWK algorithm mismatch");
        }
        if (KeyType.RSA.equals(keyWrapper.getType())) {
            if (!normalizedAlg.startsWith("RS")) {
                throw new BadRequestException("RSA keys require RS* algorithms");
            }
        } else if (KeyType.EC.equals(keyWrapper.getType())) {
            if (!normalizedAlg.startsWith("ES")) {
                throw new BadRequestException("EC keys require ES* algorithms");
            }
            String curve = keyWrapper.getCurve();
            String expectedCurve = curveForAlgorithm(normalizedAlg);
            if (curve != null && expectedCurve != null && !expectedCurve.equalsIgnoreCase(curve)) {
                throw new BadRequestException("EC curve " + curve + " incompatible with " + normalizedAlg);
            }
        } else {
            throw new BadRequestException("Unsupported key type: " + keyWrapper.getType());
        }
        keyWrapper.setAlgorithm(normalizedAlg);
    }

    private static String curveForAlgorithm(String algorithm) {
        return switch (algorithm) {
            case "ES256" -> "P-256";
            case "ES384" -> "P-384";
            case "ES512" -> "P-521";
            default -> null;
        };
    }

    private KeyWrapper keyWrapperFromNode(JsonNode jwkNode) {
        if (jwkNode == null) {
            throw new BadRequestException("JWK is required");
        }
        try {
            JWK jwk = JsonSerialization.mapper.treeToValue(jwkNode, JWK.class);
            KeyWrapper wrapper = JWKSUtils.getKeyWrapper(jwk);
            if (wrapper == null) {
                throw new BadRequestException("Unsupported JWK");
            }
            return wrapper;
        } catch (BadRequestException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new BadRequestException("Unable to parse JWK", ex);
        }
    }

    private KeyWrapper keyWrapperFromString(String jwkJson) {
        if (jwkJson == null || jwkJson.isBlank()) {
            throw new BadRequestException("Stored credential missing JWK");
        }
        try {
            JsonNode node = JsonSerialization.mapper.readTree(jwkJson);
            return keyWrapperFromNode(node);
        } catch (BadRequestException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new BadRequestException("Stored credential contains invalid JWK", ex);
        }
    }

    private boolean ensureAuthenticationSessionActive(PushChallenge challenge) {
        String rootSessionId = challenge.getRootSessionId();
        if (rootSessionId == null || rootSessionId.isBlank()) {
            return true;
        }
        var root = session.authenticationSessions().getRootAuthenticationSession(realm(), rootSessionId);
        if (root != null) {
            return true;
        }
        LOG.infof("Cleaning up stale challenge %s because auth session %s is gone", challenge.getId(), rootSessionId);
        challengeStore.remove(challenge.getId());
        return false;
    }

    private void emitLoginChallengeEvents(String challengeId, String secret, SseEventSink sink, Sse sse) {
        try (SseEventSink eventSink = sink) {
            LOG.infof("Starting login SSE stream for challenge %s", challengeId);
            if (secret == null || secret.isBlank()) {
                LOG.infof("Login SSE rejected for %s due to missing secret", challengeId);
                sendLoginStatusEvent(eventSink, sse, "INVALID", null);
                return;
            }

            PushChallengeStatus lastStatus = null;
            while (!eventSink.isClosed()) {
                Optional<PushChallenge> challengeOpt = challengeStore.get(challengeId);
                if (challengeOpt.isEmpty()) {
                    LOG.infof("Login SSE challenge %s not found", challengeId);
                    sendLoginStatusEvent(eventSink, sse, "NOT_FOUND", null);
                    break;
                }
                PushChallenge challenge = challengeOpt.get();
                if (challenge.getType() != PushChallenge.Type.AUTHENTICATION) {
                    LOG.infof(
                            "Login SSE rejected for %s because challenge type is %s", challengeId, challenge.getType());
                    sendLoginStatusEvent(eventSink, sse, "BAD_TYPE", null);
                    break;
                }
                if (!Objects.equals(secret, challenge.getWatchSecret())) {
                    LOG.infof("Login SSE forbidden for %s due to secret mismatch", challengeId);
                    sendLoginStatusEvent(eventSink, sse, "FORBIDDEN", null);
                    break;
                }

                PushChallengeStatus currentStatus = challenge.getStatus();
                if (lastStatus != currentStatus) {
                    sendLoginStatusEvent(eventSink, sse, currentStatus.name(), challenge);
                    lastStatus = currentStatus;
                }

                if (currentStatus != PushChallengeStatus.PENDING) {
                    LOG.infof("Login SSE exiting for %s after reaching status %s", challengeId, currentStatus);
                    break;
                }

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    sendLoginStatusEvent(eventSink, sse, "INTERRUPTED", null);
                    LOG.infof("Login SSE interrupted for %s", challengeId);
                    break;
                }
            }
            LOG.infof("Login SSE stream closed for challenge %s", challengeId);
        } catch (Exception ex) {
            LOG.infof(ex, "Failed to stream login events for %s", challengeId);
        }
    }

    private void emitEnrollmentEvents(String challengeId, String secret, SseEventSink sink, Sse sse) {
        try (SseEventSink eventSink = sink) {
            LOG.infof("Starting enrollment SSE stream for challenge %s", challengeId);
            if (secret == null || secret.isBlank()) {
                LOG.infof("Enrollment SSE rejected for %s due to missing secret", challengeId);
                sendEnrollmentStatusEvent(eventSink, sse, "INVALID", null);
                return;
            }

            PushChallengeStatus lastStatus = null;
            while (!eventSink.isClosed()) {
                Optional<PushChallenge> challengeOpt = challengeStore.get(challengeId);
                if (challengeOpt.isEmpty()) {
                    LOG.infof("Enrollment SSE challenge %s not found", challengeId);
                    sendEnrollmentStatusEvent(eventSink, sse, "NOT_FOUND", null);
                    break;
                }
                PushChallenge challenge = challengeOpt.get();
                if (!Objects.equals(secret, challenge.getWatchSecret())) {
                    LOG.infof("Enrollment SSE forbidden for %s due to secret mismatch", challengeId);
                    sendEnrollmentStatusEvent(eventSink, sse, "FORBIDDEN", null);
                    break;
                }

                PushChallengeStatus currentStatus = challenge.getStatus();
                if (lastStatus != currentStatus) {
                    sendEnrollmentStatusEvent(eventSink, sse, currentStatus.name(), challenge);
                    lastStatus = currentStatus;
                }

                if (currentStatus != PushChallengeStatus.PENDING) {
                    LOG.infof("Enrollment SSE exiting for %s after reaching status %s", challengeId, currentStatus);
                    break;
                }

                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    sendEnrollmentStatusEvent(eventSink, sse, "INTERRUPTED", null);
                    LOG.infof("Enrollment SSE interrupted for %s", challengeId);
                    break;
                }
            }
            LOG.infof("Enrollment SSE stream closed for challenge %s", challengeId);
        } catch (Exception ex) {
            LOG.infof(ex, "Failed to stream enrollment events for %s", challengeId);
        }
    }

    private void sendLoginStatusEvent(SseEventSink sink, Sse sse, String status, PushChallenge challenge) {
        if (sink.isClosed()) {
            return;
        }
        try {
            String targetChallengeId = challenge != null ? challenge.getId() : "n/a";
            LOG.infof("Emitting login SSE status %s for challenge %s", status, targetChallengeId);
            Map<String, Object> payload = new HashMap<>();
            payload.put("status", status);
            if (challenge != null) {
                payload.put("challengeId", challenge.getId());
                payload.put("expiresAt", challenge.getExpiresAt().toString());
                payload.put("clientId", challenge.getClientId());
                if (challenge.getResolvedAt() != null) {
                    payload.put("resolvedAt", challenge.getResolvedAt().toString());
                }
            }
            String data = JsonSerialization.writeValueAsString(payload);
            sink.send(sse.newEventBuilder()
                    .name("status")
                    .data(String.class, data)
                    .build());
        } catch (Exception ex) {
            LOG.infof(
                    ex,
                    "Unable to send login SSE status %s for %s",
                    status,
                    challenge != null ? challenge.getId() : "n/a");
        }
    }

    private void sendEnrollmentStatusEvent(SseEventSink sink, Sse sse, String status, PushChallenge challenge) {
        if (sink.isClosed()) {
            return;
        }
        try {
            String targetChallengeId = challenge != null ? challenge.getId() : "n/a";
            LOG.infof("Emitting enrollment SSE status %s for challenge %s", status, targetChallengeId);
            Map<String, Object> payload = new HashMap<>();
            payload.put("status", status);
            if (challenge != null) {
                payload.put("challengeId", challenge.getId());
                payload.put("expiresAt", challenge.getExpiresAt().toString());
                if (challenge.getResolvedAt() != null) {
                    payload.put("resolvedAt", challenge.getResolvedAt().toString());
                }
            }
            String data = JsonSerialization.writeValueAsString(payload);
            sink.send(sse.newEventBuilder()
                    .name("status")
                    .data(String.class, data)
                    .build());
        } catch (Exception ex) {
            LOG.infof(
                    ex,
                    "Unable to send enrollment SSE status %s for %s",
                    status,
                    challenge != null ? challenge.getId() : "n/a");
        }
    }

    record EnrollmentCompleteRequest(@JsonProperty("token") String token) {}

    record LoginChallenge(
            @JsonProperty("userId") String userId,
            @JsonProperty("cid") String cid,
            @JsonProperty("expiresAt") long expiresAt,
            @JsonProperty("clientId") String clientId) {}

    record ChallengeRespondRequest(@JsonProperty("token") String token) {}

    record UpdatePushProviderRequest(
            @JsonProperty("pushProviderId") String pushProviderId,
            @JsonProperty("pushProviderType") String pushProviderType) {}

    record RotateDeviceKeyRequest(
            @JsonProperty("publicKeyJwk") JsonNode publicKeyJwk, @JsonProperty("algorithm") String algorithm) {}

    record DeviceAssertion(UserModel user, CredentialModel credential, PushCredentialData credentialData) {}
}
