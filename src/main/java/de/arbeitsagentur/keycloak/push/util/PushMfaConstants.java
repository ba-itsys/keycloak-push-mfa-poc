package de.arbeitsagentur.keycloak.push.util;

import java.time.Duration;

public final class PushMfaConstants {

    private PushMfaConstants() {}

    public static final String CREDENTIAL_TYPE = "push-mfa";
    public static final String PROVIDER_ID = "push-mfa-authenticator";
    public static final String USER_CREDENTIAL_DISPLAY_NAME = "Push MFA Device";
    public static final String DEFAULT_PUSH_PROVIDER_TYPE = "log";

    public static final String CHALLENGE_NOTE = "push-mfa-challenge-id";
    public static final String CHALLENGE_WATCH_SECRET_NOTE = "push-mfa-challenge-watch-secret";
    public static final String CHALLENGE_APPROVE = "approve";
    public static final String CHALLENGE_DENY = "deny";
    public static final String ENROLL_CHALLENGE_NOTE = "push-mfa-enroll-challenge-id";
    public static final String ENROLL_SSE_TOKEN_NOTE = "push-mfa-enroll-sse-token";
    public static final String LOGIN_CHALLENGE_TTL_CONFIG = "loginChallengeTtlSeconds";
    public static final String ENROLLMENT_CHALLENGE_TTL_CONFIG = "enrollmentChallengeTtlSeconds";
    public static final String MAX_PENDING_AUTH_CHALLENGES_CONFIG = "maxPendingChallenges";
    public static final int PUSH_MESSAGE_VERSION = 1;
    public static final int PUSH_MESSAGE_TYPE = 1;
    public static final String PUSH_APP_URI_PREFIX = "push-mfa-login-app://?token=";

    public static final int NONCE_BYTES_SIZE = 32;
    public static final Duration DEFAULT_LOGIN_CHALLENGE_TTL = Duration.ofSeconds(120);
    public static final Duration DEFAULT_ENROLLMENT_CHALLENGE_TTL = Duration.ofSeconds(120);
    public static final int DEFAULT_MAX_PENDING_AUTH_CHALLENGES = 1;

    public static final String REQUIRED_ACTION_ID = "push-mfa-register";
}
