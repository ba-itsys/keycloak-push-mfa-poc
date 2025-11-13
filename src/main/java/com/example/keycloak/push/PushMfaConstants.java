package com.example.keycloak.push;

import java.time.Duration;

public final class PushMfaConstants {

    private PushMfaConstants() {
    }

    public static final String CREDENTIAL_TYPE = "push-mfa";
    public static final String PROVIDER_ID = "push-mfa-authenticator";
    public static final String USER_CREDENTIAL_DISPLAY_NAME = "Push MFA Device";

    public static final String CHALLENGE_NOTE = "push-mfa-challenge-id";
    public static final String CHALLENGE_APPROVE = "approve";
    public static final String CHALLENGE_DENY = "deny";
    public static final String ENROLL_CHALLENGE_NOTE = "push-mfa-enroll-challenge-id";
    public static final String PUSH_MESSAGE_VERSION = "1";
    public static final String PUSH_MESSAGE_TYPE = "1";

    public static final int NONCE_BYTES_SIZE = 32;
    public static final Duration CHALLENGE_TTL = Duration.ofSeconds(120);
    public static final int MAX_PENDING_AUTH_CHALLENGES = 1;

    public static final String REQUIRED_ACTION_ID = "push-mfa-register";
}
