package com.innspark.loginmonitor.enums;

/**
 * Status of an OTP (One-Time Password) challenge lifecycle.
 */
public enum OtpChallengeStatus {
    /**
     * Challenge is active and awaiting user verification.
     */
    PENDING,

    /**
     * Challenge has been successfully verified. Single-use; cannot be reused.
     */
    VERIFIED,

    /**
     * Challenge exceeded validity time window.
     */
    EXPIRED,

    /**
     * Challenge failed due to exceeding maximum allowed verification attempts.
     */
    FAILED
}
