package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.dto.ResendOtpResponse;
import com.innspark.loginmonitor.entity.OtpChallenge;
import com.innspark.loginmonitor.entity.User;

/**
 * Service interface governing One-Time Password (OTP) 2FA lifecycle:
 * generation, cryptographic hashing, verification, rate limiting, and resends.
 */
public interface OtpService {

    /**
     * Checks whether OTP two-factor authentication is globally enabled.
     */
    boolean isOtpEnabled();

    /**
     * Initiates a new OTP challenge for an authenticated user:
     * generates a secure 6-digit numeric OTP, stores its BCrypt hash, and dispatches the code via email.
     *
     * @param user the authenticated user requiring 2FA
     * @return the persisted OtpChallenge entity
     */
    OtpChallenge createAndSendOtp(User user);

    /**
     * Verifies a submitted OTP code against an active challenge.
     * Enforces single-use consumption, expiration checks, attempt limits, and constant-time hash comparison.
     *
     * @param challengeId public UUID identifier of the OTP challenge
     * @param otpCode     raw 6-digit numeric code submitted by client
     * @param clientIp    client IP address for auditing
     * @return the associated User upon successful verification
     */
    User verifyOtp(String challengeId, String otpCode, String clientIp);

    /**
     * Generates and dispatches a fresh OTP code for an active pending challenge,
     * enforcing a configurable resend cooldown and maximum resend limit.
     *
     * @param challengeId public UUID identifier of the OTP challenge
     * @param clientIp    client IP address for auditing
     * @return confirmation containing updated expiration time
     */
    ResendOtpResponse resendOtp(String challengeId, String clientIp);
}
