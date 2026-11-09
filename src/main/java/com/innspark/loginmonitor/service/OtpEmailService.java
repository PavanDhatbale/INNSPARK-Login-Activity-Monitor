package com.innspark.loginmonitor.service;

/**
 * Service for delivering One-Time Password (OTP) verification emails.
 */
public interface OtpEmailService {

    /**
     * Delivers an OTP code to the user's registered email address.
     *
     * @param recipientEmail   the user's email address
     * @param username         the user's username
     * @param otp              the raw 6-digit OTP code (used only in mail body, NEVER logged)
     * @param expirationMinutes the validity period in minutes
     * @throws com.innspark.loginmonitor.exception.OtpDeliveryException if delivery fails
     */
    void sendOtpEmail(String recipientEmail, String username, String otp, int expirationMinutes);
}
