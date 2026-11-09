package com.innspark.loginmonitor.exception;

/**
 * Thrown when an OTP resend is requested before the cooldown period has elapsed.
 */
public class OtpCooldownException extends RuntimeException {
    public OtpCooldownException(String message) {
        super(message);
    }
}
