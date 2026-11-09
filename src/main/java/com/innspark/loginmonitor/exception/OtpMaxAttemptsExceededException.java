package com.innspark.loginmonitor.exception;

/**
 * Thrown when the maximum number of failed OTP attempts or resend attempts has been exceeded.
 */
public class OtpMaxAttemptsExceededException extends RuntimeException {
    public OtpMaxAttemptsExceededException(String message) {
        super(message);
    }
}
