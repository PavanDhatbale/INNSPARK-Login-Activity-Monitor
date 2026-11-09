package com.innspark.loginmonitor.exception;

/**
 * Thrown when a submitted OTP code is incorrect or invalid.
 */
public class InvalidOtpException extends RuntimeException {
    public InvalidOtpException(String message) {
        super(message);
    }
}
