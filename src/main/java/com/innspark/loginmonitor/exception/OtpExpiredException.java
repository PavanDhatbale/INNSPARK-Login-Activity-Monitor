package com.innspark.loginmonitor.exception;

/**
 * Thrown when an OTP challenge has expired.
 */
public class OtpExpiredException extends RuntimeException {
    public OtpExpiredException(String message) {
        super(message);
    }
}
