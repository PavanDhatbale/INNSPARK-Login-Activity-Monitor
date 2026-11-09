package com.innspark.loginmonitor.exception;

/**
 * Thrown when OTP email delivery fails.
 */
public class OtpDeliveryException extends RuntimeException {
    public OtpDeliveryException(String message) {
        super(message);
    }
}
