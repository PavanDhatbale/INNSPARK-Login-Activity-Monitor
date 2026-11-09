package com.innspark.loginmonitor.exception;

/**
 * Exception thrown when CAPTCHA verification fails, a token is missing,
 * or the external CAPTCHA provider cannot be reached safely.
 */
public class InvalidCaptchaException extends RuntimeException {

    public InvalidCaptchaException(String message) {
        super(message);
    }
}
