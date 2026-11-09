package com.innspark.loginmonitor.exception;

/**
 * Exception thrown when authentication fails due to invalid credentials.
 * Maps to HTTP 401 Unauthorized with a generic message.
 */
public class AuthenticationFailedException extends RuntimeException {

    public AuthenticationFailedException(String message) {
        super(message);
    }
}
