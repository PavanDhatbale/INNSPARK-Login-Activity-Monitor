package com.innspark.loginmonitor.exception;

/**
 * Exception thrown when authentication is attempted for a disabled account.
 * Maps to HTTP 403 Forbidden.
 */
public class AccountDisabledException extends RuntimeException {

    public AccountDisabledException(String message) {
        super(message);
    }
}
