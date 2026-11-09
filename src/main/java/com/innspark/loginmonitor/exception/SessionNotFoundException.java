package com.innspark.loginmonitor.exception;

/**
 * Exception thrown when a requested user session cannot be found in the database.
 */
public class SessionNotFoundException extends RuntimeException {

    public SessionNotFoundException(String message) {
        super(message);
    }
}
