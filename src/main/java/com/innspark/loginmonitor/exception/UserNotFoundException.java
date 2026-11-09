package com.innspark.loginmonitor.exception;

/**
 * Exception thrown when a requested user account cannot be found in the database.
 */
public class UserNotFoundException extends RuntimeException {

    public UserNotFoundException(String message) {
        super(message);
    }
}
