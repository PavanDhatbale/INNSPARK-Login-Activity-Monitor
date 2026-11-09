package com.innspark.loginmonitor.exception;

/**
 * Exception thrown when the rate limit threshold for requests is exceeded.
 * Maps to HTTP 429 Too Many Requests.
 */
public class TooManyRequestsException extends RuntimeException {

    public TooManyRequestsException(String message) {
        super(message);
    }
}
