package com.innspark.loginmonitor.service;

/**
 * Service interface for enforcing in-memory rate limiting on authentication attempts.
 */
public interface RateLimiterService {

    /**
     * Checks whether the client IP has exceeded the allowed login attempt rate limit.
     * Throws TooManyRequestsException (HTTP 429) if the threshold is violated.
     * Records the current attempt timestamp if within limit.
     *
     * @param clientIp the IP address making the request
     */
    void checkRateLimit(String clientIp);

    /**
     * Resets rate limiting history for a given IP (useful for test isolation).
     *
     * @param clientIp the IP to reset
     */
    void reset(String clientIp);
}
