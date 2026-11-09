package com.innspark.loginmonitor.service.impl;

import com.innspark.loginmonitor.exception.TooManyRequestsException;
import com.innspark.loginmonitor.service.RateLimiterService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory sliding window rate limiter implementation.
 *
 * Architectural Characteristics & Limitations:
 * 1. Thread-safe: Uses ConcurrentHashMap and synchronized queues per client IP.
 * 2. In-Memory: Rate limit state is held in local JVM memory; it resets upon application
 *    restart and is not shared across horizontally scaled application instances (e.g., in a
 *    clustered deployment without a distributed cache like Redis).
 * 3. Separate from Suspicious Activity Detection: Tracks request burst frequency in a 1-minute
 *    window independently from the 10-minute brute force detection window.
 */
@Service
public class RateLimiterServiceImpl implements RateLimiterService {

    private static final Logger log = LoggerFactory.getLogger(RateLimiterServiceImpl.class);

    @Value("${app.rate-limit.max-attempts:5}")
    private int maxAttempts;

    @Value("${app.rate-limit.window-seconds:60}")
    private int windowSeconds;

    private final Map<String, Deque<Instant>> attemptHistory = new ConcurrentHashMap<>();

    @Override
    public void checkRateLimit(String clientIp) {
        String key = (clientIp != null && !clientIp.trim().isEmpty()) ? clientIp.trim() : "127.0.0.1";
        Instant now = Instant.now();
        Instant windowStart = now.minusSeconds(windowSeconds);

        Deque<Instant> timestamps = attemptHistory.computeIfAbsent(key, k -> new ArrayDeque<>());

        synchronized (timestamps) {
            // Evict attempts older than the sliding window
            while (!timestamps.isEmpty() && timestamps.peekFirst().isBefore(windowStart)) {
                timestamps.pollFirst();
            }

            if (timestamps.size() >= maxAttempts) {
                log.warn("Rate limit exceeded for IP='{}'. Attempts in window={}", key, timestamps.size());
                throw new TooManyRequestsException(
                        "Rate limit exceeded. Maximum " + maxAttempts + " login attempts allowed per " + windowSeconds + " seconds."
                );
            }

            // Record this attempt timestamp
            timestamps.addLast(now);
        }
    }

    @Override
    public void reset(String clientIp) {
        if (clientIp != null) {
            attemptHistory.remove(clientIp.trim());
        } else {
            attemptHistory.clear();
        }
    }
}
