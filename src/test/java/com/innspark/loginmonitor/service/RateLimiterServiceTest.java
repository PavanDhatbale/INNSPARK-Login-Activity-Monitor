package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.exception.TooManyRequestsException;
import com.innspark.loginmonitor.service.impl.RateLimiterServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

class RateLimiterServiceTest {

    private RateLimiterServiceImpl rateLimiterService;

    @BeforeEach
    void setUp() {
        rateLimiterService = new RateLimiterServiceImpl();
        ReflectionTestUtils.setField(rateLimiterService, "maxAttempts", 5);
        ReflectionTestUtils.setField(rateLimiterService, "windowSeconds", 60);
    }

    @Test
    @DisplayName("Should allow up to 5 login attempts within the 60-second window")
    void checkRateLimit_AllowedUnderLimit() {
        String ip = "192.168.1.50";

        assertDoesNotThrow(() -> {
            for (int i = 0; i < 5; i++) {
                rateLimiterService.checkRateLimit(ip);
            }
        });
    }

    @Test
    @DisplayName("Should throw TooManyRequestsException on the 6th login attempt within 60 seconds")
    void checkRateLimit_ExceededLimit() {
        String ip = "192.168.1.60";

        for (int i = 0; i < 5; i++) {
            rateLimiterService.checkRateLimit(ip);
        }

        TooManyRequestsException ex = assertThrows(TooManyRequestsException.class, () ->
                rateLimiterService.checkRateLimit(ip)
        );

        assertTrue(ex.getMessage().contains("Maximum 5 login attempts"));
    }

    @Test
    @DisplayName("Rate limiting for one IP does not block an unrelated IP")
    void checkRateLimit_UnrelatedIpNotBlocked() {
        String blockedIp = "10.0.0.1";
        String cleanIp = "10.0.0.2";

        for (int i = 0; i < 5; i++) {
            rateLimiterService.checkRateLimit(blockedIp);
        }

        assertThrows(TooManyRequestsException.class, () -> rateLimiterService.checkRateLimit(blockedIp));
        assertDoesNotThrow(() -> rateLimiterService.checkRateLimit(cleanIp));
    }

    @Test
    @DisplayName("Resetting rate limit allows subsequent requests from previously limited IP")
    void checkRateLimit_ResetAllowsNewAttempts() {
        String ip = "172.16.0.10";

        for (int i = 0; i < 5; i++) {
            rateLimiterService.checkRateLimit(ip);
        }

        assertThrows(TooManyRequestsException.class, () -> rateLimiterService.checkRateLimit(ip));

        rateLimiterService.reset(ip);

        assertDoesNotThrow(() -> rateLimiterService.checkRateLimit(ip));
    }
}
