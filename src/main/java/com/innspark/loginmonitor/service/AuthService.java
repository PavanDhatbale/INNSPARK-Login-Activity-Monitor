package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.dto.AuthLoginRequest;
import com.innspark.loginmonitor.dto.AuthResponse;
import com.innspark.loginmonitor.dto.ResendOtpRequest;
import com.innspark.loginmonitor.dto.ResendOtpResponse;
import com.innspark.loginmonitor.dto.VerifyOtpRequest;

/**
 * Service interface for authenticating users, managing 2FA/OTP verification, and active sessions.
 */
public interface AuthService {

    /**
     * Authenticates credentials with BCrypt, enforces rate limiting, records login attempts,
     * triggers suspicious activity detection, and either initiates 2FA OTP flow or creates a session.
     *
     * @param request credentials payload
     * @param clientIp client IP address
     * @return AuthResponse containing OTP challenge information (if 2FA enabled) or session token
     */
    AuthResponse login(AuthLoginRequest request, String clientIp);

    /**
     * Completes Step 2 of 2FA: verifies submitted OTP code against active challenge and creates session.
     *
     * @param request  challenge ID and 6-digit OTP code
     * @param clientIp client IP address
     * @return AuthResponse containing active session token and user details
     */
    AuthResponse verifyOtp(VerifyOtpRequest request, String clientIp);

    /**
     * Dispatches a fresh OTP code for an active challenge, respecting cooldown and resend limits.
     *
     * @param request  challenge ID payload
     * @param clientIp client IP address
     * @return ResendOtpResponse confirming dispatch and expiration
     */
    ResendOtpResponse resendOtp(ResendOtpRequest request, String clientIp);

    /**
     * Terminates and invalidates an active session token.
     *
     * @param sessionToken the session token to invalidate
     */
    void logout(String sessionToken);

    /**
     * Checks whether CAPTCHA verification is required for a given username and client IP
     * based on recent failed login attempts exceeding the configured threshold.
     */
    boolean isCaptchaRequired(String username, String clientIp);

    /**
     * Returns the configured failure threshold that triggers mandatory CAPTCHA enforcement.
     */
    int getCaptchaFailureThreshold();
}
