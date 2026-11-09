package com.innspark.loginmonitor.dto;

import com.innspark.loginmonitor.enums.Role;

import java.time.LocalDateTime;

/**
 * Response payload returned upon POST /auth/login and POST /auth/verify-otp.
 *
 * Scenarios:
 * 1. OTP Required (Step 1 of 2FA):
 *    - otpRequired = true
 *    - challengeId = UUID token
 *    - sessionToken = null (no session created yet!)
 * 2. Authenticated (Step 2 of 2FA, or if OTP disabled):
 *    - otpRequired = false
 *    - challengeId = null
 *    - sessionToken = valid 48-byte token
 */
public class AuthResponse {

    private boolean otpRequired;
    private String challengeId;
    private String sessionToken;
    private String tokenType = "Bearer";
    private String username;
    private Role role;
    private LocalDateTime expiresAt;
    private String message;

    public AuthResponse() {
    }

    /**
     * Backward-compatible constructor for authenticated responses (OTP disabled or direct).
     */
    public AuthResponse(String sessionToken, String username, Role role, LocalDateTime expiresAt, String message) {
        this.otpRequired = false;
        this.challengeId = null;
        this.sessionToken = sessionToken;
        this.tokenType = "Bearer";
        this.username = username;
        this.role = role;
        this.expiresAt = expiresAt;
        this.message = message;
    }

    /**
     * Factory constructor for OTP challenge response (Step 1).
     * sessionToken and tokenType are strictly null at this stage.
     */
    public static AuthResponse otpChallenge(String challengeId, String username, Role role, LocalDateTime expiresAt) {
        AuthResponse response = new AuthResponse();
        response.setOtpRequired(true);
        response.setChallengeId(challengeId);
        response.setUsername(username);
        response.setRole(role);
        response.setExpiresAt(expiresAt);
        response.setTokenType(null);
        response.setSessionToken(null);
        response.setMessage("OTP verification required. A 6-digit code has been sent to your registered email address.");
        return response;
    }

    /**
     * Factory constructor for authenticated session response (Step 2).
     */
    public static AuthResponse authenticated(String sessionToken, String username, Role role, LocalDateTime expiresAt) {
        AuthResponse response = new AuthResponse();
        response.setOtpRequired(false);
        response.setChallengeId(null);
        response.setSessionToken(sessionToken);
        response.setTokenType("Bearer");
        response.setUsername(username);
        response.setRole(role);
        response.setExpiresAt(expiresAt);
        response.setMessage("Authentication successful");
        return response;
    }

    public boolean isOtpRequired() {
        return otpRequired;
    }

    public void setOtpRequired(boolean otpRequired) {
        this.otpRequired = otpRequired;
    }

    public String getChallengeId() {
        return challengeId;
    }

    public void setChallengeId(String challengeId) {
        this.challengeId = challengeId;
    }

    public String getSessionToken() {
        return sessionToken;
    }

    public void setSessionToken(String sessionToken) {
        this.sessionToken = sessionToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
