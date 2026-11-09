package com.innspark.loginmonitor.dto;

import java.time.LocalDateTime;

/**
 * Response payload returned upon successful OTP resend (POST /auth/resend-otp).
 */
public class ResendOtpResponse {

    private String challengeId;
    private LocalDateTime expiresAt;
    private String message;

    public ResendOtpResponse() {
    }

    public ResendOtpResponse(String challengeId, LocalDateTime expiresAt, String message) {
        this.challengeId = challengeId;
        this.expiresAt = expiresAt;
        this.message = message;
    }

    public String getChallengeId() {
        return challengeId;
    }

    public void setChallengeId(String challengeId) {
        this.challengeId = challengeId;
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
