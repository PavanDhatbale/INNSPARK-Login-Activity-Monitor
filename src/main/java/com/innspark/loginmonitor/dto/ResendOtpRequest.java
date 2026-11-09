package com.innspark.loginmonitor.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Request payload for requesting a new OTP code for an existing pending challenge (POST /auth/resend-otp).
 */
public class ResendOtpRequest {

    @NotBlank(message = "Challenge ID is required")
    private String challengeId;

    public ResendOtpRequest() {
    }

    public ResendOtpRequest(String challengeId) {
        this.challengeId = challengeId;
    }

    public String getChallengeId() {
        return challengeId;
    }

    public void setChallengeId(String challengeId) {
        this.challengeId = challengeId;
    }
}
