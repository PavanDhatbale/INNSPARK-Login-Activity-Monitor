package com.innspark.loginmonitor.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * DTO mapping the verification response payload returned by CAPTCHA providers (e.g. Google reCAPTCHA).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CaptchaVerifyResponse {

    private boolean success;

    @JsonProperty("challenge_ts")
    private String challengeTs;

    private String hostname;

    private Double score;

    private String action;

    @JsonProperty("error-codes")
    private List<String> errorCodes;

    public CaptchaVerifyResponse() {
    }

    public CaptchaVerifyResponse(boolean success) {
        this.success = success;
    }

    public CaptchaVerifyResponse(boolean success, Double score) {
        this.success = success;
        this.score = score;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getChallengeTs() {
        return challengeTs;
    }

    public void setChallengeTs(String challengeTs) {
        this.challengeTs = challengeTs;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public Double getScore() {
        return score;
    }

    public void setScore(Double score) {
        this.score = score;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public List<String> getErrorCodes() {
        return errorCodes;
    }

    public void setErrorCodes(List<String> errorCodes) {
        this.errorCodes = errorCodes;
    }
}
