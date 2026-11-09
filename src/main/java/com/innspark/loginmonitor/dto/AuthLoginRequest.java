package com.innspark.loginmonitor.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Request payload for POST /auth/login.
 */
public class AuthLoginRequest {

    @NotBlank(message = "Username is required")
    private String username;

    @NotBlank(message = "Password is required")
    private String password;

    /**
     * Optional CAPTCHA response token from client (e.g. g-recaptcha-response).
     * Enforced only when app.captcha.enabled=true.
     */
    private String captchaToken;

    public AuthLoginRequest() {
    }

    public AuthLoginRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public AuthLoginRequest(String username, String password, String captchaToken) {
        this.username = username;
        this.password = password;
        this.captchaToken = captchaToken;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getCaptchaToken() {
        return captchaToken;
    }

    public void setCaptchaToken(String captchaToken) {
        this.captchaToken = captchaToken;
    }
}
