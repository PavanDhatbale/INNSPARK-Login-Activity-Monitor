package com.innspark.loginmonitor.dto;

import com.innspark.loginmonitor.enums.LoginStatus;
import jakarta.validation.constraints.NotBlank;

/**
 * Request payload for POST /login API.
 */
public class LoginRequest {

    @NotBlank(message = "Username is required")
    private String username;

    @NotBlank(message = "Password is required")
    private String password;

    /**
     * Optional client IP address provided in the payload.
     * If omitted or blank, the IP is automatically resolved from the HTTP request.
     */
    private String ipAddress;

    /**
     * Optional login status if an external system is logging pre-determined attempts.
     */
    private LoginStatus status;

    public LoginRequest() {
    }

    public LoginRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public LoginRequest(String username, String password, String ipAddress) {
        this.username = username;
        this.password = password;
        this.ipAddress = ipAddress;
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

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public LoginStatus getStatus() {
        return status;
    }

    public void setStatus(LoginStatus status) {
        this.status = status;
    }
}
