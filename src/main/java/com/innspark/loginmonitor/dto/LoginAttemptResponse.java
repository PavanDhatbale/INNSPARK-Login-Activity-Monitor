package com.innspark.loginmonitor.dto;

import com.innspark.loginmonitor.entity.LoginAttempt;
import com.innspark.loginmonitor.enums.LoginStatus;
import java.time.LocalDateTime;

/**
 * DTO representing an individual login attempt returned in the GET /login history list.
 */
public class LoginAttemptResponse {

    private Long id;
    private String username;
    private String ipAddress;
    private LoginStatus status;
    private LocalDateTime timestamp;

    public LoginAttemptResponse() {
    }

    public LoginAttemptResponse(Long id, String username, String ipAddress, LoginStatus status, LocalDateTime timestamp) {
        this.id = id;
        this.username = username;
        this.ipAddress = ipAddress;
        this.status = status;
        this.timestamp = timestamp;
    }

    public static LoginAttemptResponse fromEntity(LoginAttempt attempt) {
        return new LoginAttemptResponse(
                attempt.getId(),
                attempt.getUsername(),
                attempt.getIpAddress(),
                attempt.getStatus(),
                attempt.getTimestamp()
        );
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
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

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}
