package com.innspark.loginmonitor.dto;

import com.innspark.loginmonitor.entity.UserSession;
import java.time.LocalDateTime;

/**
 * Safe DTO for exposing user session telemetry to administrators.
 * Sensitive fields (session token, token hash) are strictly omitted.
 */
public class UserSessionResponse {

    private Long id;
    private Long userId;
    private String username;
    private LocalDateTime createdAt;
    private LocalDateTime lastActivityAt;
    private LocalDateTime expiresAt;
    private boolean active;

    public UserSessionResponse() {
    }

    public UserSessionResponse(Long id, Long userId, String username, LocalDateTime createdAt,
                               LocalDateTime lastActivityAt, LocalDateTime expiresAt, boolean active) {
        this.id = id;
        this.userId = userId;
        this.username = username;
        this.createdAt = createdAt;
        this.lastActivityAt = lastActivityAt;
        this.expiresAt = expiresAt;
        this.active = active;
    }

    public static UserSessionResponse fromEntity(UserSession session) {
        if (session == null) {
            return null;
        }
        Long uId = session.getUser() != null ? session.getUser().getId() : null;
        String uName = session.getUser() != null ? session.getUser().getUsername() : null;
        return new UserSessionResponse(
                session.getId(),
                uId,
                uName,
                session.getCreatedAt(),
                session.getLastActivityAt(),
                session.getExpiresAt(),
                session.isValid()
        );
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getLastActivityAt() {
        return lastActivityAt;
    }

    public void setLastActivityAt(LocalDateTime lastActivityAt) {
        this.lastActivityAt = lastActivityAt;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }
}
