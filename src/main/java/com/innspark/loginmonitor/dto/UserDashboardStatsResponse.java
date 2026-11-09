package com.innspark.loginmonitor.dto;

import java.time.LocalDateTime;

/**
 * Response payload containing personalized login and security metrics for the authenticated user.
 */
public class UserDashboardStatsResponse {

    private long totalLoginAttempts;
    private long successfulLogins;
    private long failedLogins;
    private long suspiciousActivities;
    private LocalDateTime lastLogin;
    private LocalDateTime lastSuccessfulLogin;

    public UserDashboardStatsResponse() {
    }

    public UserDashboardStatsResponse(long totalLoginAttempts,
                                      long successfulLogins,
                                      long failedLogins,
                                      long suspiciousActivities,
                                      LocalDateTime lastLogin,
                                      LocalDateTime lastSuccessfulLogin) {
        this.totalLoginAttempts = totalLoginAttempts;
        this.successfulLogins = successfulLogins;
        this.failedLogins = failedLogins;
        this.suspiciousActivities = suspiciousActivities;
        this.lastLogin = lastLogin;
        this.lastSuccessfulLogin = lastSuccessfulLogin;
    }

    public long getTotalLoginAttempts() {
        return totalLoginAttempts;
    }

    public void setTotalLoginAttempts(long totalLoginAttempts) {
        this.totalLoginAttempts = totalLoginAttempts;
    }

    public long getSuccessfulLogins() {
        return successfulLogins;
    }

    public void setSuccessfulLogins(long successfulLogins) {
        this.successfulLogins = successfulLogins;
    }

    public long getFailedLogins() {
        return failedLogins;
    }

    public void setFailedLogins(long failedLogins) {
        this.failedLogins = failedLogins;
    }

    public long getSuspiciousActivities() {
        return suspiciousActivities;
    }

    public void setSuspiciousActivities(long suspiciousActivities) {
        this.suspiciousActivities = suspiciousActivities;
    }

    public LocalDateTime getLastLogin() {
        return lastLogin;
    }

    public void setLastLogin(LocalDateTime lastLogin) {
        this.lastLogin = lastLogin;
    }

    public LocalDateTime getLastSuccessfulLogin() {
        return lastSuccessfulLogin;
    }

    public void setLastSuccessfulLogin(LocalDateTime lastSuccessfulLogin) {
        this.lastSuccessfulLogin = lastSuccessfulLogin;
    }
}
