package com.innspark.loginmonitor.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response payload containing system-wide administrative security and authentication metrics.
 * Accessible only by users holding ADMIN or SUPERADMIN roles.
 */
public class AdminDashboardStatsResponse {

    private long totalUsers;
    private long totalLoginAttempts;
    private long totalSuccessfulLogins;
    private long totalFailedLogins;
    private long totalSuspiciousActivities;
    private long recentSuspiciousActivities;

    public AdminDashboardStatsResponse() {
    }

    public AdminDashboardStatsResponse(long totalUsers,
                                       long totalLoginAttempts,
                                       long totalSuccessfulLogins,
                                       long totalFailedLogins,
                                       long totalSuspiciousActivities,
                                       long recentSuspiciousActivities) {
        this.totalUsers = totalUsers;
        this.totalLoginAttempts = totalLoginAttempts;
        this.totalSuccessfulLogins = totalSuccessfulLogins;
        this.totalFailedLogins = totalFailedLogins;
        this.totalSuspiciousActivities = totalSuspiciousActivities;
        this.recentSuspiciousActivities = recentSuspiciousActivities;
    }

    public long getTotalUsers() {
        return totalUsers;
    }

    public void setTotalUsers(long totalUsers) {
        this.totalUsers = totalUsers;
    }

    public long getTotalLoginAttempts() {
        return totalLoginAttempts;
    }

    public void setTotalLoginAttempts(long totalLoginAttempts) {
        this.totalLoginAttempts = totalLoginAttempts;
    }

    @JsonProperty("totalSuccessfulLogins")
    public long getTotalSuccessfulLogins() {
        return totalSuccessfulLogins;
    }

    public void setTotalSuccessfulLogins(long totalSuccessfulLogins) {
        this.totalSuccessfulLogins = totalSuccessfulLogins;
    }

    // Alias for compatibility
    public long getSuccessfulLogins() {
        return totalSuccessfulLogins;
    }

    @JsonProperty("totalFailedLogins")
    public long getTotalFailedLogins() {
        return totalFailedLogins;
    }

    public void setTotalFailedLogins(long totalFailedLogins) {
        this.totalFailedLogins = totalFailedLogins;
    }

    // Alias for compatibility
    public long getFailedLogins() {
        return totalFailedLogins;
    }

    public long getTotalSuspiciousActivities() {
        return totalSuspiciousActivities;
    }

    public void setTotalSuspiciousActivities(long totalSuspiciousActivities) {
        this.totalSuspiciousActivities = totalSuspiciousActivities;
    }

    public long getRecentSuspiciousActivities() {
        return recentSuspiciousActivities;
    }

    public void setRecentSuspiciousActivities(long recentSuspiciousActivities) {
        this.recentSuspiciousActivities = recentSuspiciousActivities;
    }
}
