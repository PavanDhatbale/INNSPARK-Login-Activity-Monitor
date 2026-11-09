package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.dto.AdminDashboardStatsResponse;
import com.innspark.loginmonitor.dto.LoginAttemptResponse;
import com.innspark.loginmonitor.dto.PageResponse;
import com.innspark.loginmonitor.dto.SuspiciousActivityResponse;
import com.innspark.loginmonitor.dto.UserDashboardStatsResponse;
import com.innspark.loginmonitor.enums.LoginStatus;

/**
 * Service interface providing analytics, aggregated statistics, and paginated audit timelines
 * for user and administrator dashboards.
 */
public interface DashboardService {

    /**
     * Calculates personalized authentication statistics for the authenticated user.
     *
     * @param username the authenticated user's username
     * @return UserDashboardStatsResponse containing total, success, failure, and suspicious metrics
     */
    UserDashboardStatsResponse getUserStats(String username);

    /**
     * Retrieves paginated login attempt history for the authenticated user with optional status filter.
     *
     * @param username the authenticated user's username
     * @param status   optional filter: SUCCESS or FAILURE
     * @param page     zero-based page index
     * @param size     page size (max 50)
     * @return PageResponse of LoginAttemptResponse items, ordered newest first
     */
    PageResponse<LoginAttemptResponse> getUserLoginHistory(String username, LoginStatus status, int page, int size);

    /**
     * Retrieves paginated suspicious activity records associated with the authenticated user.
     *
     * @param username the authenticated user's username
     * @param page     zero-based page index
     * @param size     page size
     * @return PageResponse of SuspiciousActivityResponse items, ordered newest first
     */
    PageResponse<SuspiciousActivityResponse> getUserSuspiciousActivities(String username, int page, int size);

    /**
     * Calculates system-wide administrative metrics across users, attempts, and suspicious incidents.
     *
     * @return AdminDashboardStatsResponse containing global statistics
     */
    AdminDashboardStatsResponse getAdminStats();
}
