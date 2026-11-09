package com.innspark.loginmonitor.service.impl;

import com.innspark.loginmonitor.dto.AdminDashboardStatsResponse;
import com.innspark.loginmonitor.dto.LoginAttemptResponse;
import com.innspark.loginmonitor.dto.PageResponse;
import com.innspark.loginmonitor.dto.SuspiciousActivityResponse;
import com.innspark.loginmonitor.dto.UserDashboardStatsResponse;
import com.innspark.loginmonitor.entity.LoginAttempt;
import com.innspark.loginmonitor.entity.SuspiciousActivity;
import com.innspark.loginmonitor.enums.LoginStatus;
import com.innspark.loginmonitor.repository.LoginAttemptRepository;
import com.innspark.loginmonitor.repository.SuspiciousActivityRepository;
import com.innspark.loginmonitor.repository.UserRepository;
import com.innspark.loginmonitor.service.DashboardService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Service implementation aggregating analytics and queries for user and administrator dashboards.
 *
 * Security & Efficiency Policies:
 * 1. User statistics and timelines are strictly bounded to the authenticated user's identity.
 * 2. Database queries use indexed fields (username, status, timestamp) to prevent full table scans.
 * 3. Page sizes are validated and bounded (max 50) to prevent denial of service through huge queries.
 */
@Service
@Transactional(readOnly = true)
public class DashboardServiceImpl implements DashboardService {

    private final LoginAttemptRepository loginAttemptRepository;
    private final SuspiciousActivityRepository suspiciousActivityRepository;
    private final UserRepository userRepository;

    public DashboardServiceImpl(LoginAttemptRepository loginAttemptRepository,
                                SuspiciousActivityRepository suspiciousActivityRepository,
                                UserRepository userRepository) {
        this.loginAttemptRepository = loginAttemptRepository;
        this.suspiciousActivityRepository = suspiciousActivityRepository;
        this.userRepository = userRepository;
    }

    @Override
    public UserDashboardStatsResponse getUserStats(String username) {
        String cleanUsername = username != null ? username.trim() : "";

        long totalAttempts = loginAttemptRepository.countByUsernameIgnoreCase(cleanUsername);
        long successLogins = loginAttemptRepository.countByUsernameIgnoreCaseAndStatus(cleanUsername, LoginStatus.SUCCESS);
        long failedLogins = loginAttemptRepository.countByUsernameIgnoreCaseAndStatus(cleanUsername, LoginStatus.FAILURE);
        long suspiciousCount = suspiciousActivityRepository.countByUsernameIgnoreCase(cleanUsername);

        Optional<LoginAttempt> lastAttempt = loginAttemptRepository.findFirstByUsernameIgnoreCaseOrderByTimestampDesc(cleanUsername);
        Optional<LoginAttempt> lastSuccess = loginAttemptRepository.findFirstByUsernameIgnoreCaseAndStatusOrderByTimestampDesc(cleanUsername, LoginStatus.SUCCESS);

        return new UserDashboardStatsResponse(
                totalAttempts,
                successLogins,
                failedLogins,
                suspiciousCount,
                lastAttempt.map(LoginAttempt::getTimestamp).orElse(null),
                lastSuccess.map(LoginAttempt::getTimestamp).orElse(null)
        );
    }

    @Override
    public PageResponse<LoginAttemptResponse> getUserLoginHistory(String username, LoginStatus status, int page, int size) {
        String cleanUsername = username != null ? username.trim() : "";
        Pageable pageable = createBoundedPageable(page, size);

        Page<LoginAttempt> attemptPage;
        if (status != null) {
            attemptPage = loginAttemptRepository.findByUsernameIgnoreCaseAndStatusOrderByTimestampDesc(cleanUsername, status, pageable);
        } else {
            attemptPage = loginAttemptRepository.findByUsernameIgnoreCaseOrderByTimestampDesc(cleanUsername, pageable);
        }

        Page<LoginAttemptResponse> mappedPage = attemptPage.map(LoginAttemptResponse::fromEntity);
        return PageResponse.of(mappedPage);
    }

    @Override
    public PageResponse<SuspiciousActivityResponse> getUserSuspiciousActivities(String username, int page, int size) {
        String cleanUsername = username != null ? username.trim() : "";
        Pageable pageable = createBoundedPageable(page, size);

        Page<SuspiciousActivity> activityPage = suspiciousActivityRepository.findByUsernameIgnoreCaseOrderByTimestampDesc(cleanUsername, pageable);
        Page<SuspiciousActivityResponse> mappedPage = activityPage.map(SuspiciousActivityResponse::fromEntity);
        return PageResponse.of(mappedPage);
    }

    @Override
    public AdminDashboardStatsResponse getAdminStats() {
        long totalUsers = userRepository.count();
        long totalAttempts = loginAttemptRepository.count();
        long successfulLogins = loginAttemptRepository.countByStatus(LoginStatus.SUCCESS);
        long failedLogins = loginAttemptRepository.countByStatus(LoginStatus.FAILURE);
        long totalSuspicious = suspiciousActivityRepository.count();

        LocalDateTime twentyFourHoursAgo = LocalDateTime.now().minusHours(24);
        long recentSuspicious = suspiciousActivityRepository.countByTimestampGreaterThanEqual(twentyFourHoursAgo);

        return new AdminDashboardStatsResponse(
                totalUsers,
                totalAttempts,
                successfulLogins,
                failedLogins,
                totalSuspicious,
                recentSuspicious
        );
    }

    private Pageable createBoundedPageable(int page, int size) {
        int boundedPage = Math.max(0, page);
        int boundedSize = Math.min(50, Math.max(1, size));
        return PageRequest.of(boundedPage, boundedSize);
    }
}
