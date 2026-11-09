package com.innspark.loginmonitor.service;

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
import com.innspark.loginmonitor.service.impl.DashboardServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DashboardServiceTest {

    @Mock
    private LoginAttemptRepository loginAttemptRepository;

    @Mock
    private SuspiciousActivityRepository suspiciousActivityRepository;

    @Mock
    private UserRepository userRepository;

    private DashboardServiceImpl dashboardService;

    @BeforeEach
    void setUp() {
        dashboardService = new DashboardServiceImpl(loginAttemptRepository, suspiciousActivityRepository, userRepository);
    }

    @Test
    @DisplayName("getUserStats calculates correct user statistics and last timestamps")
    void getUserStats_Success() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime earlier = now.minusHours(2);

        when(loginAttemptRepository.countByUsernameIgnoreCase("alice")).thenReturn(10L);
        when(loginAttemptRepository.countByUsernameIgnoreCaseAndStatus("alice", LoginStatus.SUCCESS)).thenReturn(7L);
        when(loginAttemptRepository.countByUsernameIgnoreCaseAndStatus("alice", LoginStatus.FAILURE)).thenReturn(3L);
        when(suspiciousActivityRepository.countByUsernameIgnoreCase("alice")).thenReturn(2L);

        LoginAttempt lastAttempt = new LoginAttempt("alice", "192.168.1.1", now, LoginStatus.FAILURE);
        LoginAttempt lastSuccess = new LoginAttempt("alice", "192.168.1.2", earlier, LoginStatus.SUCCESS);

        when(loginAttemptRepository.findFirstByUsernameIgnoreCaseOrderByTimestampDesc("alice"))
                .thenReturn(Optional.of(lastAttempt));
        when(loginAttemptRepository.findFirstByUsernameIgnoreCaseAndStatusOrderByTimestampDesc("alice", LoginStatus.SUCCESS))
                .thenReturn(Optional.of(lastSuccess));

        UserDashboardStatsResponse stats = dashboardService.getUserStats("alice");

        assertNotNull(stats);
        assertEquals(10L, stats.getTotalLoginAttempts());
        assertEquals(7L, stats.getSuccessfulLogins());
        assertEquals(3L, stats.getFailedLogins());
        assertEquals(2L, stats.getSuspiciousActivities());
        assertEquals(now, stats.getLastLogin());
        assertEquals(earlier, stats.getLastSuccessfulLogin());
    }

    @Test
    @DisplayName("getUserStats handles user with zero activity gracefully")
    void getUserStats_ZeroActivity() {
        when(loginAttemptRepository.countByUsernameIgnoreCase("newuser")).thenReturn(0L);
        when(loginAttemptRepository.countByUsernameIgnoreCaseAndStatus("newuser", LoginStatus.SUCCESS)).thenReturn(0L);
        when(loginAttemptRepository.countByUsernameIgnoreCaseAndStatus("newuser", LoginStatus.FAILURE)).thenReturn(0L);
        when(suspiciousActivityRepository.countByUsernameIgnoreCase("newuser")).thenReturn(0L);

        when(loginAttemptRepository.findFirstByUsernameIgnoreCaseOrderByTimestampDesc("newuser"))
                .thenReturn(Optional.empty());
        when(loginAttemptRepository.findFirstByUsernameIgnoreCaseAndStatusOrderByTimestampDesc("newuser", LoginStatus.SUCCESS))
                .thenReturn(Optional.empty());

        UserDashboardStatsResponse stats = dashboardService.getUserStats("newuser");

        assertNotNull(stats);
        assertEquals(0L, stats.getTotalLoginAttempts());
        assertEquals(0L, stats.getSuccessfulLogins());
        assertEquals(0L, stats.getFailedLogins());
        assertEquals(0L, stats.getSuspiciousActivities());
        assertNull(stats.getLastLogin());
        assertNull(stats.getLastSuccessfulLogin());
    }

    @Test
    @DisplayName("getUserLoginHistory without status filter returns all paginated attempts")
    void getUserLoginHistory_All() {
        LoginAttempt attempt1 = new LoginAttempt("alice", "10.0.0.1", LocalDateTime.now(), LoginStatus.SUCCESS);
        attempt1.setId(1L);
        Page<LoginAttempt> page = new PageImpl<>(List.of(attempt1));

        when(loginAttemptRepository.findByUsernameIgnoreCaseOrderByTimestampDesc(eq("alice"), any(Pageable.class)))
                .thenReturn(page);

        PageResponse<LoginAttemptResponse> response = dashboardService.getUserLoginHistory("alice", null, 0, 10);

        assertNotNull(response);
        assertEquals(1, response.getContent().size());
        assertEquals("alice", response.getContent().get(0).getUsername());
        assertEquals(LoginStatus.SUCCESS, response.getContent().get(0).getStatus());
        assertEquals(1L, response.getTotalElements());
    }

    @Test
    @DisplayName("getUserLoginHistory with status filter queries filtered attempts")
    void getUserLoginHistory_WithFilter() {
        LoginAttempt attempt = new LoginAttempt("alice", "10.0.0.1", LocalDateTime.now(), LoginStatus.FAILURE);
        attempt.setId(2L);
        Page<LoginAttempt> page = new PageImpl<>(List.of(attempt));

        when(loginAttemptRepository.findByUsernameIgnoreCaseAndStatusOrderByTimestampDesc(eq("alice"), eq(LoginStatus.FAILURE), any(Pageable.class)))
                .thenReturn(page);

        PageResponse<LoginAttemptResponse> response = dashboardService.getUserLoginHistory("alice", LoginStatus.FAILURE, 0, 10);

        assertNotNull(response);
        assertEquals(1, response.getContent().size());
        assertEquals(LoginStatus.FAILURE, response.getContent().get(0).getStatus());
    }

    @Test
    @DisplayName("getUserSuspiciousActivities returns paginated user timeline records with severity")
    void getUserSuspiciousActivities_Success() {
        SuspiciousActivity activity = new SuspiciousActivity("192.168.1.10", "alice", "Multiple failed login attempts from the same IP within 10 minutes");
        activity.setId(5L);
        Page<SuspiciousActivity> page = new PageImpl<>(List.of(activity));

        when(suspiciousActivityRepository.findByUsernameIgnoreCaseOrderByTimestampDesc(eq("alice"), any(Pageable.class)))
                .thenReturn(page);

        PageResponse<SuspiciousActivityResponse> response = dashboardService.getUserSuspiciousActivities("alice", 0, 10);

        assertNotNull(response);
        assertEquals(1, response.getContent().size());
        assertEquals("alice", response.getContent().get(0).getUsername());
        assertEquals("HIGH", response.getContent().get(0).getSeverity());
        assertEquals(5L, response.getContent().get(0).getId());
    }

    @Test
    @DisplayName("getAdminStats aggregates system-wide statistics correctly")
    void getAdminStats_Success() {
        when(userRepository.count()).thenReturn(50L);
        when(loginAttemptRepository.count()).thenReturn(500L);
        when(loginAttemptRepository.countByStatus(LoginStatus.SUCCESS)).thenReturn(400L);
        when(loginAttemptRepository.countByStatus(LoginStatus.FAILURE)).thenReturn(100L);
        when(suspiciousActivityRepository.count()).thenReturn(15L);
        when(suspiciousActivityRepository.countByTimestampGreaterThanEqual(any(LocalDateTime.class))).thenReturn(4L);

        AdminDashboardStatsResponse response = dashboardService.getAdminStats();

        assertNotNull(response);
        assertEquals(50L, response.getTotalUsers());
        assertEquals(500L, response.getTotalLoginAttempts());
        assertEquals(400L, response.getSuccessfulLogins());
        assertEquals(100L, response.getFailedLogins());
        assertEquals(15L, response.getTotalSuspiciousActivities());
        assertEquals(4L, response.getRecentSuspiciousActivities());
    }
}
