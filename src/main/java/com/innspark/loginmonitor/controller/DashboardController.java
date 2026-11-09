package com.innspark.loginmonitor.controller;

import com.innspark.loginmonitor.dto.LoginAttemptResponse;
import com.innspark.loginmonitor.dto.PageResponse;
import com.innspark.loginmonitor.dto.SuspiciousActivityResponse;
import com.innspark.loginmonitor.dto.UserDashboardStatsResponse;
import com.innspark.loginmonitor.enums.LoginStatus;
import com.innspark.loginmonitor.service.DashboardService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * Controller exposing authenticated user dashboard APIs:
 * personal login statistics, paginated login attempt history, and personal suspicious activity timeline.
 */
@RestController
@RequestMapping("/dashboard")
public class DashboardController {

    private final DashboardService dashboardService;

    public DashboardController(DashboardService dashboardService) {
        this.dashboardService = dashboardService;
    }

    /**
     * GET /dashboard/stats
     * Returns personal authentication metrics for the authenticated user.
     * Privileged operators (ADMIN, SUPERADMIN) can optionally inspect metrics for a target username.
     * Regular users attempting to query another user's metrics will receive HTTP 403 Forbidden.
     */
    @GetMapping("/stats")
    public ResponseEntity<UserDashboardStatsResponse> getUserStats(
            Principal principal,
            @RequestParam(required = false) String username) {
        if (principal == null || principal.getName() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String targetUsername = resolveTargetUsername(principal, username);
        if (targetUsername == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        UserDashboardStatsResponse stats = dashboardService.getUserStats(targetUsername);
        return ResponseEntity.ok(stats);
    }

    /**
     * GET /dashboard/login-history
     * Returns paginated login attempt history for the authenticated user with optional status filter.
     * Regular users are isolated to their own login history (HTTP 403 Forbidden if requesting another username).
     * Privileged operators (ADMIN, SUPERADMIN) may inspect any user's login history.
     */
    @GetMapping("/login-history")
    public ResponseEntity<PageResponse<LoginAttemptResponse>> getUserLoginHistory(
            Principal principal,
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        if (principal == null || principal.getName() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String targetUsername = resolveTargetUsername(principal, username);
        if (targetUsername == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        LoginStatus parsedStatus = parseStatus(status);
        PageResponse<LoginAttemptResponse> history = dashboardService.getUserLoginHistory(
                targetUsername, parsedStatus, page, size
        );
        return ResponseEntity.ok(history);
    }

    /**
     * GET /dashboard/suspicious-activities
     * Returns paginated suspicious activities associated with the authenticated user.
     * Regular users are isolated to their own timeline (HTTP 403 Forbidden if requesting another username).
     */
    @GetMapping("/suspicious-activities")
    public ResponseEntity<PageResponse<SuspiciousActivityResponse>> getUserSuspiciousActivities(
            Principal principal,
            @RequestParam(required = false) String username,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        if (principal == null || principal.getName() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String targetUsername = resolveTargetUsername(principal, username);
        if (targetUsername == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        PageResponse<SuspiciousActivityResponse> activities = dashboardService.getUserSuspiciousActivities(
                targetUsername, page, size
        );
        return ResponseEntity.ok(activities);
    }

    private String resolveTargetUsername(Principal principal, String requestedUsername) {
        if (requestedUsername != null && !requestedUsername.trim().isEmpty()) {
            if (!isPrivileged(principal) && !requestedUsername.trim().equalsIgnoreCase(principal.getName())) {
                return null; // Denied: non-privileged user cannot access another user's records
            }
            return isPrivileged(principal) ? requestedUsername.trim() : principal.getName();
        }
        return principal.getName();
    }

    private boolean isPrivileged(Principal principal) {
        if (principal instanceof Authentication auth) {
            return auth.getAuthorities().stream()
                    .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()) || "ROLE_SUPERADMIN".equals(a.getAuthority()));
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            return auth.getAuthorities().stream()
                    .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()) || "ROLE_SUPERADMIN".equals(a.getAuthority()));
        }
        return false;
    }

    private LoginStatus parseStatus(String statusStr) {
        if (statusStr == null || statusStr.trim().isEmpty()) {
            return null;
        }
        try {
            return LoginStatus.valueOf(statusStr.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid status filter '" + statusStr + "'. Allowed values: SUCCESS, FAILURE");
        }
    }
}
