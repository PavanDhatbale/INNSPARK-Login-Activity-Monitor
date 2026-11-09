package com.innspark.loginmonitor.controller;

import com.innspark.loginmonitor.dto.AdminDashboardStatsResponse;
import com.innspark.loginmonitor.service.DashboardService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller exposing administrative dashboard metrics for privileged operators (ADMIN, SUPERADMIN).
 * Normal USER accounts cannot access these endpoints.
 */
@RestController
@RequestMapping("/admin/dashboard")
@PreAuthorize("hasAnyRole('ADMIN', 'SUPERADMIN')")
public class AdminDashboardController {

    private final DashboardService dashboardService;

    public AdminDashboardController(DashboardService dashboardService) {
        this.dashboardService = dashboardService;
    }

    /**
     * GET /admin/dashboard/stats
     * Returns system-wide authentication and security analytics.
     */
    @GetMapping("/stats")
    public ResponseEntity<AdminDashboardStatsResponse> getAdminStats() {
        AdminDashboardStatsResponse stats = dashboardService.getAdminStats();
        return ResponseEntity.ok(stats);
    }
}
