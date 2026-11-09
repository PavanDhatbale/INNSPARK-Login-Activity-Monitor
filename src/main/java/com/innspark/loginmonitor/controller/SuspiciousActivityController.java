package com.innspark.loginmonitor.controller;

import com.innspark.loginmonitor.dto.SuspiciousActivityResponse;
import com.innspark.loginmonitor.service.SuspiciousActivityService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Controller exposing endpoints for retrieving suspicious activity logs.
 * Restricted strictly to privileged operators (ADMIN, SUPERADMIN) per assignment RBAC requirements.
 */
@RestController
@RequestMapping("/suspicious")
@PreAuthorize("hasAnyRole('ADMIN', 'SUPERADMIN')")
public class SuspiciousActivityController {

    private final SuspiciousActivityService suspiciousActivityService;

    public SuspiciousActivityController(SuspiciousActivityService suspiciousActivityService) {
        this.suspiciousActivityService = suspiciousActivityService;
    }

    /**
     * GET /suspicious
     * Fetches all detected suspicious activities ordered by timestamp descending.
     * Returns an empty list [] if no suspicious activities have been detected.
     */
    @GetMapping
    public ResponseEntity<List<SuspiciousActivityResponse>> getSuspiciousActivities() {
        List<SuspiciousActivityResponse> activities = suspiciousActivityService.getAllSuspiciousActivities();
        return ResponseEntity.ok(activities);
    }
}
