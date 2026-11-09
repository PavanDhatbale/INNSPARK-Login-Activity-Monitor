package com.innspark.loginmonitor.controller;

import com.innspark.loginmonitor.dto.MessageResponse;
import com.innspark.loginmonitor.service.SessionService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller exposing active session revocation APIs restricted exclusively to administrators.
 * Supports direct session revocation by session ID.
 */
@RestController
@RequestMapping("/admin/sessions")
@PreAuthorize("hasAnyRole('ADMIN', 'SUPERADMIN')")
public class AdminSessionController {

    private final SessionService sessionService;

    public AdminSessionController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    /**
     * DELETE /admin/sessions/{sessionId}
     * Revokes a specific active session by its ID.
     * Accessible exclusively to ADMIN and SUPERADMIN roles.
     */
    @DeleteMapping("/{sessionId}")
    public ResponseEntity<MessageResponse> revokeSession(@PathVariable("sessionId") Long sessionId) {
        sessionService.revokeSessionById(sessionId);
        return ResponseEntity.ok(new MessageResponse("Session #" + sessionId + " revoked successfully"));
    }
}
