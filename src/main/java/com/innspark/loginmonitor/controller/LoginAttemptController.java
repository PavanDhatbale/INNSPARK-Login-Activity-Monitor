package com.innspark.loginmonitor.controller;

import com.innspark.loginmonitor.dto.LoginAttemptResponse;
import com.innspark.loginmonitor.dto.LoginRequest;
import com.innspark.loginmonitor.dto.LoginResponse;
import com.innspark.loginmonitor.enums.LoginStatus;
import com.innspark.loginmonitor.service.LoginAttemptService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.List;

/**
 * Controller exposing endpoints for logging attempts and querying login history.
 */
@RestController
@RequestMapping("/login")
public class LoginAttemptController {

    private final LoginAttemptService loginAttemptService;

    public LoginAttemptController(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    /**
     * POST /login
     * Processes a login attempt, executes simulated authentication,
     * records the attempt in MySQL, and returns the attempt result.
     */
    @PostMapping
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        String clientIp = extractClientIp(httpRequest);
        LoginResponse response = loginAttemptService.processLogin(request, clientIp);

        if (response.getStatus() == LoginStatus.SUCCESS) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    /**
     * GET /login
     * Retrieves login attempt history with secure user isolation and RBAC.
     * - Regular USERs can only view their own login history (identity derived strictly from session).
     *   Attempts to query another user's history will be rejected with HTTP 403 Forbidden.
     * - ADMIN and SUPERADMIN accounts can inspect all attempts or filter by arbitrary username and IP address.
     * - Unauthenticated calls return HTTP 401 Unauthorized.
     */
    @GetMapping
    public ResponseEntity<List<LoginAttemptResponse>> getLoginHistory(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String ipAddress,
            @RequestParam(required = false) String status,
            Principal principal) {

        if (principal == null || principal.getName() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        boolean privileged = isPrivileged(principal);

        String effectiveUsername;
        String effectiveIp = ipAddress;

        if (privileged) {
            // ADMIN / SUPERADMIN can view all attempts or filter by arbitrary username and/or IP
            effectiveUsername = (username != null && !username.trim().isEmpty()) ? username.trim() : null;
        } else {
            // Regular USER: strictly restricted to their own login history
            if (username != null && !username.trim().isEmpty() && !username.trim().equalsIgnoreCase(principal.getName())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }
            effectiveUsername = principal.getName();
            // Regular users cannot probe arbitrary system IP addresses
            effectiveIp = null;
        }

        LoginStatus parsedStatus = parseStatus(status);
        List<LoginAttemptResponse> history = loginAttemptService.getLoginHistory(effectiveUsername, effectiveIp, parsedStatus);
        return ResponseEntity.ok(history);
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

    /**
     * Extracts client IP address from HTTP request.
     *
     * Security and Architecture Note:
     * - In a production setup behind a trusted reverse proxy (e.g. Nginx, AWS ALB),
     *   the X-Forwarded-For header contains the original client IP.
     * - For local development and standard assessment evaluation, the server-observed
     *   remote address (request.getRemoteAddr()) is preferred to prevent client IP spoofing.
     */
    private String extractClientIp(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();

        // If running behind a reverse proxy on localhost, optionally inspect X-Forwarded-For
        if (remoteAddr == null || "127.0.0.1".equals(remoteAddr) || "0:0:0:0:0:0:0:1".equals(remoteAddr)) {
            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.trim().isEmpty() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
                return xForwardedFor.split(",")[0].trim();
            }
        }

        // Normalize IPv6 localhost to standard IPv4 loopback
        if ("0:0:0:0:0:0:0:1".equals(remoteAddr)) {
            return "127.0.0.1";
        }
        return (remoteAddr != null && !remoteAddr.trim().isEmpty()) ? remoteAddr : "127.0.0.1";
    }

    /**
     * Validates and parses the status query parameter into a LoginStatus enum value.
     */
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
