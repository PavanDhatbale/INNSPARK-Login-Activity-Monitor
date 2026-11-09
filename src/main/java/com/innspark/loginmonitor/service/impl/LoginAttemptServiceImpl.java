package com.innspark.loginmonitor.service.impl;

import com.innspark.loginmonitor.dto.LoginAttemptResponse;
import com.innspark.loginmonitor.dto.LoginRequest;
import com.innspark.loginmonitor.dto.LoginResponse;
import com.innspark.loginmonitor.entity.LoginAttempt;
import com.innspark.loginmonitor.enums.LoginStatus;
import com.innspark.loginmonitor.repository.LoginAttemptRepository;
import com.innspark.loginmonitor.service.LoginAttemptService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Service implementation for managing login attempts.
 *
 * NOTE: For Phase 1, authentication is simulated as requested by the specification.
 * Passwords are NEVER persisted in the database or logged.
 * In Phase 2, this simulated check will be replaced with real BCrypt authentication.
 */
@Service
public class LoginAttemptServiceImpl implements LoginAttemptService {

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptServiceImpl.class);

    private final LoginAttemptRepository loginAttemptRepository;
    private final com.innspark.loginmonitor.service.DetectionService detectionService;

    public LoginAttemptServiceImpl(LoginAttemptRepository loginAttemptRepository,
                                  com.innspark.loginmonitor.service.DetectionService detectionService) {
        this.loginAttemptRepository = loginAttemptRepository;
        this.detectionService = detectionService;
    }

    @Override
    @Transactional
    public LoginResponse processLogin(LoginRequest request, String clientIp) {
        // Prefer IP from request payload if explicitly provided, else fallback to extracted client IP
        String finalIp = (request.getIpAddress() != null && !request.getIpAddress().trim().isEmpty())
                ? request.getIpAddress().trim()
                : (clientIp != null ? clientIp : "127.0.0.1");

        // Determine login status (using simulated authentication or explicit status if provided)
        LoginStatus status;
        if (request.getStatus() != null) {
            status = request.getStatus();
        } else {
            status = simulateAuthentication(request.getUsername(), request.getPassword())
                    ? LoginStatus.SUCCESS
                    : LoginStatus.FAILURE;
        }

        // Record the login attempt in the database
        // Security requirement: The submitted password is intentionally NOT stored.
        LoginAttempt attempt = new LoginAttempt(
                request.getUsername().trim(),
                finalIp,
                LocalDateTime.now(),
                status
        );

        LoginAttempt savedAttempt = loginAttemptRepository.save(attempt);
        log.info("Recorded login attempt id={} for user='{}' from ip='{}' with status={}",
                savedAttempt.getId(), savedAttempt.getUsername(), savedAttempt.getIpAddress(), savedAttempt.getStatus());

        // Trigger immediate suspicious activity detection
        detectionService.detectSuspiciousActivity(savedAttempt);

        String responseMessage = (status == LoginStatus.SUCCESS)
                ? "Login successful"
                : "Invalid username or password";

        return new LoginResponse(
                savedAttempt.getId(),
                savedAttempt.getUsername(),
                savedAttempt.getIpAddress(),
                savedAttempt.getStatus(),
                responseMessage,
                savedAttempt.getTimestamp()
        );
    }

    @Override
    @Transactional(readOnly = true)
    public List<LoginAttemptResponse> getLoginHistory(String username, String ipAddress, LoginStatus status) {
        String cleanUsername = (username != null && !username.trim().isEmpty()) ? username.trim() : null;
        String cleanIp = (ipAddress != null && !ipAddress.trim().isEmpty()) ? ipAddress.trim() : null;

        List<LoginAttempt> attempts = loginAttemptRepository.filterLoginAttempts(cleanUsername, cleanIp, status);

        return attempts.stream()
                .map(LoginAttemptResponse::fromEntity)
                .collect(Collectors.toList());
    }

    /**
     * Simulated authentication mechanism for Phase 1.
     * Accepted demo credentials:
     * - admin / admin123
     * - testuser / password123
     * Or any user where password equals "password123".
     *
     * This will be replaced with real BCrypt authentication in Phase 2.
     */
    private boolean simulateAuthentication(String username, String password) {
        if (username == null || password == null) {
            return false;
        }

        String trimmedUser = username.trim();

        if ("admin".equalsIgnoreCase(trimmedUser) && "admin123".equals(password)) {
            return true;
        }
        if ("testuser".equalsIgnoreCase(trimmedUser) && "password123".equals(password)) {
            return true;
        }
        return "password123".equals(password);
    }
}
