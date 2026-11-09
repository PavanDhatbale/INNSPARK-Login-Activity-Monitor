package com.innspark.loginmonitor.service.impl;

import com.innspark.loginmonitor.dto.UserSessionResponse;
import com.innspark.loginmonitor.entity.User;
import com.innspark.loginmonitor.entity.UserSession;
import com.innspark.loginmonitor.exception.SessionNotFoundException;
import com.innspark.loginmonitor.exception.UserNotFoundException;
import com.innspark.loginmonitor.repository.UserRepository;
import com.innspark.loginmonitor.repository.UserSessionRepository;
import com.innspark.loginmonitor.service.SessionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Service implementation managing database-backed user sessions.
 *
 * Enforces:
 * 1. Cryptographically secure unpredictable session tokens.
 * 2. Sliding window inactivity timeout (default: 15 minutes).
 * 3. Session invalidation on logout.
 */
@Service
public class SessionServiceImpl implements SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionServiceImpl.class);

    private final UserSessionRepository userSessionRepository;
    private final UserRepository userRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${app.session.timeout-minutes:15}")
    private int sessionTimeoutMinutes;

    public SessionServiceImpl(UserSessionRepository userSessionRepository, UserRepository userRepository) {
        this.userSessionRepository = userSessionRepository;
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public UserSession createSession(User user) {
        String rawToken = generateSecureToken();
        String tokenHash = hashToken(rawToken);
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiresAt = now.plusMinutes(sessionTimeoutMinutes);

        // Persist SHA-256 hash in MySQL, retain rawToken transiently in memory for caller response
        UserSession session = new UserSession(user, tokenHash, now, now, expiresAt);
        session.setRawToken(rawToken);
        UserSession saved = userSessionRepository.save(session);
        saved.setRawToken(rawToken);

        log.info("Created session id={} for user='{}', expires at {}", saved.getId(), user.getUsername(), expiresAt);
        return saved;
    }

    @Override
    @Transactional
    public Optional<UserSession> validateAndRefreshSession(String sessionToken) {
        if (sessionToken == null || sessionToken.trim().isEmpty()) {
            return Optional.empty();
        }

        String raw = sessionToken.trim();
        String tokenHash = hashToken(raw);

        // Look up by SHA-256 hash first; fallback to raw token for backward compatibility
        Optional<UserSession> optionalSession = userSessionRepository.findBySessionToken(tokenHash);
        if (optionalSession.isEmpty()) {
            optionalSession = userSessionRepository.findBySessionToken(raw);
        }

        if (optionalSession.isEmpty()) {
            return Optional.empty();
        }

        UserSession session = optionalSession.get();
        LocalDateTime now = LocalDateTime.now();

        // Check active flag and inactivity expiration
        boolean isInactive = session.getLastActivityAt() != null
                && session.getLastActivityAt().plusMinutes(sessionTimeoutMinutes).isBefore(now);

        if (!session.isActive() || now.isAfter(session.getExpiresAt()) || isInactive) {
            if (session.isActive()) {
                session.setActive(false);
                userSessionRepository.save(session);
                log.info("Session id={} for user='{}' marked expired due to inactivity", session.getId(), session.getUser().getUsername());
            }
            return Optional.empty();
        }

        // Slide the expiration window and update last activity on active authenticated request
        session.setLastActivityAt(now);
        session.setExpiresAt(now.plusMinutes(sessionTimeoutMinutes));
        userSessionRepository.save(session);

        return Optional.of(session);
    }

    @Override
    @Transactional
    public void invalidateSession(String sessionToken) {
        if (sessionToken == null || sessionToken.trim().isEmpty()) {
            return;
        }

        String raw = sessionToken.trim();
        String tokenHash = hashToken(raw);

        Optional<UserSession> optionalSession = userSessionRepository.findBySessionToken(tokenHash);
        if (optionalSession.isEmpty()) {
            optionalSession = userSessionRepository.findBySessionToken(raw);
        }

        optionalSession.ifPresent(session -> {
            session.setActive(false);
            userSessionRepository.save(session);
            log.info("Session id={} invalidated (logged out)", session.getId());
        });
    }

    @Override
    @Scheduled(fixedDelayString = "${app.session.cleanup-interval-seconds:60}000", initialDelay = 10000)
    @Transactional
    public void cleanExpiredSessions() {
        try {
            int invalidatedCount = userSessionRepository.invalidateExpiredSessions(LocalDateTime.now());
            if (invalidatedCount > 0) {
                log.info("Scheduled cleanup: invalidated {} expired sessions", invalidatedCount);
            }
        } catch (Exception e) {
            log.error("Error during scheduled session cleanup: {}", e.getMessage(), e);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserSessionResponse> getActiveSessionsForUser(Long userId) {
        if (userId == null) {
            return List.of();
        }
        LocalDateTime now = LocalDateTime.now();
        List<UserSession> activeSessions = userSessionRepository.findActiveSessionsByUserId(userId, now);
        return activeSessions.stream()
                .map(UserSessionResponse::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public void invalidateAllSessionsForUser(User user) {
        if (user != null) {
            int count = userSessionRepository.invalidateAllUserSessions(user);
            log.info("Invalidated {} active sessions for user id={}", count, user.getId());
        }
    }

    @Override
    @Transactional
    public void deleteAllSessionsForUser(User user) {
        if (user != null) {
            int count = userSessionRepository.deleteAllByUser(user);
            log.info("Deleted {} session records for user id={}", count, user.getId());
        }
    }

    @Override
    @Transactional
    public void revokeSession(Long userId, Long sessionId) {
        if (userId == null || sessionId == null) {
            throw new IllegalArgumentException("User ID and Session ID must not be null");
        }

        userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));

        UserSession session = userSessionRepository.findById(sessionId)
                .orElseThrow(() -> new SessionNotFoundException("Session with ID " + sessionId + " not found"));

        if (!session.getUser().getId().equals(userId)) {
            throw new IllegalArgumentException("Session ID " + sessionId + " does not belong to user ID " + userId);
        }

        // Direct DB update ensures immediate MySQL persistence
        userSessionRepository.invalidateSessionByIdAndUserId(sessionId, userId);

        // Also update loaded entity and flush
        session.setActive(false);
        userSessionRepository.saveAndFlush(session);
        log.info("Administrator revoked active session id={} for user id={}", sessionId, userId);
    }

    @Override
    @Transactional
    public void revokeSessionById(Long sessionId) {
        if (sessionId == null) {
            throw new IllegalArgumentException("Session ID must not be null");
        }

        UserSession session = userSessionRepository.findById(sessionId)
                .orElseThrow(() -> new SessionNotFoundException("Session with ID " + sessionId + " not found"));

        userSessionRepository.invalidateSessionById(sessionId);

        session.setActive(false);
        userSessionRepository.saveAndFlush(session);
        log.info("Administrator revoked active session id={}", sessionId);
    }

    @Override
    @Transactional
    public int revokeAllSessionsForUser(Long userId) {
        if (userId == null) {
            throw new IllegalArgumentException("User ID must not be null");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));

        int count = userSessionRepository.invalidateAllUserSessions(user);
        log.info("Administrator revoked {} active sessions for user id={} ({})", count, userId, user.getUsername());
        return count;
    }

    /**
     * Generates a 48-byte cryptographically secure random session token encoded in URL-safe Base64 (64 characters).
     */
    private String generateSecureToken() {
        byte[] randomBytes = new byte[48];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Computes the deterministic SHA-256 cryptographic hash of a raw session token.
     * Stored in the database to prevent token leakage in the event of database access.
     */
    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
