package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.dto.UserSessionResponse;
import com.innspark.loginmonitor.entity.User;
import com.innspark.loginmonitor.entity.UserSession;

import java.util.List;
import java.util.Optional;

/**
 * Service interface for managing user session lifecycles, activity tracking, and expiration.
 */
public interface SessionService {

    /**
     * Creates and persists a new active session with a secure random token for an authenticated user.
     */
    UserSession createSession(User user);

    /**
     * Validates a session token, checks for expiration/inactivity, updates last activity timestamp,
     * and returns the active session.
     */
    Optional<UserSession> validateAndRefreshSession(String sessionToken);

    /**
     * Invalidates a session (logout).
     */
    void invalidateSession(String sessionToken);

    /**
     * Periodic scheduled task to mark stale expired sessions in the database.
     */
    void cleanExpiredSessions();

    /**
     * Retrieves active unexpired sessions for a specific user.
     * Restricted to administrators.
     */
    List<UserSessionResponse> getActiveSessionsForUser(Long userId);

    /**
     * Invalidates all active sessions for a specific user (used when an account is disabled).
     */
    void invalidateAllSessionsForUser(User user);

    /**
     * Deletes all session records for a specific user (used prior to user account deletion).
     */
    void deleteAllSessionsForUser(User user);

    /**
     * Revokes a specific active session belonging to a user by session ID.
     * The revoked session is immediately invalidated.
     */
    void revokeSession(Long userId, Long sessionId);

    /**
     * Revokes a specific active session by session ID directly.
     */
    void revokeSessionById(Long sessionId);

    /**
     * Revokes all active sessions for a specific user ID.
     * Strictly scoped to the specified user without terminating administrator sessions.
     *
     * @param userId the ID of the user whose sessions will be revoked
     * @return count of sessions revoked
     */
    int revokeAllSessionsForUser(Long userId);
}
