package com.innspark.loginmonitor.controller;

import com.innspark.loginmonitor.dto.MessageResponse;
import com.innspark.loginmonitor.dto.UpdateUserRoleRequest;
import com.innspark.loginmonitor.dto.UpdateUserStatusRequest;
import com.innspark.loginmonitor.dto.UserResponse;
import com.innspark.loginmonitor.dto.UserSessionResponse;
import com.innspark.loginmonitor.service.SessionService;
import com.innspark.loginmonitor.service.UserService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller exposing user management APIs restricted exclusively to administrators.
 *
 * Authorization:
 * - Listing and inspecting users: ADMIN and SUPERADMIN
 * - Updating roles: ADMIN and SUPERADMIN (subject to role hierarchy checks)
 * - Updating account status: ADMIN and SUPERADMIN (subject to hierarchy checks)
 * - Deleting user accounts: SUPERADMIN only
 */
@RestController
@RequestMapping("/admin/users")
@PreAuthorize("hasAnyRole('ADMIN', 'SUPERADMIN')")
public class AdminUserController {

    private final UserService userService;
    private final SessionService sessionService;

    public AdminUserController(UserService userService, SessionService sessionService) {
        this.userService = userService;
        this.sessionService = sessionService;
    }

    /**
     * GET /admin/users
     * Retrieves a paginated list of registered users with optional search filtering by username or email.
     */
    @GetMapping
    public ResponseEntity<Page<UserResponse>> listUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String search) {

        int finalPage = Math.max(page, 0);
        int finalSize = Math.max(1, Math.min(size, 100));
        Pageable pageable = PageRequest.of(finalPage, finalSize, Sort.by(Sort.Direction.DESC, "createdAt"));

        Page<UserResponse> users = userService.listUsers(search, pageable);
        return ResponseEntity.ok(users);
    }

    /**
     * GET /admin/users/{id}
     * Retrieves safe profile information for a specific user account.
     */
    @GetMapping("/{id}")
    public ResponseEntity<UserResponse> getUserById(@PathVariable Long id) {
        UserResponse user = userService.getUserById(id);
        return ResponseEntity.ok(user);
    }

    /**
     * GET /admin/users/{id}/sessions
     * Retrieves active sessions for a specific user account.
     * Allows administrators to inspect user sessions and activity timestamps.
     */
    @GetMapping("/{id}/sessions")
    public ResponseEntity<java.util.List<UserSessionResponse>> getUserSessions(@PathVariable Long id) {
        java.util.List<UserSessionResponse> sessions = sessionService.getActiveSessionsForUser(id);
        return ResponseEntity.ok(sessions);
    }

    /**
     * DELETE /admin/users/{userId}/sessions/{sessionId}
     * Revokes a specific active session belonging to the target user.
     * Accessible exclusively to ADMIN and SUPERADMIN roles.
     * The revoked session is immediately invalidated in the database and denied access to protected APIs.
     */
    @DeleteMapping("/{userId}/sessions/{sessionId}")
    public ResponseEntity<MessageResponse> revokeSession(
            @PathVariable("userId") Long userId,
            @PathVariable("sessionId") Long sessionId) {
        sessionService.revokeSession(userId, sessionId);
        return ResponseEntity.ok(new MessageResponse("Session #" + sessionId + " revoked successfully"));
    }

    /**
     * DELETE /admin/users/{userId}/sessions
     * Revokes all active sessions for a selected user.
     * Accessible exclusively to ADMIN and SUPERADMIN roles.
     * Strictly scoped to the specified user and does not terminate administrator or other user sessions.
     */
    @DeleteMapping("/{userId}/sessions")
    public ResponseEntity<MessageResponse> revokeAllSessions(@PathVariable("userId") Long userId) {
        int count = sessionService.revokeAllSessionsForUser(userId);
        return ResponseEntity.ok(new MessageResponse(count + " active session(s) revoked successfully"));
    }

    /**
     * PATCH or PUT /admin/users/{id}/role
     * Updates a user's role subject to hierarchy checks:
     * - USER cannot assign roles
     * - ADMIN cannot assign or revoke SUPERADMIN
     * - Users cannot modify their own role
     */
    @RequestMapping(value = "/{id}/role", method = {RequestMethod.PATCH, RequestMethod.PUT})
    public ResponseEntity<UserResponse> updateUserRole(
            @PathVariable Long id,
            @Valid @RequestBody UpdateUserRoleRequest request,
            Authentication authentication) {

        String actorUsername = authentication.getName();
        UserResponse updated = userService.updateUserRole(id, request.getRole(), actorUsername);
        return ResponseEntity.ok(updated);
    }

    /**
     * PATCH or PUT /admin/users/{id}/status
     * Enables or disables a user account.
     * When disabled, all active sessions belonging to the user are invalidated immediately.
     */
    @RequestMapping(value = "/{id}/status", method = {RequestMethod.PATCH, RequestMethod.PUT})
    public ResponseEntity<UserResponse> updateUserStatus(
            @PathVariable Long id,
            @Valid @RequestBody UpdateUserStatusRequest request,
            Authentication authentication) {

        String actorUsername = authentication.getName();
        UserResponse updated = userService.updateUserStatus(id, request.getEnabled(), actorUsername);
        return ResponseEntity.ok(updated);
    }

    /**
     * DELETE /admin/users/{id}
     * Permanently deletes a user account.
     * Restricted to SUPERADMIN only.
     * Cleans up session records while preserving login attempt and suspicious activity audit logs.
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('SUPERADMIN')")
    public ResponseEntity<MessageResponse> deleteUser(
            @PathVariable Long id,
            Authentication authentication) {

        String actorUsername = authentication.getName();
        userService.deleteUser(id, actorUsername);
        return ResponseEntity.ok(new MessageResponse("User deleted successfully"));
    }
}
