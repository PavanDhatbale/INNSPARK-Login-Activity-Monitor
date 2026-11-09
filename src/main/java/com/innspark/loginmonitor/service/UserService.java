package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.dto.RegisterRequest;
import com.innspark.loginmonitor.dto.UserResponse;
import com.innspark.loginmonitor.enums.Role;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

/**
 * Service interface for user account registration and management.
 */
public interface UserService {

    /**
     * Registers a new user account with BCrypt password hashing.
     * Enforces username and email uniqueness and restricts public registration to the USER role.
     *
     * @param request the registration details
     * @return safe UserResponse without sensitive credential data
     */
    UserResponse registerUser(RegisterRequest request);

    /**
     * Retrieves the profile of the currently authenticated user based on session identity.
     *
     * @param username the username derived from the validated session
     * @return safe UserResponse without sensitive credential data
     */
    UserResponse getCurrentUserProfile(String username);

    /**
     * Retrieves a paginated list of registered users with optional username/email search.
     * Accessible to ADMIN and SUPERADMIN roles only.
     *
     * @param search   optional search keyword for username or email
     * @param pageable pagination parameters
     * @return paginated UserResponse items
     */
    Page<UserResponse> listUsers(String search, Pageable pageable);

    /**
     * Retrieves a specific user by their database ID.
     *
     * @param id the user ID
     * @return safe UserResponse
     */
    UserResponse getUserById(Long id);

    /**
     * Updates a user's role according to role hierarchy rules:
     * - USER cannot assign roles
     * - ADMIN cannot assign/revoke SUPERADMIN
     * - Users cannot modify their own role
     * - Only SUPERADMIN can grant or revoke SUPERADMIN role
     *
     * @param targetUserId  the ID of the user whose role is being changed
     * @param newRole       the new role to assign
     * @param actorUsername the username of the administrator performing the action
     * @return safe UserResponse with updated role
     */
    UserResponse updateUserRole(Long targetUserId, Role newRole, String actorUsername);

    /**
     * Enables or disables a user account according to hierarchy rules:
     * - Administrators cannot disable their own account
     * - ADMIN cannot disable SUPERADMIN accounts
     * - Disabling invalidates all active sessions for that user
     *
     * @param targetUserId  the ID of the user to enable/disable
     * @param enabled       the new enabled status
     * @param actorUsername the username of the administrator performing the action
     * @return safe UserResponse with updated status
     */
    UserResponse updateUserStatus(Long targetUserId, boolean enabled, String actorUsername);

    /**
     * Deletes a user account:
     * - SUPERADMIN only
     * - Administrators cannot delete their own account
     * - Invalidates and cleans up all active sessions before deletion
     * - Preserves login attempt and suspicious activity audit history
     *
     * @param targetUserId  the ID of the user to delete
     * @param actorUsername the username of the SUPERADMIN performing the deletion
     */
    void deleteUser(Long targetUserId, String actorUsername);
}
