package com.innspark.loginmonitor.service.impl;

import com.innspark.loginmonitor.dto.RegisterRequest;
import com.innspark.loginmonitor.dto.UserResponse;
import com.innspark.loginmonitor.entity.User;
import com.innspark.loginmonitor.enums.Role;
import com.innspark.loginmonitor.exception.AccountDisabledException;
import com.innspark.loginmonitor.exception.UserNotFoundException;
import com.innspark.loginmonitor.repository.UserRepository;
import com.innspark.loginmonitor.service.SessionService;
import com.innspark.loginmonitor.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service implementation for managing user registration and administration.
 *
 * Security Policies:
 * 1. Passwords are encrypted exclusively with BCrypt before persistence.
 * 2. Plain-text passwords are never logged or stored.
 * 3. Public registration is restricted to the USER role; attempts to self-assign
 *    ADMIN or SUPERADMIN are rejected.
 * 4. Role Hierarchy:
 *    - Regular USER cannot assign or modify roles.
 *    - ADMIN can modify roles between USER and ADMIN, but cannot grant or revoke SUPERADMIN.
 *    - Only SUPERADMIN can grant or revoke SUPERADMIN privileges.
 *    - Users cannot modify their own role.
 *    - Admins cannot disable or delete their own accounts.
 *    - Deletion is restricted to SUPERADMIN only.
 */
@Service
public class UserServiceImpl implements UserService {

    private static final Logger log = LoggerFactory.getLogger(UserServiceImpl.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessionService;

    public UserServiceImpl(UserRepository userRepository,
                           PasswordEncoder passwordEncoder,
                           SessionService sessionService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.sessionService = sessionService;
    }

    @Override
    @Transactional
    public UserResponse registerUser(RegisterRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Registration request cannot be null");
        }

        String username = request.getUsername().trim();
        String email = request.getEmail().trim().toLowerCase();

        // 1. Enforce username uniqueness
        if (userRepository.existsByUsernameIgnoreCase(username)) {
            throw new IllegalArgumentException("Username '" + username + "' is already taken");
        }

        // 2. Enforce email uniqueness
        if (userRepository.existsByEmailIgnoreCase(email)) {
            throw new IllegalArgumentException("Email '" + email + "' is already registered");
        }

        // 3. Role Assignment Security: Reject attempts to self-register as privileged roles
        Role assignedRole = Role.USER;
        if (request.getRole() != null) {
            if (request.getRole() == Role.ADMIN || request.getRole() == Role.SUPERADMIN) {
                throw new IllegalArgumentException(
                        "Self-registration as " + request.getRole() + " is not permitted. Only USER registration is allowed."
                );
            }
            assignedRole = request.getRole();
        }

        // 4. Secure Password Hashing using BCrypt
        String hashedPassword = passwordEncoder.encode(request.getPassword());

        // 5. Build and persist user entity
        User user = new User(
                username,
                email,
                hashedPassword,
                assignedRole
        );

        User savedUser = userRepository.save(user);
        log.info("Registered new user id={} username='{}' role={}", savedUser.getId(), savedUser.getUsername(), savedUser.getRole());

        // 6. Return safe DTO without password or hash
        return UserResponse.fromEntity(savedUser);
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getCurrentUserProfile(String username) {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }

        User user = userRepository.findByUsernameIgnoreCase(username.trim())
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        if (!user.isEnabled()) {
            throw new AccountDisabledException("Account is disabled. Please contact administrator.");
        }

        return UserResponse.fromEntity(user);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<UserResponse> listUsers(String search, Pageable pageable) {
        if (search != null && !search.trim().isEmpty()) {
            String query = search.trim();
            return userRepository.findByUsernameContainingIgnoreCaseOrEmailContainingIgnoreCase(query, query, pageable)
                    .map(UserResponse::fromEntity);
        }

        return userRepository.findAll(pageable)
                .map(UserResponse::fromEntity);
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserById(Long id) {
        if (id == null) {
            throw new IllegalArgumentException("User ID cannot be null");
        }

        return userRepository.findById(id)
                .map(UserResponse::fromEntity)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + id));
    }

    @Override
    @Transactional
    public UserResponse updateUserRole(Long targetUserId, Role newRole, String actorUsername) {
        if (targetUserId == null) {
            throw new IllegalArgumentException("Target user ID cannot be null");
        }
        if (newRole == null) {
            throw new IllegalArgumentException("Role cannot be null");
        }

        User targetUser = userRepository.findById(targetUserId)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + targetUserId));

        User actor = userRepository.findByUsernameIgnoreCase(actorUsername.trim())
                .orElseThrow(() -> new UserNotFoundException("Authenticated administrator not found: " + actorUsername));

        // 1. Prevent users from modifying their own role
        if (actor.getId().equals(targetUser.getId())) {
            throw new AccessDeniedException("Users are not permitted to modify their own role");
        }

        // 2. Regular USER cannot modify any roles
        if (actor.getRole() == Role.USER) {
            throw new AccessDeniedException("Regular users are not permitted to assign or modify roles");
        }

        // 3. ADMIN cannot grant SUPERADMIN privileges
        if (newRole == Role.SUPERADMIN && actor.getRole() != Role.SUPERADMIN) {
            throw new AccessDeniedException("Only SUPERADMIN users can grant SUPERADMIN privileges");
        }

        // 4. ADMIN cannot modify existing SUPERADMIN accounts
        if (targetUser.getRole() == Role.SUPERADMIN && actor.getRole() != Role.SUPERADMIN) {
            throw new AccessDeniedException("Only SUPERADMIN users can modify roles of existing SUPERADMIN accounts");
        }

        // 5. Protect against demoting the last active SUPERADMIN
        if (targetUser.getRole() == Role.SUPERADMIN && newRole != Role.SUPERADMIN && targetUser.isEnabled()) {
            long activeSuperadminCount = userRepository.countByRoleAndEnabledTrue(Role.SUPERADMIN);
            if (activeSuperadminCount <= 1) {
                throw new IllegalStateException("Cannot demote the only remaining active SUPERADMIN account. At least one active SUPERADMIN is required.");
            }
        }

        targetUser.setRole(newRole);
        User savedUser = userRepository.save(targetUser);
        log.info("User id={} '{}' role updated to {} by actor '{}'",
                savedUser.getId(), savedUser.getUsername(), savedUser.getRole(), actor.getUsername());

        return UserResponse.fromEntity(savedUser);
    }

    @Override
    @Transactional
    public UserResponse updateUserStatus(Long targetUserId, boolean enabled, String actorUsername) {
        if (targetUserId == null) {
            throw new IllegalArgumentException("Target user ID cannot be null");
        }

        User targetUser = userRepository.findById(targetUserId)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + targetUserId));

        User actor = userRepository.findByUsernameIgnoreCase(actorUsername.trim())
                .orElseThrow(() -> new UserNotFoundException("Authenticated administrator not found: " + actorUsername));

        // 1. Prevent administrators from disabling their own account
        if (actor.getId().equals(targetUser.getId()) && !enabled) {
            throw new AccessDeniedException("Administrators are not permitted to disable their own account");
        }

        // 2. ADMIN cannot disable SUPERADMIN accounts
        if (targetUser.getRole() == Role.SUPERADMIN && actor.getRole() != Role.SUPERADMIN && !enabled) {
            throw new AccessDeniedException("ADMIN users are not permitted to disable SUPERADMIN accounts");
        }

        // 3. Prevent disabling the last active SUPERADMIN
        if (targetUser.getRole() == Role.SUPERADMIN && targetUser.isEnabled() && !enabled) {
            long activeSuperadminCount = userRepository.countByRoleAndEnabledTrue(Role.SUPERADMIN);
            if (activeSuperadminCount <= 1) {
                throw new IllegalStateException("Cannot disable the only remaining active SUPERADMIN account. At least one active SUPERADMIN is required.");
            }
        }

        targetUser.setEnabled(enabled);

        // 3. When disabling an account, invalidate all active sessions immediately
        if (!enabled) {
            sessionService.invalidateAllSessionsForUser(targetUser);
        }

        User savedUser = userRepository.save(targetUser);
        log.info("User id={} '{}' enabled status updated to {} by actor '{}'",
                savedUser.getId(), savedUser.getUsername(), savedUser.isEnabled(), actor.getUsername());

        return UserResponse.fromEntity(savedUser);
    }

    @Override
    @Transactional
    public void deleteUser(Long targetUserId, String actorUsername) {
        if (targetUserId == null) {
            throw new IllegalArgumentException("Target user ID cannot be null");
        }

        User targetUser = userRepository.findById(targetUserId)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + targetUserId));

        User actor = userRepository.findByUsernameIgnoreCase(actorUsername.trim())
                .orElseThrow(() -> new UserNotFoundException("Authenticated administrator not found: " + actorUsername));

        // 1. Only SUPERADMIN can delete user accounts
        if (actor.getRole() != Role.SUPERADMIN) {
            throw new AccessDeniedException("Only SUPERADMIN users can delete user accounts");
        }

        // 2. Prevent deleting own account
        if (actor.getId().equals(targetUser.getId())) {
            throw new AccessDeniedException("Administrators are not permitted to delete their own account");
        }

        // 3. Prevent deleting the last active SUPERADMIN
        if (targetUser.getRole() == Role.SUPERADMIN && targetUser.isEnabled()) {
            long activeSuperadminCount = userRepository.countByRoleAndEnabledTrue(Role.SUPERADMIN);
            if (activeSuperadminCount <= 1) {
                throw new IllegalStateException("Cannot delete the only remaining active SUPERADMIN account. At least one active SUPERADMIN is required.");
            }
        }

        // 4. Clean up user_sessions FK records before deleting the user
        // Note: login_attempts and suspicious_activity records store username as a String
        // and do not have an FK constraint, preserving full monitoring history.
        sessionService.deleteAllSessionsForUser(targetUser);

        userRepository.delete(targetUser);
        log.info("User id={} username='{}' deleted by SUPERADMIN '{}'",
                targetUserId, targetUser.getUsername(), actor.getUsername());
    }
}
