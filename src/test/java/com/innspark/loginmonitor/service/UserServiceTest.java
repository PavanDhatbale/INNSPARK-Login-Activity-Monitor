package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.dto.RegisterRequest;
import com.innspark.loginmonitor.dto.UserResponse;
import com.innspark.loginmonitor.entity.User;
import com.innspark.loginmonitor.enums.Role;
import com.innspark.loginmonitor.exception.AccountDisabledException;
import com.innspark.loginmonitor.exception.UserNotFoundException;
import com.innspark.loginmonitor.repository.UserRepository;
import com.innspark.loginmonitor.service.impl.UserServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private SessionService sessionService;

    @InjectMocks
    private UserServiceImpl userService;

    private PasswordEncoder realBCryptEncoder;

    @BeforeEach
    void setUp() {
        realBCryptEncoder = new BCryptPasswordEncoder();
    }

    @Test
    @DisplayName("Should successfully register a new user with BCrypt-hashed password and default USER role")
    void registerUser_Success() {
        RegisterRequest request = new RegisterRequest("newuser", "newuser@example.com", "secret123");

        when(userRepository.existsByUsernameIgnoreCase("newuser")).thenReturn(false);
        when(userRepository.existsByEmailIgnoreCase("newuser@example.com")).thenReturn(false);
        when(passwordEncoder.encode("secret123")).thenReturn(realBCryptEncoder.encode("secret123"));

        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User u = invocation.getArgument(0);
            u.setId(1L);
            return u;
        });

        UserResponse response = userService.registerUser(request);

        assertNotNull(response);
        assertEquals(1L, response.getId());
        assertEquals("newuser", response.getUsername());
        assertEquals("newuser@example.com", response.getEmail());
        assertEquals(Role.USER, response.getRole());
        assertTrue(response.isEnabled());

        // Verify entity persisted in repository
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository, times(1)).save(captor.capture());
        User saved = captor.getValue();

        // Plain text password must NEVER be saved
        assertNotEquals("secret123", saved.getPassword());
        assertTrue(saved.getPassword().startsWith("$2a$") || saved.getPassword().startsWith("$2b$"));
        assertTrue(realBCryptEncoder.matches("secret123", saved.getPassword()));
        assertEquals(Role.USER, saved.getRole());
    }

    @Test
    @DisplayName("Should reject registration if username already exists")
    void registerUser_DuplicateUsername() {
        RegisterRequest request = new RegisterRequest("existinguser", "unique@example.com", "secret123");

        when(userRepository.existsByUsernameIgnoreCase("existinguser")).thenReturn(true);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> userService.registerUser(request));
        assertTrue(ex.getMessage().contains("already taken"));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should reject registration if email already exists")
    void registerUser_DuplicateEmail() {
        RegisterRequest request = new RegisterRequest("uniqueuser", "existing@example.com", "secret123");

        when(userRepository.existsByUsernameIgnoreCase("uniqueuser")).thenReturn(false);
        when(userRepository.existsByEmailIgnoreCase("existing@example.com")).thenReturn(true);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> userService.registerUser(request));
        assertTrue(ex.getMessage().contains("already registered"));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should reject public registration attempting to assign ADMIN role")
    void registerUser_RejectAdminSelfAssignment() {
        RegisterRequest request = new RegisterRequest("hacker", "hacker@example.com", "secret123", Role.ADMIN);

        when(userRepository.existsByUsernameIgnoreCase("hacker")).thenReturn(false);
        when(userRepository.existsByEmailIgnoreCase("hacker@example.com")).thenReturn(false);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> userService.registerUser(request));
        assertTrue(ex.getMessage().contains("Only USER registration is allowed"));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should reject public registration attempting to assign SUPERADMIN role")
    void registerUser_RejectSuperadminSelfAssignment() {
        RegisterRequest request = new RegisterRequest("hacker2", "hacker2@example.com", "secret123", Role.SUPERADMIN);

        when(userRepository.existsByUsernameIgnoreCase("hacker2")).thenReturn(false);
        when(userRepository.existsByEmailIgnoreCase("hacker2@example.com")).thenReturn(false);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> userService.registerUser(request));
        assertTrue(ex.getMessage().contains("Only USER registration is allowed"));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("UserResponse does not expose password or password hash")
    void userResponse_DoesNotContainPassword() {
        User user = new User("secureUser", "secure@example.com", "$2a$10$hashedvalue", Role.USER);
        user.setId(5L);

        UserResponse response = UserResponse.fromEntity(user);

        assertEquals("secureUser", response.getUsername());
        assertEquals("secure@example.com", response.getEmail());
        assertEquals(Role.USER, response.getRole());
        // Verify UserResponse class has no getPassword method by checking fields
        boolean hasPasswordField = false;
        for (java.lang.reflect.Field field : UserResponse.class.getDeclaredFields()) {
            if (field.getName().toLowerCase().contains("password")) {
                hasPasswordField = true;
                break;
            }
        }
        assertFalse(hasPasswordField, "UserResponse must NEVER contain a password field");
    }

    // --- Profile Tests (getCurrentUserProfile) ---

    @Test
    @DisplayName("Should return user profile for valid active user")
    void getCurrentUserProfile_Success() {
        User user = new User("alice", "alice@example.com", "hash", Role.USER);
        user.setId(10L);
        when(userRepository.findByUsernameIgnoreCase("alice")).thenReturn(Optional.of(user));

        UserResponse response = userService.getCurrentUserProfile("alice");

        assertNotNull(response);
        assertEquals(10L, response.getId());
        assertEquals("alice", response.getUsername());
    }

    @Test
    @DisplayName("Should throw UserNotFoundException when looking up nonexistent username")
    void getCurrentUserProfile_NotFound() {
        when(userRepository.findByUsernameIgnoreCase("ghost")).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> userService.getCurrentUserProfile("ghost"));
    }

    @Test
    @DisplayName("Should throw AccountDisabledException when looking up disabled user profile")
    void getCurrentUserProfile_Disabled() {
        User user = new User("disabled_alice", "alice@example.com", "hash", Role.USER, false);
        when(userRepository.findByUsernameIgnoreCase("disabled_alice")).thenReturn(Optional.of(user));

        assertThrows(AccountDisabledException.class, () -> userService.getCurrentUserProfile("disabled_alice"));
    }

    // --- List Users Tests ---

    @Test
    @DisplayName("Should list users without search using pagination")
    void listUsers_WithoutSearch() {
        Pageable pageable = PageRequest.of(0, 10);
        User u1 = new User("u1", "u1@example.com", "h1", Role.USER);
        u1.setId(1L);
        Page<User> page = new PageImpl<>(List.of(u1));

        when(userRepository.findAll(pageable)).thenReturn(page);

        Page<UserResponse> result = userService.listUsers(null, pageable);

        assertEquals(1, result.getTotalElements());
        assertEquals("u1", result.getContent().get(0).getUsername());
    }

    @Test
    @DisplayName("Should list users with search query matching username or email")
    void listUsers_WithSearch() {
        Pageable pageable = PageRequest.of(0, 10);
        User u1 = new User("searchTarget", "target@example.com", "h1", Role.USER);
        u1.setId(2L);
        Page<User> page = new PageImpl<>(List.of(u1));

        when(userRepository.findByUsernameContainingIgnoreCaseOrEmailContainingIgnoreCase("target", "target", pageable))
                .thenReturn(page);

        Page<UserResponse> result = userService.listUsers("target", pageable);

        assertEquals(1, result.getTotalElements());
        assertEquals("searchTarget", result.getContent().get(0).getUsername());
    }

    // --- Get User By ID Tests ---

    @Test
    @DisplayName("Should return user by ID")
    void getUserById_Success() {
        User u = new User("test", "test@example.com", "h", Role.USER);
        u.setId(5L);
        when(userRepository.findById(5L)).thenReturn(Optional.of(u));

        UserResponse res = userService.getUserById(5L);

        assertEquals(5L, res.getId());
        assertEquals("test", res.getUsername());
    }

    @Test
    @DisplayName("Should throw UserNotFoundException when ID does not exist")
    void getUserById_NotFound() {
        when(userRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> userService.getUserById(999L));
    }

    // --- Role Update & Hierarchy Tests ---

    @Test
    @DisplayName("ADMIN promoting USER to ADMIN succeeds")
    void updateUserRole_AdminPromotesUser_Success() {
        User target = new User("targetUser", "target@example.com", "h", Role.USER);
        target.setId(10L);
        User admin = new User("adminUser", "admin@example.com", "h", Role.ADMIN);
        admin.setId(1L);

        when(userRepository.findById(10L)).thenReturn(Optional.of(target));
        when(userRepository.findByUsernameIgnoreCase("adminUser")).thenReturn(Optional.of(admin));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        UserResponse res = userService.updateUserRole(10L, Role.ADMIN, "adminUser");

        assertEquals(Role.ADMIN, res.getRole());
        verify(userRepository, times(1)).save(target);
    }

    @Test
    @DisplayName("Prevent users from modifying their own role")
    void updateUserRole_SelfModification_Rejected() {
        User admin = new User("adminUser", "admin@example.com", "h", Role.ADMIN);
        admin.setId(1L);

        when(userRepository.findById(1L)).thenReturn(Optional.of(admin));
        when(userRepository.findByUsernameIgnoreCase("adminUser")).thenReturn(Optional.of(admin));

        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> userService.updateUserRole(1L, Role.SUPERADMIN, "adminUser"));
        assertTrue(ex.getMessage().contains("modify their own role"));
    }

    @Test
    @DisplayName("ADMIN cannot assign SUPERADMIN role")
    void updateUserRole_AdminAssigningSuperadmin_Rejected() {
        User target = new User("targetUser", "target@example.com", "h", Role.USER);
        target.setId(10L);
        User admin = new User("adminUser", "admin@example.com", "h", Role.ADMIN);
        admin.setId(1L);

        when(userRepository.findById(10L)).thenReturn(Optional.of(target));
        when(userRepository.findByUsernameIgnoreCase("adminUser")).thenReturn(Optional.of(admin));

        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> userService.updateUserRole(10L, Role.SUPERADMIN, "adminUser"));
        assertTrue(ex.getMessage().contains("Only SUPERADMIN users can grant SUPERADMIN privileges"));
    }

    @Test
    @DisplayName("ADMIN cannot modify existing SUPERADMIN account")
    void updateUserRole_AdminModifyingSuperadmin_Rejected() {
        User superadminTarget = new User("superadminUser", "sa@example.com", "h", Role.SUPERADMIN);
        superadminTarget.setId(10L);
        User admin = new User("adminUser", "admin@example.com", "h", Role.ADMIN);
        admin.setId(1L);

        when(userRepository.findById(10L)).thenReturn(Optional.of(superadminTarget));
        when(userRepository.findByUsernameIgnoreCase("adminUser")).thenReturn(Optional.of(admin));

        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> userService.updateUserRole(10L, Role.USER, "adminUser"));
        assertTrue(ex.getMessage().contains("Only SUPERADMIN users can modify roles of existing SUPERADMIN accounts"));
    }

    @Test
    @DisplayName("SUPERADMIN can assign SUPERADMIN role")
    void updateUserRole_SuperadminAssigningSuperadmin_Success() {
        User target = new User("targetUser", "target@example.com", "h", Role.ADMIN);
        target.setId(10L);
        User superadmin = new User("saActor", "sa@example.com", "h", Role.SUPERADMIN);
        superadmin.setId(1L);

        when(userRepository.findById(10L)).thenReturn(Optional.of(target));
        when(userRepository.findByUsernameIgnoreCase("saActor")).thenReturn(Optional.of(superadmin));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        UserResponse res = userService.updateUserRole(10L, Role.SUPERADMIN, "saActor");

        assertEquals(Role.SUPERADMIN, res.getRole());
    }

    // --- Account Status (Enable/Disable) Tests ---

    @Test
    @DisplayName("ADMIN disabling a user invalidates all their active sessions")
    void updateUserStatus_DisableUser_InvalidatesSessions() {
        User target = new User("targetUser", "target@example.com", "h", Role.USER, true);
        target.setId(10L);
        User admin = new User("adminUser", "admin@example.com", "h", Role.ADMIN);
        admin.setId(1L);

        when(userRepository.findById(10L)).thenReturn(Optional.of(target));
        when(userRepository.findByUsernameIgnoreCase("adminUser")).thenReturn(Optional.of(admin));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        UserResponse res = userService.updateUserStatus(10L, false, "adminUser");

        assertFalse(res.isEnabled());
        verify(sessionService, times(1)).invalidateAllSessionsForUser(target);
    }

    @Test
    @DisplayName("Administrator cannot disable their own account")
    void updateUserStatus_SelfDisable_Rejected() {
        User admin = new User("adminUser", "admin@example.com", "h", Role.ADMIN);
        admin.setId(1L);

        when(userRepository.findById(1L)).thenReturn(Optional.of(admin));
        when(userRepository.findByUsernameIgnoreCase("adminUser")).thenReturn(Optional.of(admin));

        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> userService.updateUserStatus(1L, false, "adminUser"));
        assertTrue(ex.getMessage().contains("disable their own account"));
    }

    @Test
    @DisplayName("ADMIN cannot disable SUPERADMIN account")
    void updateUserStatus_AdminDisablingSuperadmin_Rejected() {
        User superadmin = new User("saTarget", "sa@example.com", "h", Role.SUPERADMIN);
        superadmin.setId(10L);
        User admin = new User("adminUser", "admin@example.com", "h", Role.ADMIN);
        admin.setId(1L);

        when(userRepository.findById(10L)).thenReturn(Optional.of(superadmin));
        when(userRepository.findByUsernameIgnoreCase("adminUser")).thenReturn(Optional.of(admin));

        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> userService.updateUserStatus(10L, false, "adminUser"));
        assertTrue(ex.getMessage().contains("ADMIN users are not permitted to disable SUPERADMIN accounts"));
    }

    // --- Deletion Tests ---

    @Test
    @DisplayName("SUPERADMIN can delete user account and cleans up sessions")
    void deleteUser_Superadmin_Success() {
        User target = new User("targetUser", "target@example.com", "h", Role.USER);
        target.setId(10L);
        User superadmin = new User("saActor", "sa@example.com", "h", Role.SUPERADMIN);
        superadmin.setId(1L);

        when(userRepository.findById(10L)).thenReturn(Optional.of(target));
        when(userRepository.findByUsernameIgnoreCase("saActor")).thenReturn(Optional.of(superadmin));

        userService.deleteUser(10L, "saActor");

        verify(sessionService, times(1)).deleteAllSessionsForUser(target);
        verify(userRepository, times(1)).delete(target);
    }

    @Test
    @DisplayName("Non-SUPERADMIN cannot delete user account")
    void deleteUser_Admin_Rejected() {
        User target = new User("targetUser", "target@example.com", "h", Role.USER);
        target.setId(10L);
        User admin = new User("adminUser", "admin@example.com", "h", Role.ADMIN);
        admin.setId(1L);

        when(userRepository.findById(10L)).thenReturn(Optional.of(target));
        when(userRepository.findByUsernameIgnoreCase("adminUser")).thenReturn(Optional.of(admin));

        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> userService.deleteUser(10L, "adminUser"));
        assertTrue(ex.getMessage().contains("Only SUPERADMIN users can delete user accounts"));
    }

    @Test
    @DisplayName("SUPERADMIN cannot delete their own account")
    void deleteUser_SelfDelete_Rejected() {
        User superadmin = new User("saActor", "sa@example.com", "h", Role.SUPERADMIN);
        superadmin.setId(1L);

        when(userRepository.findById(1L)).thenReturn(Optional.of(superadmin));
        when(userRepository.findByUsernameIgnoreCase("saActor")).thenReturn(Optional.of(superadmin));

        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> userService.deleteUser(1L, "saActor"));
        assertTrue(ex.getMessage().contains("delete their own account"));
    }

    @Test
    @DisplayName("Cannot disable the last active SUPERADMIN account")
    void updateUserStatus_LastSuperadmin_Rejected() {
        User superadminActor = new User("saActor", "sa@example.com", "h", Role.SUPERADMIN);
        superadminActor.setId(1L);
        User superadminTarget = new User("saTarget", "satarget@example.com", "h", Role.SUPERADMIN, true);
        superadminTarget.setId(2L);

        when(userRepository.findById(2L)).thenReturn(Optional.of(superadminTarget));
        when(userRepository.findByUsernameIgnoreCase("saActor")).thenReturn(Optional.of(superadminActor));
        when(userRepository.countByRoleAndEnabledTrue(Role.SUPERADMIN)).thenReturn(1L);

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> userService.updateUserStatus(2L, false, "saActor"));
        assertTrue(ex.getMessage().contains("Cannot disable the only remaining active SUPERADMIN"));
    }

    @Test
    @DisplayName("Cannot delete the last active SUPERADMIN account")
    void deleteUser_LastSuperadmin_Rejected() {
        User superadminActor = new User("saActor", "sa@example.com", "h", Role.SUPERADMIN);
        superadminActor.setId(1L);
        User superadminTarget = new User("saTarget", "satarget@example.com", "h", Role.SUPERADMIN, true);
        superadminTarget.setId(2L);

        when(userRepository.findById(2L)).thenReturn(Optional.of(superadminTarget));
        when(userRepository.findByUsernameIgnoreCase("saActor")).thenReturn(Optional.of(superadminActor));
        when(userRepository.countByRoleAndEnabledTrue(Role.SUPERADMIN)).thenReturn(1L);

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> userService.deleteUser(2L, "saActor"));
        assertTrue(ex.getMessage().contains("Cannot delete the only remaining active SUPERADMIN"));
    }

    @Test
    @DisplayName("Cannot demote the last active SUPERADMIN account")
    void updateUserRole_LastSuperadmin_Rejected() {
        User superadminActor = new User("saActor", "sa@example.com", "h", Role.SUPERADMIN);
        superadminActor.setId(1L);
        User superadminTarget = new User("saTarget", "satarget@example.com", "h", Role.SUPERADMIN, true);
        superadminTarget.setId(2L);

        when(userRepository.findById(2L)).thenReturn(Optional.of(superadminTarget));
        when(userRepository.findByUsernameIgnoreCase("saActor")).thenReturn(Optional.of(superadminActor));
        when(userRepository.countByRoleAndEnabledTrue(Role.SUPERADMIN)).thenReturn(1L);

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> userService.updateUserRole(2L, Role.ADMIN, "saActor"));
        assertTrue(ex.getMessage().contains("Cannot demote the only remaining active SUPERADMIN"));
    }
}
