package com.innspark.loginmonitor;

import com.innspark.loginmonitor.dto.*;
import com.innspark.loginmonitor.entity.*;
import com.innspark.loginmonitor.enums.LoginStatus;
import com.innspark.loginmonitor.enums.OtpChallengeStatus;
import com.innspark.loginmonitor.enums.Role;
import com.innspark.loginmonitor.exception.*;
import com.innspark.loginmonitor.repository.*;
import com.innspark.loginmonitor.service.*;
import com.innspark.loginmonitor.service.impl.CaptchaServiceImpl;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive Acceptance Test Suite for INNSPARK Login Activity Monitor.
 * Validates Phase 2 (Authentication), Phase 3 (RBAC), Phase 4 (Login Monitoring),
 * Phase 5 (Suspicious Activity Detection), and Phase 6 (CAPTCHA & Notifications).
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class AcceptanceComprehensiveTest {

    @Autowired
    private UserService userService;

    @Autowired
    private AuthService authService;

    @Autowired
    private OtpService otpService;

    @Autowired
    private SessionService sessionService;

    @Autowired
    private DashboardService dashboardService;

    @Autowired
    private DetectionService detectionService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserSessionRepository userSessionRepository;

    @Autowired
    private LoginAttemptRepository loginAttemptRepository;

    @Autowired
    private SuspiciousActivityRepository suspiciousActivityRepository;

    @Autowired
    private OtpChallengeRepository otpChallengeRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // =========================================================================
    // PHASE 2: AUTHENTICATION ACCEPTANCE TESTS
    // =========================================================================
    @Nested
    @DisplayName("Phase 2 — Authentication, Hashing & OTP Flow Acceptance")
    class AuthenticationAcceptanceTests {

        @Test
        @DisplayName("2.1: Valid Registration saves user with BCrypt hashed password and default USER role")
        void testValidRegistration() {
            String uname = "accept_user_" + System.currentTimeMillis();
            RegisterRequest req = new RegisterRequest(uname, uname + "@example.com", "SecurePass@123");

            UserResponse res = userService.registerUser(req);

            assertNotNull(res);
            assertEquals(uname, res.getUsername());
            assertEquals(Role.USER, res.getRole());
            assertTrue(res.isEnabled());

            User dbUser = userRepository.findByUsernameIgnoreCase(uname).orElseThrow();
            assertTrue(passwordEncoder.matches("SecurePass@123", dbUser.getPassword()),
                    "Stored password must match raw password via BCrypt");
            assertTrue(dbUser.getPassword().startsWith("$2a$") || dbUser.getPassword().startsWith("$2b$"),
                    "Password hash must be a BCrypt string");
            assertNotEquals("SecurePass@123", dbUser.getPassword(),
                    "Plaintext password must NEVER be persisted");
        }

        @Test
        @DisplayName("2.2: Duplicate username and email registration are rejected")
        void testDuplicateRegistration() {
            String uname = "dup_user_" + System.currentTimeMillis();
            RegisterRequest req1 = new RegisterRequest(uname, uname + "@example.com", "Password@123");
            userService.registerUser(req1);

            RegisterRequest dupUname = new RegisterRequest(uname, "diff_" + uname + "@example.com", "Password@123");
            IllegalArgumentException ex1 = assertThrows(IllegalArgumentException.class, () -> userService.registerUser(dupUname));
            assertTrue(ex1.getMessage().contains("already taken"));

            RegisterRequest dupEmail = new RegisterRequest("diff_" + uname, uname + "@example.com", "Password@123");
            IllegalArgumentException ex2 = assertThrows(IllegalArgumentException.class, () -> userService.registerUser(dupEmail));
            assertTrue(ex2.getMessage().contains("already registered"));
        }

        @Test
        @DisplayName("2.3: Valid credentials initiate 2FA (returns challengeId, NO session token yet)")
        void testValidCredentialsInitiateOtp() {
            String uname = "otp_init_" + System.currentTimeMillis();
            userService.registerUser(new RegisterRequest(uname, uname + "@test.com", "Pass@123"));

            AuthLoginRequest loginReq = new AuthLoginRequest(uname, "Pass@123");
            AuthResponse res = authService.login(loginReq, "192.168.1.50");

            assertTrue(res.isOtpRequired());
            assertNotNull(res.getChallengeId());
            assertNull(res.getSessionToken(), "NO session token should be created before OTP verification");

            OtpChallenge challenge = otpChallengeRepository.findByChallengeId(res.getChallengeId()).orElseThrow();
            assertEquals(OtpChallengeStatus.PENDING, challenge.getStatus());
            assertEquals(uname, challenge.getUser().getUsername());
        }

        @Test
        @DisplayName("2.4: Invalid credentials throw 401 and record a FAILURE login attempt")
        void testInvalidCredentialsRecordFailure() {
            String uname = "invalid_cred_" + System.currentTimeMillis();
            userService.registerUser(new RegisterRequest(uname, uname + "@test.com", "Pass@123"));

            AuthLoginRequest badReq = new AuthLoginRequest(uname, "WrongPassword");
            assertThrows(AuthenticationFailedException.class, () -> authService.login(badReq, "10.0.0.99"));

            List<LoginAttempt> attempts = loginAttemptRepository.findRecentAttemptsByUsername(uname, LocalDateTime.now().minusMinutes(5));
            assertFalse(attempts.isEmpty());
            assertEquals(LoginStatus.FAILURE, attempts.get(0).getStatus());
            assertEquals("10.0.0.99", attempts.get(0).getIpAddress());
        }

        @Test
        @DisplayName("2.5: Successful OTP verification creates active session and returns sessionToken")
        void testSuccessfulOtpVerificationCreatesSession() {
            String uname = "otp_verify_" + System.currentTimeMillis();
            userService.registerUser(new RegisterRequest(uname, uname + "@test.com", "Pass@123"));
            User user = userRepository.findByUsernameIgnoreCase(uname).orElseThrow();

            OtpChallenge challenge = otpService.createAndSendOtp(user);
            String challengeId = challenge.getChallengeId();

            // Override with known OTP hash for testing
            challenge.setOtpHash(passwordEncoder.encode("654321"));
            otpChallengeRepository.save(challenge);

            VerifyOtpRequest verifyReq = new VerifyOtpRequest(challengeId, "654321");
            AuthResponse authRes = authService.verifyOtp(verifyReq, "192.168.1.100");

            assertFalse(authRes.isOtpRequired());
            assertNotNull(authRes.getSessionToken());
            assertEquals(uname, authRes.getUsername());

            Optional<UserSession> sessionOpt = sessionService.validateAndRefreshSession(authRes.getSessionToken());
            assertTrue(sessionOpt.isPresent());
            assertTrue(sessionOpt.get().isActive());
            assertEquals(uname, sessionOpt.get().getUser().getUsername());
        }

        @Test
        @DisplayName("2.6: Incorrect OTP increments failed count and is rejected")
        void testIncorrectOtpRejected() {
            String uname = "otp_wrong_" + System.currentTimeMillis();
            userService.registerUser(new RegisterRequest(uname, uname + "@test.com", "Pass@123"));
            User user = userRepository.findByUsernameIgnoreCase(uname).orElseThrow();

            OtpChallenge challenge = otpService.createAndSendOtp(user);
            challenge.setOtpHash(passwordEncoder.encode("111222"));
            otpChallengeRepository.save(challenge);

            VerifyOtpRequest wrongReq = new VerifyOtpRequest(challenge.getChallengeId(), "999999");
            InvalidOtpException ex = assertThrows(InvalidOtpException.class, () -> authService.verifyOtp(wrongReq, "192.168.1.100"));
            assertTrue(ex.getMessage().contains("Remaining attempts: 4"));

            OtpChallenge updated = otpChallengeRepository.findByChallengeId(challenge.getChallengeId()).orElseThrow();
            assertEquals(1, updated.getFailedAttempts());
            assertEquals(OtpChallengeStatus.PENDING, updated.getStatus());
        }

        @Test
        @DisplayName("2.7: Exceeding 5 failed OTP attempts marks challenge FAILED")
        void testOtpAttemptLimitExceeded() {
            String uname = "otp_limit_" + System.currentTimeMillis();
            userService.registerUser(new RegisterRequest(uname, uname + "@test.com", "Pass@123"));
            User user = userRepository.findByUsernameIgnoreCase(uname).orElseThrow();

            OtpChallenge challenge = otpService.createAndSendOtp(user);
            challenge.setOtpHash(passwordEncoder.encode("111222"));
            challenge.setFailedAttempts(4); // 5th will fail
            otpChallengeRepository.save(challenge);

            VerifyOtpRequest wrongReq = new VerifyOtpRequest(challenge.getChallengeId(), "999999");
            assertThrows(OtpMaxAttemptsExceededException.class, () -> authService.verifyOtp(wrongReq, "192.168.1.100"));

            OtpChallenge updated = otpChallengeRepository.findByChallengeId(challenge.getChallengeId()).orElseThrow();
            assertEquals(5, updated.getFailedAttempts());
            assertEquals(OtpChallengeStatus.FAILED, updated.getStatus());
        }

        @Test
        @DisplayName("2.8: OTP replay prevention — verified challenge cannot be used again")
        void testOtpReplayPrevention() {
            String uname = "otp_replay_" + System.currentTimeMillis();
            userService.registerUser(new RegisterRequest(uname, uname + "@test.com", "Pass@123"));
            User user = userRepository.findByUsernameIgnoreCase(uname).orElseThrow();

            OtpChallenge challenge = otpService.createAndSendOtp(user);
            challenge.setStatus(OtpChallengeStatus.VERIFIED);
            otpChallengeRepository.save(challenge);

            VerifyOtpRequest req = new VerifyOtpRequest(challenge.getChallengeId(), "123456");
            InvalidOtpException ex = assertThrows(InvalidOtpException.class, () -> authService.verifyOtp(req, "192.168.1.100"));
            assertTrue(ex.getMessage().contains("already been used"));
        }

        @Test
        @DisplayName("2.9: Resend OTP enforces 60-second cooldown")
        void testResendOtpCooldown() {
            String uname = "otp_cd_" + System.currentTimeMillis();
            userService.registerUser(new RegisterRequest(uname, uname + "@test.com", "Pass@123"));
            User user = userRepository.findByUsernameIgnoreCase(uname).orElseThrow();

            OtpChallenge challenge = otpService.createAndSendOtp(user);
            challenge.setLastResentAt(LocalDateTime.now().minusSeconds(15)); // only 15s ago
            otpChallengeRepository.save(challenge);

            ResendOtpRequest req = new ResendOtpRequest(challenge.getChallengeId());
            assertThrows(OtpCooldownException.class, () -> authService.resendOtp(req, "192.168.1.100"));
        }

        @Test
        @DisplayName("2.10: Session storage is SHA-256 hashed in MySQL, and logout invalidates session")
        void testLogoutInvalidatesSession() {
            String uname = "logout_user_" + System.currentTimeMillis();
            userService.registerUser(new RegisterRequest(uname, uname + "@test.com", "Pass@123"));
            User user = userRepository.findByUsernameIgnoreCase(uname).orElseThrow();

            UserSession session = sessionService.createSession(user);
            String rawToken = session.getSessionToken();

            // Verify raw session token is NEVER stored directly in MySQL; only the SHA-256 hash is persisted
            assertNotEquals(rawToken, session.getStoredSessionTokenHash(), "Raw session token must not match stored hash");
            assertTrue(session.getStoredSessionTokenHash().matches("^[0-9a-f]{64}$"), "Stored session token must be a 64-char hex SHA-256 string");

            UserSession dbSession = userSessionRepository.findById(session.getId()).orElseThrow();
            assertEquals(session.getStoredSessionTokenHash(), dbSession.getStoredSessionTokenHash(), "Database record must contain the SHA-256 hash");
            assertNotEquals(rawToken, dbSession.getStoredSessionTokenHash(), "Database row must not store raw token");

            // Validating raw token works via hash lookup
            assertTrue(sessionService.validateAndRefreshSession(rawToken).isPresent());

            authService.logout(rawToken);

            Optional<UserSession> invalidated = sessionService.validateAndRefreshSession(rawToken);
            assertFalse(invalidated.isPresent(), "Session should be empty or inactive after logout");
        }

        @Test
        @DisplayName("2.11: 15-minute inactivity timeout deactivates session, and active requests slide the window")
        void testSessionInactivityTimeoutAndSlidingWindow() {
            String uname = "inact_user_" + System.currentTimeMillis();
            userService.registerUser(new RegisterRequest(uname, uname + "@test.com", "Pass@123"));
            User user = userRepository.findByUsernameIgnoreCase(uname).orElseThrow();

            UserSession session = sessionService.createSession(user);
            String rawToken = session.getSessionToken();

            // 1. Sliding window test: active request within 15 minutes refreshes lastActivityAt and slides expiresAt
            LocalDateTime beforeSlide = LocalDateTime.now();
            Optional<UserSession> refreshed = sessionService.validateAndRefreshSession(rawToken);
            assertTrue(refreshed.isPresent());
            assertTrue(refreshed.get().getLastActivityAt().isAfter(beforeSlide.minusSeconds(2)));
            assertTrue(refreshed.get().getExpiresAt().isAfter(beforeSlide.plusMinutes(14)));

            // 2. Simulate 16 minutes of inactivity by setting lastActivityAt to 16 minutes ago
            UserSession dbSession = userSessionRepository.findById(session.getId()).orElseThrow();
            dbSession.setLastActivityAt(LocalDateTime.now().minusMinutes(16));
            dbSession.setExpiresAt(LocalDateTime.now().minusMinutes(1));
            userSessionRepository.save(dbSession);

            // 3. Attempting to validate inactive session must reject and deactivate
            Optional<UserSession> expired = sessionService.validateAndRefreshSession(rawToken);
            assertTrue(expired.isEmpty(), "Session inactive for > 15 minutes must be rejected");

            UserSession deactivated = userSessionRepository.findById(session.getId()).orElseThrow();
            assertFalse(deactivated.isActive(), "Inactive session must be marked inactive in MySQL");
        }

        @Test
        @DisplayName("2.12: Administrators can view active unexpired sessions for each user")
        void testAdminCanViewActiveSessionsForUser() {
            String uname = "sess_user_" + System.currentTimeMillis();
            userService.registerUser(new RegisterRequest(uname, uname + "@test.com", "Pass@123"));
            User user = userRepository.findByUsernameIgnoreCase(uname).orElseThrow();

            UserSession s1 = sessionService.createSession(user);

            // Active sessions query returns the session
            List<UserSessionResponse> activeSessions = sessionService.getActiveSessionsForUser(user.getId());
            assertThat(activeSessions).isNotEmpty();
            assertThat(activeSessions.get(0).getUserId()).isEqualTo(user.getId());
            assertThat(activeSessions.get(0).getUsername()).isEqualTo(uname);
            assertThat(activeSessions.get(0).isActive()).isTrue();

            // When user logs out, active sessions list becomes empty
            sessionService.invalidateSession(s1.getSessionToken());
            List<UserSessionResponse> afterLogout = sessionService.getActiveSessionsForUser(user.getId());
            assertThat(afterLogout).isEmpty();
        }
    }

    // =========================================================================
    // PHASE 3: ROLE-BASED ACCESS CONTROL (RBAC) ACCEPTANCE TESTS
    // =========================================================================
    @Nested
    @DisplayName("Phase 3 — RBAC, Privileges & User Management Acceptance")
    class RbacAcceptanceTests {

        @Test
        @DisplayName("3.1: Self-registration as ADMIN or SUPERADMIN is prohibited")
        void testPublicRegistrationPrivilegedRoleBlocked() {
            RegisterRequest reqAdmin = new RegisterRequest("bad_admin", "bad_admin@test.com", "Pass@123", Role.ADMIN);
            IllegalArgumentException ex1 = assertThrows(IllegalArgumentException.class, () -> userService.registerUser(reqAdmin));
            assertTrue(ex1.getMessage().contains("Self-registration as ADMIN is not permitted"));

            RegisterRequest reqSuper = new RegisterRequest("bad_super", "bad_super@test.com", "Pass@123", Role.SUPERADMIN);
            IllegalArgumentException ex2 = assertThrows(IllegalArgumentException.class, () -> userService.registerUser(reqSuper));
            assertTrue(ex2.getMessage().contains("Self-registration as SUPERADMIN is not permitted"));
        }

        @Test
        @DisplayName("3.2: ADMIN cannot promote any user to SUPERADMIN")
        void testAdminCannotPromoteToSuperadmin() {
            String adminName = "admin_actor_" + System.currentTimeMillis();
            User admin = new User(adminName, adminName + "@test.com", "h", Role.ADMIN);
            admin.setEnabled(true);
            userRepository.save(admin);

            String targetName = "target_" + System.currentTimeMillis();
            User target = new User(targetName, targetName + "@test.com", "h", Role.USER);
            target.setEnabled(true);
            userRepository.save(target);

            AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                    () -> userService.updateUserRole(target.getId(), Role.SUPERADMIN, adminName));
            assertTrue(ex.getMessage().contains("Only SUPERADMIN users can grant SUPERADMIN privileges"));
        }

        @Test
        @DisplayName("3.3: ADMIN cannot modify or disable a SUPERADMIN account")
        void testAdminCannotModifySuperadmin() {
            String adminName = "admin_actor2_" + System.currentTimeMillis();
            User admin = new User(adminName, adminName + "@test.com", "h", Role.ADMIN);
            userRepository.save(admin);

            String saName = "sa_target_" + System.currentTimeMillis();
            User superadmin = new User(saName, saName + "@test.com", "h", Role.SUPERADMIN);
            userRepository.save(superadmin);

            AccessDeniedException exRole = assertThrows(AccessDeniedException.class,
                    () -> userService.updateUserRole(superadmin.getId(), Role.USER, adminName));
            assertTrue(exRole.getMessage().contains("Only SUPERADMIN users can modify roles of existing SUPERADMIN accounts"));

            AccessDeniedException exStatus = assertThrows(AccessDeniedException.class,
                    () -> userService.updateUserStatus(superadmin.getId(), false, adminName));
            assertTrue(exStatus.getMessage().contains("ADMIN users are not permitted to disable SUPERADMIN accounts"));
        }

        @Test
        @DisplayName("3.4: Protection against users modifying their own role (self-demotion/self-escalation)")
        void testCannotDemoteSelf() {
            String saName = "sa_self_role_" + System.currentTimeMillis();
            User sa = new User(saName, saName + "@test.com", "h", Role.SUPERADMIN);
            sa = userRepository.save(sa);

            User finalSa = sa;
            AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                    () -> userService.updateUserRole(finalSa.getId(), Role.ADMIN, saName));
            assertTrue(ex.getMessage().contains("Users are not permitted to modify their own role"));
        }

        @Test
        @DisplayName("3.5: SUPERADMIN cannot delete their own account")
        void testSuperadminCannotDeleteSelf() {
            String saName = "sa_self_del_" + System.currentTimeMillis();
            User sa = new User(saName, saName + "@test.com", "h", Role.SUPERADMIN);
            sa = userRepository.save(sa);

            User finalSa = sa;
            AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                    () -> userService.deleteUser(finalSa.getId(), saName));
            assertTrue(ex.getMessage().contains("Administrators are not permitted to delete their own account"));
        }

        @Test
        @DisplayName("3.6: Protection against disabling, deleting, or demoting the last active SUPERADMIN")
        void testLastSuperadminProtection() {
            String actorName = "sa_actor_" + System.currentTimeMillis();
            User saActor = new User(actorName, actorName + "@test.com", "h", Role.SUPERADMIN, true);
            userRepository.save(saActor);

            String targetName = "sa_target_" + System.currentTimeMillis();
            User saTarget = new User(targetName, targetName + "@test.com", "h", Role.SUPERADMIN, true);
            final User savedTarget = userRepository.save(saTarget);

            // With multiple active SUPERADMINs, actor can operate on target
            assertTrue(userRepository.countByRoleAndEnabledTrue(Role.SUPERADMIN) >= 2);

            // Temporarily disable all other superadmins to isolate savedTarget as the lone active superadmin
            List<User> allSuperadmins = userRepository.findAll().stream()
                    .filter(u -> u.getRole() == Role.SUPERADMIN && !u.getId().equals(savedTarget.getId()) && u.isEnabled())
                    .toList();

            for (User u : allSuperadmins) {
                u.setEnabled(false);
                userRepository.save(u);
            }

            assertEquals(1L, userRepository.countByRoleAndEnabledTrue(Role.SUPERADMIN));

            // Attempt to disable the lone active superadmin
            IllegalStateException exDisable = assertThrows(IllegalStateException.class,
                    () -> userService.updateUserStatus(savedTarget.getId(), false, actorName));
            assertTrue(exDisable.getMessage().contains("Cannot disable the only remaining active SUPERADMIN"));

            // Attempt to delete the lone active superadmin
            IllegalStateException exDelete = assertThrows(IllegalStateException.class,
                    () -> userService.deleteUser(savedTarget.getId(), actorName));
            assertTrue(exDelete.getMessage().contains("Cannot delete the only remaining active SUPERADMIN"));

            // Attempt to demote the lone active superadmin
            IllegalStateException exDemote = assertThrows(IllegalStateException.class,
                    () -> userService.updateUserRole(savedTarget.getId(), Role.ADMIN, actorName));
            assertTrue(exDemote.getMessage().contains("Cannot demote the only remaining active SUPERADMIN"));

            // Re-enable isolated superadmins to restore clean state
            for (User u : allSuperadmins) {
                u.setEnabled(true);
                userRepository.save(u);
            }
        }

        @Test
        @DisplayName("3.7: SUPERADMIN successfully changes USER to ADMIN, ADMIN to USER, and user to SUPERADMIN")
        void testSuperadminRoleChanges() {
            String saName = "sa_mgr_" + System.currentTimeMillis();
            User sa = userRepository.save(new User(saName, saName + "@test.com", "h", Role.SUPERADMIN, true));

            String targetName = "user_target_" + System.currentTimeMillis();
            User target = userRepository.save(new User(targetName, targetName + "@test.com", "h", Role.USER, true));

            // 1. Change USER -> ADMIN
            UserResponse r1 = userService.updateUserRole(target.getId(), Role.ADMIN, saName);
            assertEquals(Role.ADMIN, r1.getRole());

            // 2. Change ADMIN -> USER
            UserResponse r2 = userService.updateUserRole(target.getId(), Role.USER, saName);
            assertEquals(Role.USER, r2.getRole());

            // 3. Change USER -> SUPERADMIN
            UserResponse r3 = userService.updateUserRole(target.getId(), Role.SUPERADMIN, saName);
            assertEquals(Role.SUPERADMIN, r3.getRole());
        }

        @Test
        @DisplayName("3.8: USER role attempting role modification is rejected")
        void testUserCannotChangeRoles() {
            String u1Name = "user_regular_" + System.currentTimeMillis();
            User u1 = userRepository.save(new User(u1Name, u1Name + "@test.com", "h", Role.USER, true));

            String u2Name = "user_other_" + System.currentTimeMillis();
            User u2 = userRepository.save(new User(u2Name, u2Name + "@test.com", "h", Role.USER, true));

            AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                    () -> userService.updateUserRole(u2.getId(), Role.ADMIN, u1Name));
            assertTrue(ex.getMessage().contains("Regular users are not permitted to assign or modify roles"));
        }

        @Test
        @DisplayName("3.9: Updated role is correctly displayed in the user directory list")
        void testUpdatedRoleDisplayedInDirectory() {
            String saName = "sa_dir_" + System.currentTimeMillis();
            User sa = userRepository.save(new User(saName, saName + "@test.com", "h", Role.SUPERADMIN, true));

            String targetName = "dir_target_" + System.currentTimeMillis();
            User target = userRepository.save(new User(targetName, targetName + "@test.com", "h", Role.USER, true));

            userService.updateUserRole(target.getId(), Role.ADMIN, saName);

            org.springframework.data.domain.Page<UserResponse> page = userService.listUsers(targetName, org.springframework.data.domain.PageRequest.of(0, 10));
            assertThat(page.getContent()).isNotEmpty();
            assertEquals(Role.ADMIN, page.getContent().get(0).getRole());
        }

        @Test
        @DisplayName("3.10: Updated permissions take effect after logout and login again")
        void testUpdatedPermissionsTakeEffectAfterReLogin() {
            String uname = "relogin_user_" + System.currentTimeMillis();
            String rawPass = "Pass@123456";
            userService.registerUser(new RegisterRequest(uname, uname + "@test.com", rawPass));

            // Verify initial role is USER
            User user = userRepository.findByUsernameIgnoreCase(uname).orElseThrow();
            assertEquals(Role.USER, user.getRole());

            // A SUPERADMIN promotes user to ADMIN
            String saName = "sa_promoter_" + System.currentTimeMillis();
            userRepository.save(new User(saName, saName + "@test.com", "h", Role.SUPERADMIN, true));
            userService.updateUserRole(user.getId(), Role.ADMIN, saName);

            // User logs in with primary credentials -> completes OTP -> gets session
            AuthResponse authRes = authService.login(new AuthLoginRequest(uname, rawPass), "127.0.0.1");
            assertTrue(authRes.isOtpRequired());

            OtpChallenge challenge = otpChallengeRepository.findByChallengeId(authRes.getChallengeId()).orElseThrow();
            // Verify and simulate OTP completion
            challenge.setStatus(OtpChallengeStatus.VERIFIED);
            challenge.setVerifiedAt(LocalDateTime.now());
            otpChallengeRepository.save(challenge);

            User reloadedUser = userRepository.findByUsernameIgnoreCase(uname).orElseThrow();
            UserSession newSession = sessionService.createSession(reloadedUser);
            Optional<UserSession> validated = sessionService.validateAndRefreshSession(newSession.getSessionToken());
            assertTrue(validated.isPresent());
            assertEquals(Role.ADMIN, validated.get().getUser().getRole(), "New session must have updated ADMIN role");
        }
    }

    // =========================================================================
    // PHASE 4: LOGIN MONITORING & DASHBOARD METRICS ACCEPTANCE TESTS
    // =========================================================================
    @Nested
    @DisplayName("Phase 4 — Login Monitoring & Metric Computation Acceptance")
    class LoginMonitoringAcceptanceTests {

        @Test
        @DisplayName("4.1: Login attempts record IP, timestamp, userAgent and status accurately")
        void testLoginAttemptRecording() {
            String uname = "monitor_test_" + System.currentTimeMillis();

            loginAttemptRepository.save(new LoginAttempt(uname, "203.0.113.195", LocalDateTime.now(), LoginStatus.SUCCESS));
            loginAttemptRepository.save(new LoginAttempt(uname, "203.0.113.195", LocalDateTime.now(), LoginStatus.FAILURE));

            List<LoginAttempt> attempts = loginAttemptRepository.findRecentAttemptsByUsername(uname, LocalDateTime.now().minusMinutes(5));
            assertThat(attempts).hasSize(2);
            assertThat(attempts).extracting(LoginAttempt::getIpAddress).containsOnly("203.0.113.195");
            assertThat(attempts).extracting(LoginAttempt::getStatus).contains(LoginStatus.SUCCESS, LoginStatus.FAILURE);
        }

        @Test
        @DisplayName("4.2: User Dashboard statistics accurately aggregate real user records")
        void testUserDashboardStatsCalculation() {
            String uname = "dash_user_" + System.currentTimeMillis();

            loginAttemptRepository.save(new LoginAttempt(uname, "10.0.0.1", LocalDateTime.now(), LoginStatus.SUCCESS));
            loginAttemptRepository.save(new LoginAttempt(uname, "10.0.0.1", LocalDateTime.now(), LoginStatus.SUCCESS));
            loginAttemptRepository.save(new LoginAttempt(uname, "10.0.0.1", LocalDateTime.now(), LoginStatus.FAILURE));

            SuspiciousActivity sa = new SuspiciousActivity(
                    "10.0.0.1",
                    uname,
                    "RULE_2_MULTIPLE_FAILED_LOGINS_SAME_USER: 3 failed attempts",
                    LocalDateTime.now()
            );
            suspiciousActivityRepository.save(sa);

            UserDashboardStatsResponse stats = dashboardService.getUserStats(uname);

            assertEquals(3L, stats.getTotalLoginAttempts());
            assertEquals(2L, stats.getSuccessfulLogins());
            assertEquals(1L, stats.getFailedLogins());
            assertEquals(1L, stats.getSuspiciousActivities());
            assertNotNull(stats.getLastLogin());
            assertNotNull(stats.getLastSuccessfulLogin());
        }

        @Test
        @DisplayName("4.3: Paginated login history respects filters and user isolation")
        void testPaginatedLoginHistory() {
            String userA = "user_a_" + System.currentTimeMillis();
            String userB = "user_b_" + System.currentTimeMillis();

            loginAttemptRepository.save(new LoginAttempt(userA, "1.1.1.1", LocalDateTime.now(), LoginStatus.SUCCESS));
            loginAttemptRepository.save(new LoginAttempt(userA, "1.1.1.1", LocalDateTime.now(), LoginStatus.FAILURE));
            loginAttemptRepository.save(new LoginAttempt(userB, "2.2.2.2", LocalDateTime.now(), LoginStatus.SUCCESS));

            PageResponse<LoginAttemptResponse> pageA = dashboardService.getUserLoginHistory(userA, null, 0, 10);

            assertThat(pageA.getContent()).hasSize(2);
            assertThat(pageA.getContent()).allMatch(a -> a.getUsername().equalsIgnoreCase(userA));

            PageResponse<LoginAttemptResponse> successOnlyA = dashboardService.getUserLoginHistory(userA, LoginStatus.SUCCESS, 0, 10);

            assertThat(successOnlyA.getContent()).hasSize(1);
            assertEquals(LoginStatus.SUCCESS, successOnlyA.getContent().get(0).getStatus());
        }
    }

    // =========================================================================
    // PHASE 5: SUSPICIOUS ACTIVITY DETECTION ACCEPTANCE TESTS
    // =========================================================================
    @Nested
    @DisplayName("Phase 5 — Suspicious Activity Detection Engine Acceptance")
    class SuspiciousActivityAcceptanceTests {

        @Test
        @DisplayName("5.1: Rule 1 — Multiple failed attempts from the same IP (>= 5 in 10m) triggers alert")
        void testRule1_IpBruteForceTriggered() {
            String ip = "198.51.100." + (int)(Math.random() * 200 + 10);

            for (int i = 0; i < 5; i++) {
                LoginAttempt attempt = new LoginAttempt("testuser_" + i, ip, LocalDateTime.now(), LoginStatus.FAILURE);
                loginAttemptRepository.save(attempt);
                detectionService.detectSuspiciousActivity(attempt);
            }

            boolean exists = suspiciousActivityRepository.existsByIpAddressAndReasonPrefixSince(
                    ip, "Multiple failed login attempts from the same IP", LocalDateTime.now().minusMinutes(10));
            assertTrue(exists, "Rule 1 must flag suspicious activity for >= 5 failures from same IP");

            // Deduplication test: 6th failure should NOT duplicate the incident
            long countBefore = suspiciousActivityRepository.count();
            LoginAttempt attempt6 = new LoginAttempt("testuser_6", ip, LocalDateTime.now(), LoginStatus.FAILURE);
            loginAttemptRepository.save(attempt6);
            detectionService.detectSuspiciousActivity(attempt6);
            long countAfter = suspiciousActivityRepository.count();
            assertEquals(countBefore, countAfter, "Deduplication must prevent duplicate incident logging");
        }

        @Test
        @DisplayName("5.2: Rule 2 — Multiple failed attempts for the same username (>= 5 in 10m) triggers alert")
        void testRule2_UsernameBruteForceTriggered() {
            String targetUser = "victim_" + System.currentTimeMillis();

            for (int i = 0; i < 5; i++) {
                LoginAttempt attempt = new LoginAttempt(targetUser, "192.168.1." + (i + 1), LocalDateTime.now(), LoginStatus.FAILURE);
                loginAttemptRepository.save(attempt);
                detectionService.detectSuspiciousActivity(attempt);
            }

            boolean exists = suspiciousActivityRepository.existsByUsernameAndReasonPrefixSince(
                    targetUser, "Multiple failed login attempts for the same username", LocalDateTime.now().minusMinutes(10));
            assertTrue(exists, "Rule 2 must flag suspicious activity for >= 5 failures for same username");
        }

        @Test
        @DisplayName("5.3: Rule 3 — Successful login after >= 3 consecutive failed attempts triggers alert")
        void testRule3_UnusualSuccessTriggered() {
            String targetUser = "recovered_" + System.currentTimeMillis();

            // 3 consecutive failures
            for (int i = 0; i < 3; i++) {
                LoginAttempt fail = new LoginAttempt(targetUser, "10.10.10.1", LocalDateTime.now().minusSeconds(30 - i * 5), LoginStatus.FAILURE);
                loginAttemptRepository.save(fail);
            }
            // 4th attempt is successful
            LoginAttempt success = new LoginAttempt(targetUser, "10.10.10.1", LocalDateTime.now(), LoginStatus.SUCCESS);
            loginAttemptRepository.save(success);
            detectionService.detectSuspiciousActivity(success);

            boolean exists = suspiciousActivityRepository.existsByUsernameAndReasonPrefixSince(
                    targetUser, "Successful login following multiple failed attempts", LocalDateTime.now().minusMinutes(10));
            assertTrue(exists, "Rule 3 must flag suspicious activity on success following multiple failures");
        }

        @Test
        @DisplayName("5.4: Severity rating classifies incidents correctly")
        void testSeverityClassification() {
            SuspiciousActivityResponse resHigh = new SuspiciousActivityResponse(1L, "ip", "user", "Multiple failed login attempts from the same IP: 5 failed attempts", LocalDateTime.now());
            assertEquals("HIGH", resHigh.getSeverity());

            SuspiciousActivityResponse resMed = new SuspiciousActivityResponse(2L, "ip", "user", "Login from different IP address within short window", LocalDateTime.now());
            assertEquals("MEDIUM", resMed.getSeverity());

            SuspiciousActivityResponse resLow = new SuspiciousActivityResponse(3L, "ip", "user", "Informational system notice", LocalDateTime.now());
            assertEquals("LOW", resLow.getSeverity());
        }
    }

    // =========================================================================
    // PHASE 6: CAPTCHA, EMAIL & HYGIENE ACCEPTANCE TESTS
    // =========================================================================
    @Nested
    @DisplayName("Phase 6 — CAPTCHA, Email & Data Hygiene Acceptance")
    class CaptchaAndEmailAcceptanceTests {

        @Test
        @DisplayName("6.1: When CAPTCHA is disabled, null token is handled gracefully")
        void testCaptchaGracefulNullWhenDisabled() {
            assertDoesNotThrow(() -> loginAttemptRepository.save(new LoginAttempt("test", "1.1.1.1", LocalDateTime.now(), LoginStatus.SUCCESS)));
        }

        @Test
        @DisplayName("6.2: Passwords and OTP hashes in database are securely salted and hashed")
        void testDataHygieneHashes() {
            String rawPass = "MyP@ssword999";
            String encodedPass = passwordEncoder.encode(rawPass);

            assertFalse(encodedPass.contains(rawPass));
            assertTrue(passwordEncoder.matches(rawPass, encodedPass));

            String encodedPass2 = passwordEncoder.encode(rawPass);
            assertNotEquals(encodedPass, encodedPass2, "BCrypt must use a distinct salt for every hash");
        }

        @Test
        @DisplayName("6.3: Production profile enforces CAPTCHA enablement and secret configuration")
        void testCaptchaProductionEnforcement() {
            org.springframework.mock.env.MockEnvironment prodEnv = new org.springframework.mock.env.MockEnvironment();
            prodEnv.setActiveProfiles("prod");

            CaptchaServiceImpl prodCaptchaService = new CaptchaServiceImpl(new org.springframework.web.client.RestTemplate(), prodEnv);
            // Default disabled -> must throw IllegalStateException
            IllegalStateException ex = assertThrows(IllegalStateException.class, prodCaptchaService::validateProductionConfiguration);
            assertTrue(ex.getMessage().contains("CAPTCHA cannot be disabled in production profile"));

            // Enabled but missing secret -> must throw IllegalStateException
            org.springframework.test.util.ReflectionTestUtils.setField(prodCaptchaService, "captchaEnabled", true);
            IllegalStateException exSecret = assertThrows(IllegalStateException.class, prodCaptchaService::validateProductionConfiguration);
            assertTrue(exSecret.getMessage().contains("CAPTCHA secret"));

            // Enabled with secret -> succeeds
            org.springframework.test.util.ReflectionTestUtils.setField(prodCaptchaService, "captchaSecret", "prod-secret-key");
            assertDoesNotThrow(prodCaptchaService::validateProductionConfiguration);
        }
    }
}
