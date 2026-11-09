package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.dto.AuthLoginRequest;
import com.innspark.loginmonitor.dto.AuthResponse;
import com.innspark.loginmonitor.dto.ResendOtpRequest;
import com.innspark.loginmonitor.dto.ResendOtpResponse;
import com.innspark.loginmonitor.dto.VerifyOtpRequest;
import com.innspark.loginmonitor.entity.LoginAttempt;
import com.innspark.loginmonitor.entity.OtpChallenge;
import com.innspark.loginmonitor.entity.User;
import com.innspark.loginmonitor.entity.UserSession;
import com.innspark.loginmonitor.enums.LoginStatus;
import com.innspark.loginmonitor.enums.Role;
import com.innspark.loginmonitor.exception.AccountDisabledException;
import com.innspark.loginmonitor.exception.AuthenticationFailedException;
import com.innspark.loginmonitor.exception.InvalidCaptchaException;
import com.innspark.loginmonitor.exception.InvalidOtpException;
import com.innspark.loginmonitor.repository.LoginAttemptRepository;
import com.innspark.loginmonitor.repository.UserRepository;
import com.innspark.loginmonitor.service.impl.AuthServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private SessionService sessionService;

    @Mock
    private RateLimiterService rateLimiterService;

    @Mock
    private LoginAttemptRepository loginAttemptRepository;

    @Mock
    private DetectionService detectionService;

    @Mock
    private CaptchaService captchaService;

    @Mock
    private OtpService otpService;

    @InjectMocks
    private AuthServiceImpl authService;

    private User sampleUser;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "captchaFailureThreshold", 3);
        ReflectionTestUtils.setField(authService, "windowMinutes", 10);
        sampleUser = new User("validuser", "valid@example.com", "$2a$10$hashedPassword", Role.USER);
        sampleUser.setId(1L);
        sampleUser.setEnabled(true);
    }

    @Test
    @DisplayName("When OTP is enabled, login returns OTP challenge and DOES NOT create a session")
    void login_OtpEnabled_ReturnsChallenge_NoSessionCreated() {
        AuthLoginRequest request = new AuthLoginRequest("validuser", "correctPass");
        OtpChallenge mockChallenge = new OtpChallenge("ch-uuid-1234", sampleUser, "$2a$10$hashedOtp",
                LocalDateTime.now(), LocalDateTime.now().plusMinutes(5));

        when(otpService.isOtpEnabled()).thenReturn(true);
        when(userRepository.findByUsernameIgnoreCase("validuser")).thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("correctPass", "$2a$10$hashedPassword")).thenReturn(true);
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(otpService.createAndSendOtp(sampleUser)).thenReturn(mockChallenge);

        AuthResponse response = authService.login(request, "192.168.1.10");

        assertNotNull(response);
        assertTrue(response.isOtpRequired(), "OTP must be required when 2FA is enabled");
        assertEquals("ch-uuid-1234", response.getChallengeId());
        assertNull(response.getSessionToken(), "Session token must NOT be generated before OTP verification");
        assertEquals("validuser", response.getUsername());
        assertEquals(Role.USER, response.getRole());

        // Verify sessionService.createSession was NEVER invoked
        verify(sessionService, never()).createSession(any(User.class));
        verify(otpService, times(1)).createAndSendOtp(sampleUser);
    }

    @Test
    @DisplayName("When OTP is enabled, ALL user roles (USER, ADMIN, SUPERADMIN) require OTP")
    void login_OtpEnabled_AllRolesRequireOtp() {
        Role[] roles = {Role.USER, Role.ADMIN, Role.SUPERADMIN};

        for (Role role : roles) {
            User testUser = new User("user_" + role.name(), "user@example.com", "$2a$10$hashedPass", role);
            testUser.setId(100L);
            testUser.setEnabled(true);

            OtpChallenge mockChallenge = new OtpChallenge("ch-" + role.name(), testUser, "$2a$10$hash",
                    LocalDateTime.now(), LocalDateTime.now().plusMinutes(5));

            when(otpService.isOtpEnabled()).thenReturn(true);
            when(userRepository.findByUsernameIgnoreCase(testUser.getUsername())).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("pass", "$2a$10$hashedPass")).thenReturn(true);
            when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(i -> i.getArgument(0));
            when(otpService.createAndSendOtp(testUser)).thenReturn(mockChallenge);

            AuthResponse response = authService.login(new AuthLoginRequest(testUser.getUsername(), "pass"), "127.0.0.1");

            assertTrue(response.isOtpRequired(), "Role " + role + " must require OTP");
            assertEquals("ch-" + role.name(), response.getChallengeId());
            assertNull(response.getSessionToken(), "Role " + role + " must not receive session token before OTP");
        }

        verify(sessionService, never()).createSession(any(User.class));
    }

    @Test
    @DisplayName("When OTP is disabled, login directly creates session (backward-compatible fallback)")
    void login_OtpDisabled_DirectSessionCreation() {
        AuthLoginRequest request = new AuthLoginRequest("validuser", "correctPass");
        UserSession mockSession = new UserSession(sampleUser, "session_token_xyz", LocalDateTime.now(), LocalDateTime.now(), LocalDateTime.now().plusMinutes(15));

        when(otpService.isOtpEnabled()).thenReturn(false);
        when(userRepository.findByUsernameIgnoreCase("validuser")).thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("correctPass", "$2a$10$hashedPassword")).thenReturn(true);
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(sessionService.createSession(sampleUser)).thenReturn(mockSession);

        AuthResponse response = authService.login(request, "192.168.1.10");

        assertNotNull(response);
        assertFalse(response.isOtpRequired());
        assertEquals("session_token_xyz", response.getSessionToken());
        assertEquals("validuser", response.getUsername());
        assertEquals(Role.USER, response.getRole());

        verify(sessionService, times(1)).createSession(sampleUser);
        verify(otpService, never()).createAndSendOtp(any(User.class));
    }

    @Test
    @DisplayName("Unknown username: records FAILURE, triggers detection, throws AuthenticationFailedException, no session")
    void login_UnknownUsername() {
        AuthLoginRequest request = new AuthLoginRequest("nonexistent", "pass123");

        when(userRepository.findByUsernameIgnoreCase("nonexistent")).thenReturn(Optional.empty());
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AuthenticationFailedException ex = assertThrows(AuthenticationFailedException.class, () ->
                authService.login(request, "192.168.1.10")
        );
        assertEquals("Invalid username or password", ex.getMessage());

        ArgumentCaptor<LoginAttempt> attemptCaptor = ArgumentCaptor.forClass(LoginAttempt.class);
        verify(loginAttemptRepository, times(1)).save(attemptCaptor.capture());
        assertEquals(LoginStatus.FAILURE, attemptCaptor.getValue().getStatus());
        assertEquals("nonexistent", attemptCaptor.getValue().getUsername());

        verify(detectionService, times(1)).detectSuspiciousActivity(any(LoginAttempt.class));
        verify(sessionService, never()).createSession(any(User.class));
    }

    @Test
    @DisplayName("Password mismatch: records FAILURE, triggers detection, throws AuthenticationFailedException, no session")
    void login_PasswordMismatch() {
        AuthLoginRequest request = new AuthLoginRequest("validuser", "wrongPass");

        when(userRepository.findByUsernameIgnoreCase("validuser")).thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("wrongPass", "$2a$10$hashedPassword")).thenReturn(false);
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AuthenticationFailedException ex = assertThrows(AuthenticationFailedException.class, () ->
                authService.login(request, "192.168.1.10")
        );
        assertEquals("Invalid username or password", ex.getMessage());

        ArgumentCaptor<LoginAttempt> attemptCaptor = ArgumentCaptor.forClass(LoginAttempt.class);
        verify(loginAttemptRepository, times(1)).save(attemptCaptor.capture());
        assertEquals(LoginStatus.FAILURE, attemptCaptor.getValue().getStatus());

        verify(detectionService, times(1)).detectSuspiciousActivity(any(LoginAttempt.class));
        verify(sessionService, never()).createSession(any(User.class));
    }

    @Test
    @DisplayName("Disabled account: records FAILURE, throws AccountDisabledException (403), no session")
    void login_DisabledAccount() {
        sampleUser.setEnabled(false);
        AuthLoginRequest request = new AuthLoginRequest("validuser", "correctPass");

        when(userRepository.findByUsernameIgnoreCase("validuser")).thenReturn(Optional.of(sampleUser));
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AccountDisabledException ex = assertThrows(AccountDisabledException.class, () ->
                authService.login(request, "192.168.1.10")
        );
        assertTrue(ex.getMessage().contains("Account is disabled"));

        verify(sessionService, never()).createSession(any(User.class));
    }

    @Test
    @DisplayName("verifyOtp with valid code creates session and returns AuthResponse with token")
    void verifyOtp_Success() {
        VerifyOtpRequest request = new VerifyOtpRequest("ch-1234", "123456");
        UserSession mockSession = new UserSession(sampleUser, "session_token_abc",
                LocalDateTime.now(), LocalDateTime.now(), LocalDateTime.now().plusMinutes(15));

        when(otpService.verifyOtp("ch-1234", "123456", "192.168.1.10")).thenReturn(sampleUser);
        when(sessionService.createSession(sampleUser)).thenReturn(mockSession);

        AuthResponse response = authService.verifyOtp(request, "192.168.1.10");

        assertNotNull(response);
        assertFalse(response.isOtpRequired());
        assertEquals("session_token_abc", response.getSessionToken());
        assertEquals("validuser", response.getUsername());
        assertEquals(Role.USER, response.getRole());

        verify(rateLimiterService, times(1)).checkRateLimit("192.168.1.10");
        verify(sessionService, times(1)).createSession(sampleUser);
    }

    @Test
    @DisplayName("verifyOtp failure records audit attempt and throws exception")
    void verifyOtp_Failure_AuditsAttempt() {
        VerifyOtpRequest request = new VerifyOtpRequest("ch-1234", "999999");

        when(otpService.verifyOtp("ch-1234", "999999", "192.168.1.10"))
                .thenThrow(new InvalidOtpException("Invalid OTP code"));
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(i -> i.getArgument(0));

        assertThrows(InvalidOtpException.class, () -> authService.verifyOtp(request, "192.168.1.10"));

        ArgumentCaptor<LoginAttempt> attemptCaptor = ArgumentCaptor.forClass(LoginAttempt.class);
        verify(loginAttemptRepository, times(1)).save(attemptCaptor.capture());
        assertEquals(LoginStatus.FAILURE, attemptCaptor.getValue().getStatus());

        verify(sessionService, never()).createSession(any(User.class));
    }

    @Test
    @DisplayName("resendOtp delegates to otpService after rate limit check")
    void resendOtp_Success() {
        ResendOtpRequest request = new ResendOtpRequest("ch-1234");
        ResendOtpResponse mockResponse = new ResendOtpResponse("ch-1234", LocalDateTime.now().plusMinutes(5), "sent");

        when(otpService.resendOtp("ch-1234", "192.168.1.10")).thenReturn(mockResponse);

        ResendOtpResponse response = authService.resendOtp(request, "192.168.1.10");

        assertNotNull(response);
        assertEquals("ch-1234", response.getChallengeId());
        verify(rateLimiterService, times(1)).checkRateLimit("192.168.1.10");
        verify(otpService, times(1)).resendOtp("ch-1234", "192.168.1.10");
    }

    @Test
    @DisplayName("Logout: delegates token invalidation to sessionService")
    void logout_Success() {
        authService.logout("token_to_kill");
        verify(sessionService, times(1)).invalidateSession("token_to_kill");
    }

    // --- CAPTCHA Verification Tests ---

    @Test
    @DisplayName("When CAPTCHA is enabled and valid, login proceeds to OTP check")
    void login_CaptchaEnabled_ValidToken_Success() {
        AuthLoginRequest request = new AuthLoginRequest("validuser", "correctPass", "valid_captcha_token");
        OtpChallenge mockChallenge = new OtpChallenge("ch-1234", sampleUser, "$2a$10$hash",
                LocalDateTime.now(), LocalDateTime.now().plusMinutes(5));

        when(captchaService.isCaptchaEnabled()).thenReturn(true);
        doNothing().when(captchaService).verifyCaptcha("valid_captcha_token", "192.168.1.10");

        when(otpService.isOtpEnabled()).thenReturn(true);
        when(userRepository.findByUsernameIgnoreCase("validuser")).thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("correctPass", "$2a$10$hashedPassword")).thenReturn(true);
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(otpService.createAndSendOtp(sampleUser)).thenReturn(mockChallenge);

        AuthResponse response = authService.login(request, "192.168.1.10");

        assertNotNull(response);
        assertTrue(response.isOtpRequired());
        verify(captchaService, times(1)).verifyCaptcha("valid_captcha_token", "192.168.1.10");
        verify(otpService, times(1)).createAndSendOtp(sampleUser);
    }

    @Test
    @DisplayName("When CAPTCHA is enabled and invalid, login is rejected and failure is audited")
    void login_CaptchaEnabled_InvalidToken_ThrowsException() {
        AuthLoginRequest request = new AuthLoginRequest("validuser", "correctPass", "bad_captcha_token");

        when(captchaService.isCaptchaEnabled()).thenReturn(true);
        doThrow(new InvalidCaptchaException("CAPTCHA verification failed. Please try again."))
                .when(captchaService).verifyCaptcha("bad_captcha_token", "192.168.1.10");
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(invocation -> invocation.getArgument(0));

        assertThrows(InvalidCaptchaException.class, () ->
                authService.login(request, "192.168.1.10")
        );

        // Verification: Failure must be audited in login attempts
        verify(loginAttemptRepository, times(1)).save(any(LoginAttempt.class));
        verify(userRepository, never()).findByUsernameIgnoreCase(anyString());
        verify(sessionService, never()).createSession(any(User.class));
    }

    @Test
    @DisplayName("When CAPTCHA is disabled, verifyCaptcha is never invoked")
    void login_CaptchaDisabled_DoesNotVerifyCaptcha() {
        AuthLoginRequest request = new AuthLoginRequest("validuser", "correctPass");
        UserSession mockSession = new UserSession(sampleUser, "session_token_xyz", LocalDateTime.now(), LocalDateTime.now(), LocalDateTime.now().plusMinutes(15));

        when(captchaService.isCaptchaEnabled()).thenReturn(false);
        when(otpService.isOtpEnabled()).thenReturn(false);
        when(userRepository.findByUsernameIgnoreCase("validuser")).thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("correctPass", "$2a$10$hashedPassword")).thenReturn(true);
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(sessionService.createSession(sampleUser)).thenReturn(mockSession);

        AuthResponse response = authService.login(request, "192.168.1.10");

        assertNotNull(response);
        verify(captchaService, never()).verifyCaptcha(anyString(), anyString());
    }

    @Test
    @DisplayName("Feature 2: Before reaching failure threshold (<3), login succeeds without CAPTCHA token")
    void login_CaptchaEnabled_BeforeThreshold_NoTokenProvided_Succeeds() {
        AuthLoginRequest request = new AuthLoginRequest("validuser", "correctPass"); // No captcha token
        OtpChallenge mockChallenge = new OtpChallenge("ch-1234", sampleUser, "$2a$10$hash",
                LocalDateTime.now(), LocalDateTime.now().plusMinutes(5));

        when(captchaService.isCaptchaEnabled()).thenReturn(true);
        // Only 2 prior failures in window (< threshold 3)
        when(loginAttemptRepository.countByIpAddressAndStatusSince(eq("192.168.1.10"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(2L);
        when(loginAttemptRepository.countByUsernameAndStatusSince(eq("validuser"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(2L);

        when(otpService.isOtpEnabled()).thenReturn(true);
        when(userRepository.findByUsernameIgnoreCase("validuser")).thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("correctPass", "$2a$10$hashedPassword")).thenReturn(true);
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(otpService.createAndSendOtp(sampleUser)).thenReturn(mockChallenge);

        AuthResponse response = authService.login(request, "192.168.1.10");

        assertNotNull(response);
        assertTrue(response.isOtpRequired());
        // Verify CAPTCHA verification was NOT enforced
        verify(captchaService, never()).verifyCaptcha(any(), any());
    }

    @Test
    @DisplayName("Feature 2: After reaching failure threshold (>=3), missing CAPTCHA token is rejected")
    void login_CaptchaEnabled_AtThreshold_MissingToken_ThrowsException() {
        AuthLoginRequest request = new AuthLoginRequest("validuser", "correctPass", null); // Missing token

        when(captchaService.isCaptchaEnabled()).thenReturn(true);
        // 3 prior failures from this IP (>= threshold 3)
        when(loginAttemptRepository.countByIpAddressAndStatusSince(eq("192.168.1.10"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(3L);
        when(loginAttemptRepository.countByUsernameAndStatusSince(eq("validuser"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(0L);
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(invocation -> invocation.getArgument(0));

        InvalidCaptchaException ex = assertThrows(InvalidCaptchaException.class, () ->
                authService.login(request, "192.168.1.10")
        );
        assertTrue(ex.getMessage().contains("CAPTCHA verification is required after repeated failed login attempts"));

        // Audit check: Failure must be recorded in login_attempts
        verify(loginAttemptRepository, times(1)).save(any(LoginAttempt.class));
        verify(userRepository, never()).findByUsernameIgnoreCase(anyString());
    }

    @Test
    @DisplayName("Feature 2: After reaching failure threshold (>=3), valid CAPTCHA token allows login")
    void login_CaptchaEnabled_AtThreshold_ValidToken_Succeeds() {
        AuthLoginRequest request = new AuthLoginRequest("validuser", "correctPass", "valid_recaptcha_v3_token");
        OtpChallenge mockChallenge = new OtpChallenge("ch-1234", sampleUser, "$2a$10$hash",
                LocalDateTime.now(), LocalDateTime.now().plusMinutes(5));

        when(captchaService.isCaptchaEnabled()).thenReturn(true);
        // 3 prior failures for this user (>= threshold 3)
        when(loginAttemptRepository.countByIpAddressAndStatusSince(eq("192.168.1.10"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(0L);
        when(loginAttemptRepository.countByUsernameAndStatusSince(eq("validuser"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(3L);
        doNothing().when(captchaService).verifyCaptcha("valid_recaptcha_v3_token", "192.168.1.10");

        when(otpService.isOtpEnabled()).thenReturn(true);
        when(userRepository.findByUsernameIgnoreCase("validuser")).thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("correctPass", "$2a$10$hashedPassword")).thenReturn(true);
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(otpService.createAndSendOtp(sampleUser)).thenReturn(mockChallenge);

        AuthResponse response = authService.login(request, "192.168.1.10");

        assertNotNull(response);
        assertTrue(response.isOtpRequired());
        verify(captchaService, times(1)).verifyCaptcha("valid_recaptcha_v3_token", "192.168.1.10");
    }

    @Test
    @DisplayName("Feature 2: isCaptchaRequired accurately evaluates IP and username failure thresholds")
    void isCaptchaRequired_EvaluatesThresholdsCorrectly() {
        when(captchaService.isCaptchaEnabled()).thenReturn(true);

        // Case 1: IP has 3 failures -> required
        when(loginAttemptRepository.countByIpAddressAndStatusSince(eq("192.168.1.10"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(3L);
        when(loginAttemptRepository.countByUsernameAndStatusSince(eq("userA"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(0L);
        assertTrue(authService.isCaptchaRequired("userA", "192.168.1.10"));

        // Case 2: Username has 3 failures -> required
        when(loginAttemptRepository.countByIpAddressAndStatusSince(eq("192.168.1.10"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(0L);
        when(loginAttemptRepository.countByUsernameAndStatusSince(eq("userA"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(3L);
        assertTrue(authService.isCaptchaRequired("userA", "192.168.1.10"));

        // Case 3: Both have 2 failures (<3) -> not required
        when(loginAttemptRepository.countByIpAddressAndStatusSince(eq("192.168.1.10"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(2L);
        when(loginAttemptRepository.countByUsernameAndStatusSince(eq("userA"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(2L);
        assertFalse(authService.isCaptchaRequired("userA", "192.168.1.10"));

        // Case 4: CAPTCHA disabled -> always false
        when(captchaService.isCaptchaEnabled()).thenReturn(false);
        assertFalse(authService.isCaptchaRequired("userA", "192.168.1.10"));
    }
}
