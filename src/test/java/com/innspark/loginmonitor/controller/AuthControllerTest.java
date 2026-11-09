package com.innspark.loginmonitor.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innspark.loginmonitor.dto.AuthLoginRequest;
import com.innspark.loginmonitor.dto.AuthResponse;
import com.innspark.loginmonitor.dto.RegisterRequest;
import com.innspark.loginmonitor.dto.UserResponse;
import com.innspark.loginmonitor.dto.ResendOtpRequest;
import com.innspark.loginmonitor.dto.ResendOtpResponse;
import com.innspark.loginmonitor.dto.VerifyOtpRequest;
import com.innspark.loginmonitor.enums.Role;
import com.innspark.loginmonitor.exception.AccountDisabledException;
import com.innspark.loginmonitor.exception.AuthenticationFailedException;
import com.innspark.loginmonitor.exception.GlobalExceptionHandler;
import com.innspark.loginmonitor.exception.InvalidOtpException;
import com.innspark.loginmonitor.exception.OtpCooldownException;
import com.innspark.loginmonitor.exception.OtpExpiredException;
import com.innspark.loginmonitor.exception.OtpMaxAttemptsExceededException;
import com.innspark.loginmonitor.exception.TooManyRequestsException;
import com.innspark.loginmonitor.service.AuthService;
import com.innspark.loginmonitor.service.UserService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(GlobalExceptionHandler.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private UserService userService;

    @MockBean
    private AuthService authService;

    // --- Registration Tests ---

    @Test
    @DisplayName("POST /auth/register successfully returns 201 Created and UserResponse")
    void register_Success() throws Exception {
        RegisterRequest request = new RegisterRequest("alice", "alice@example.com", "password123");
        UserResponse response = new UserResponse(10L, "alice", "alice@example.com", Role.USER, true, LocalDateTime.now());

        when(userService.registerUser(any(RegisterRequest.class))).thenReturn(response);

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(10L))
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.email").value("alice@example.com"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.enabled").value(true));
    }

    @Test
    @DisplayName("POST /auth/register with missing username returns 400 Bad Request")
    void register_MissingUsername() throws Exception {
        RegisterRequest request = new RegisterRequest("", "alice@example.com", "password123");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.validationErrors.username").exists());
    }

    @Test
    @DisplayName("POST /auth/register with invalid email format returns 400 Bad Request")
    void register_InvalidEmail() throws Exception {
        RegisterRequest request = new RegisterRequest("alice", "not-an-email", "password123");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.validationErrors.email").exists());
    }

    @Test
    @DisplayName("POST /auth/register with password under 6 characters returns 400 Bad Request")
    void register_ShortPassword() throws Exception {
        RegisterRequest request = new RegisterRequest("alice", "alice@example.com", "12345");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.validationErrors.password").exists());
    }

    @Test
    @DisplayName("POST /auth/register with duplicate username returns 400 Bad Request")
    void register_DuplicateUsername() throws Exception {
        RegisterRequest request = new RegisterRequest("existinguser", "alice@example.com", "password123");

        when(userService.registerUser(any(RegisterRequest.class)))
                .thenThrow(new IllegalArgumentException("Username 'existinguser' is already taken"));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("Username 'existinguser' is already taken"));
    }

    @Test
    @DisplayName("POST /auth/register with privileged role attempt returns 400 Bad Request")
    void register_RejectPrivilegedRole() throws Exception {
        RegisterRequest request = new RegisterRequest("badactor", "bad@example.com", "password123", Role.ADMIN);

        when(userService.registerUser(any(RegisterRequest.class)))
                .thenThrow(new IllegalArgumentException("Self-registration as ADMIN is not permitted. Only USER registration is allowed."));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("Self-registration as ADMIN is not permitted. Only USER registration is allowed."));
    }

    // --- Authentication Tests (POST /auth/login) ---

    @Test
    @DisplayName("POST /auth/login valid credentials returns 200 OK and AuthResponse")
    void login_Success() throws Exception {
        AuthLoginRequest request = new AuthLoginRequest("john_doe", "password123");
        AuthResponse response = new AuthResponse("session_token_123", "john_doe", Role.USER, LocalDateTime.now().plusMinutes(15), "Login successful");

        when(authService.login(any(AuthLoginRequest.class), anyString())).thenReturn(response);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sessionToken").value("session_token_123"))
                .andExpect(jsonPath("$.username").value("john_doe"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.message").value("Login successful"));
    }

    @Test
    @DisplayName("POST /auth/login invalid credentials returns 401 Unauthorized")
    void login_InvalidCredentials() throws Exception {
        AuthLoginRequest request = new AuthLoginRequest("john_doe", "wrongpass");

        when(authService.login(any(AuthLoginRequest.class), anyString()))
                .thenThrow(new AuthenticationFailedException("Invalid username or password"));

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message").value("Invalid username or password"));
    }

    @Test
    @DisplayName("POST /auth/login disabled account returns 403 Forbidden")
    void login_DisabledAccount() throws Exception {
        AuthLoginRequest request = new AuthLoginRequest("disabled_user", "password123");

        when(authService.login(any(AuthLoginRequest.class), anyString()))
                .thenThrow(new AccountDisabledException("Account is disabled. Please contact administrator."));

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.message").value("Account is disabled. Please contact administrator."));
    }

    @Test
    @DisplayName("POST /auth/login rate limit exceeded returns 429 Too Many Requests")
    void login_RateLimited() throws Exception {
        AuthLoginRequest request = new AuthLoginRequest("john_doe", "password123");

        when(authService.login(any(AuthLoginRequest.class), anyString()))
                .thenThrow(new TooManyRequestsException("Rate limit exceeded. Maximum 5 login attempts allowed per 60 seconds."));

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.error").value("Too Many Requests"))
                .andExpect(jsonPath("$.message").value("Rate limit exceeded. Maximum 5 login attempts allowed per 60 seconds."));
    }

    @Test
    @DisplayName("POST /auth/login missing username returns 400 Bad Request")
    void login_MissingUsername() throws Exception {
        AuthLoginRequest request = new AuthLoginRequest("", "password123");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.validationErrors.username").exists());
    }

    @Test
    @DisplayName("POST /auth/login missing password returns 400 Bad Request")
    void login_MissingPassword() throws Exception {
        AuthLoginRequest request = new AuthLoginRequest("john_doe", "");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.validationErrors.password").exists());
    }

    // --- Logout Tests (POST /auth/logout) ---

    @Test
    @DisplayName("POST /auth/logout with Bearer token invalidates session and returns 200 OK")
    void logout_Success() throws Exception {
        doNothing().when(authService).logout("sample_token_xyz");

        mockMvc.perform(post("/auth/logout")
                        .header("Authorization", "Bearer sample_token_xyz"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logged out successfully"));

        verify(authService, times(1)).logout("sample_token_xyz");
    }

    // --- Profile Tests (GET /auth/me) ---

    @Test
    @DisplayName("GET /auth/me returns 200 OK and safe UserResponse for authenticated user")
    void getMe_Success() throws Exception {
        UserResponse response = new UserResponse(1L, "alice", "alice@example.com", Role.USER, true, LocalDateTime.now());
        when(userService.getCurrentUserProfile("alice")).thenReturn(response);

        mockMvc.perform(get("/auth/me")
                        .principal(() -> "alice"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.email").value("alice@example.com"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.enabled").value(true));

        verify(userService, times(1)).getCurrentUserProfile("alice");
    }

    @Test
    @DisplayName("GET /auth/me returns 401 Unauthorized when unauthenticated")
    void getMe_Unauthenticated() throws Exception {
        mockMvc.perform(get("/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /auth/me returns 403 Forbidden when account is disabled")
    void getMe_DisabledAccount() throws Exception {
        when(userService.getCurrentUserProfile("disabled_user"))
                .thenThrow(new AccountDisabledException("Account is disabled. Please contact administrator."));

        mockMvc.perform(get("/auth/me")
                        .principal(() -> "disabled_user"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.message").value("Account is disabled. Please contact administrator."));
    }

    // --- 2FA / OTP Endpoint Tests (Phase 3.2) ---

    @Test
    @DisplayName("POST /auth/verify-otp with valid code returns 200 OK and authenticated session")
    void verifyOtp_Success() throws Exception {
        VerifyOtpRequest request = new VerifyOtpRequest("ch-1234", "123456");
        AuthResponse response = AuthResponse.authenticated("session_token_xyz", "alice", Role.USER, LocalDateTime.now().plusMinutes(15));

        when(authService.verifyOtp(any(VerifyOtpRequest.class), anyString())).thenReturn(response);

        mockMvc.perform(post("/auth/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.otpRequired").value(false))
                .andExpect(jsonPath("$.sessionToken").value("session_token_xyz"))
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    @DisplayName("POST /auth/verify-otp with non-numeric or non-6-digit code returns 400 Bad Request")
    void verifyOtp_InvalidCodeFormat() throws Exception {
        VerifyOtpRequest request = new VerifyOtpRequest("ch-1234", "12abc");

        mockMvc.perform(post("/auth/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.validationErrors.otp").exists());
    }

    @Test
    @DisplayName("POST /auth/verify-otp with missing challenge ID returns 400 Bad Request")
    void verifyOtp_MissingChallengeId() throws Exception {
        VerifyOtpRequest request = new VerifyOtpRequest("", "123456");

        mockMvc.perform(post("/auth/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.validationErrors.challengeId").exists());
    }

    @Test
    @DisplayName("POST /auth/verify-otp with wrong code returns 400 Bad Request")
    void verifyOtp_WrongCode_Returns400() throws Exception {
        VerifyOtpRequest request = new VerifyOtpRequest("ch-1234", "999999");

        when(authService.verifyOtp(any(VerifyOtpRequest.class), anyString()))
                .thenThrow(new InvalidOtpException("Invalid OTP code. Remaining attempts: 4"));

        mockMvc.perform(post("/auth/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Invalid OTP"))
                .andExpect(jsonPath("$.message").value("Invalid OTP code. Remaining attempts: 4"));
    }

    @Test
    @DisplayName("POST /auth/verify-otp on expired challenge returns 400 Bad Request")
    void verifyOtp_Expired_Returns400() throws Exception {
        VerifyOtpRequest request = new VerifyOtpRequest("ch-1234", "123456");

        when(authService.verifyOtp(any(VerifyOtpRequest.class), anyString()))
                .thenThrow(new OtpExpiredException("OTP code has expired. Please initiate a new login or request a resend."));

        mockMvc.perform(post("/auth/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("OTP Expired"));
    }

    @Test
    @DisplayName("POST /auth/verify-otp exceeding max attempts returns 429 Too Many Requests")
    void verifyOtp_MaxAttempts_Returns429() throws Exception {
        VerifyOtpRequest request = new VerifyOtpRequest("ch-1234", "999999");

        when(authService.verifyOtp(any(VerifyOtpRequest.class), anyString()))
                .thenThrow(new OtpMaxAttemptsExceededException("Maximum OTP verification attempts exceeded. Please initiate a new login."));

        mockMvc.perform(post("/auth/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.error").value("Too Many Attempts"));
    }

    @Test
    @DisplayName("POST /auth/resend-otp valid request returns 200 OK")
    void resendOtp_Success() throws Exception {
        ResendOtpRequest request = new ResendOtpRequest("ch-1234");
        ResendOtpResponse response = new ResendOtpResponse("ch-1234", LocalDateTime.now().plusMinutes(5), "A new verification code has been sent.");

        when(authService.resendOtp(any(ResendOtpRequest.class), anyString())).thenReturn(response);

        mockMvc.perform(post("/auth/resend-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challengeId").value("ch-1234"))
                .andExpect(jsonPath("$.message").value("A new verification code has been sent."));
    }

    @Test
    @DisplayName("POST /auth/resend-otp within cooldown returns 429 Too Many Requests")
    void resendOtp_Cooldown_Returns429() throws Exception {
        ResendOtpRequest request = new ResendOtpRequest("ch-1234");

        when(authService.resendOtp(any(ResendOtpRequest.class), anyString()))
                .thenThrow(new OtpCooldownException("Please wait 45 seconds before requesting a new verification code."));

        mockMvc.perform(post("/auth/resend-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.error").value("Rate Limit Exceeded"));
    }

    // --- CAPTCHA Status Tests ---

    @Test
    @DisplayName("GET /auth/captcha-status returns captcha requirements and threshold")
    void getCaptchaStatus_Success() throws Exception {
        when(authService.isCaptchaRequired(eq("testuser"), anyString())).thenReturn(true);
        when(authService.getCaptchaFailureThreshold()).thenReturn(3);

        mockMvc.perform(get("/auth/captcha-status")
                        .param("username", "testuser"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.captchaRequired").value(true))
                .andExpect(jsonPath("$.failureThreshold").value(3));
    }
}
