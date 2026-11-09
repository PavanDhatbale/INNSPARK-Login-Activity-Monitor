package com.innspark.loginmonitor.controller;

import com.innspark.loginmonitor.dto.AuthLoginRequest;
import com.innspark.loginmonitor.dto.AuthResponse;
import com.innspark.loginmonitor.dto.MessageResponse;
import com.innspark.loginmonitor.dto.RegisterRequest;
import com.innspark.loginmonitor.dto.UserResponse;
import com.innspark.loginmonitor.service.AuthService;
import com.innspark.loginmonitor.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * Controller exposing authentication endpoints: registration, login, and logout.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final AuthService authService;

    public AuthController(UserService userService, AuthService authService) {
        this.userService = userService;
        this.authService = authService;
    }

    /**
     * POST /auth/register
     * Registers a new user account with BCrypt-hashed password.
     */
    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        UserResponse response = userService.registerUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * POST /auth/login
     * Authenticates a user using BCrypt, enforces rate limiting, audits login attempt,
     * and initiates 2FA OTP challenge (or generates active database session if 2FA disabled).
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthLoginRequest request,
                                              HttpServletRequest httpRequest) {
        String clientIp = extractClientIp(httpRequest);
        AuthResponse response = authService.login(request, clientIp);
        return ResponseEntity.ok(response);
    }

    /**
     * POST /auth/verify-otp
     * Completes Step 2 of 2FA: verifies submitted 6-digit OTP code against the active challenge
     * and creates the authenticated database session upon success.
     */
    @PostMapping("/verify-otp")
    public ResponseEntity<AuthResponse> verifyOtp(@Valid @RequestBody com.innspark.loginmonitor.dto.VerifyOtpRequest request,
                                                  HttpServletRequest httpRequest) {
        String clientIp = extractClientIp(httpRequest);
        AuthResponse response = authService.verifyOtp(request, clientIp);
        return ResponseEntity.ok(response);
    }

    /**
     * POST /auth/resend-otp
     * Dispatches a fresh 6-digit OTP code to the registered email address,
     * enforcing rate limiting, resend cooldown, and maximum resend limits.
     */
    @PostMapping("/resend-otp")
    public ResponseEntity<com.innspark.loginmonitor.dto.ResendOtpResponse> resendOtp(
            @Valid @RequestBody com.innspark.loginmonitor.dto.ResendOtpRequest request,
            HttpServletRequest httpRequest) {
        String clientIp = extractClientIp(httpRequest);
        com.innspark.loginmonitor.dto.ResendOtpResponse response = authService.resendOtp(request, clientIp);
        return ResponseEntity.ok(response);
    }

    /**
     * GET /auth/captcha-status
     * Returns whether CAPTCHA verification is required for the client IP or target username.
     * Public endpoint to aid client transparency and testing.
     */
    @GetMapping("/captcha-status")
    public ResponseEntity<java.util.Map<String, Object>> getCaptchaStatus(
            @org.springframework.web.bind.annotation.RequestParam(required = false) String username,
            HttpServletRequest httpRequest) {
        String clientIp = extractClientIp(httpRequest);
        boolean required = authService.isCaptchaRequired(username, clientIp);
        return ResponseEntity.ok(java.util.Map.of(
                "captchaRequired", required,
                "failureThreshold", authService.getCaptchaFailureThreshold()
        ));
    }

    /**
     * GET /auth/me
     * Returns profile information for the currently authenticated user.
     * Identity is derived strictly from the validated session in SecurityContext.
     */
    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser(Principal principal) {
        if (principal == null || principal.getName() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        UserResponse profile = userService.getCurrentUserProfile(principal.getName());
        return ResponseEntity.ok(profile);
    }

    /**
     * POST /auth/logout
     * Invalidates the active session token.
     */
    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestHeader(value = "X-Session-Token", required = false) String sessionHeader) {

        String token = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7).trim();
        } else if (sessionHeader != null && !sessionHeader.trim().isEmpty()) {
            token = sessionHeader.trim();
        }

        if (token != null) {
            authService.logout(token);
        }

        return ResponseEntity.ok(new MessageResponse("Logged out successfully"));
    }

    /**
     * Extracts client IP address from HTTP request.
     */
    private String extractClientIp(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (remoteAddr == null || "127.0.0.1".equals(remoteAddr) || "0:0:0:0:0:0:0:1".equals(remoteAddr)) {
            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.trim().isEmpty() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
                return xForwardedFor.split(",")[0].trim();
            }
        }
        if ("0:0:0:0:0:0:0:1".equals(remoteAddr)) {
            return "127.0.0.1";
        }
        return (remoteAddr != null && !remoteAddr.trim().isEmpty()) ? remoteAddr : "127.0.0.1";
    }
}
