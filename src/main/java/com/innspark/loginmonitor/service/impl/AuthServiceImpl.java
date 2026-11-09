package com.innspark.loginmonitor.service.impl;

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
import com.innspark.loginmonitor.exception.AccountDisabledException;
import com.innspark.loginmonitor.exception.AuthenticationFailedException;
import com.innspark.loginmonitor.exception.InvalidCaptchaException;
import com.innspark.loginmonitor.repository.LoginAttemptRepository;
import com.innspark.loginmonitor.repository.UserRepository;
import com.innspark.loginmonitor.service.AuthService;
import com.innspark.loginmonitor.service.CaptchaService;
import com.innspark.loginmonitor.service.DetectionService;
import com.innspark.loginmonitor.service.OtpService;
import com.innspark.loginmonitor.service.RateLimiterService;
import com.innspark.loginmonitor.service.SessionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Service implementation executing real user authentication, rate limiting,
 * CAPTCHA protection, Two-Factor Authentication (OTP), login auditing, and session lifecycle management.
 */
@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessionService;
    private final RateLimiterService rateLimiterService;
    private final LoginAttemptRepository loginAttemptRepository;
    private final DetectionService detectionService;
    private final CaptchaService captchaService;
    private final OtpService otpService;

    @Value("${app.captcha.failure-threshold:3}")
    private int captchaFailureThreshold;

    @Value("${app.detection.window-minutes:10}")
    private int windowMinutes;

    public AuthServiceImpl(UserRepository userRepository,
                           PasswordEncoder passwordEncoder,
                           SessionService sessionService,
                           RateLimiterService rateLimiterService,
                           LoginAttemptRepository loginAttemptRepository,
                           DetectionService detectionService,
                           CaptchaService captchaService,
                           OtpService otpService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.sessionService = sessionService;
        this.rateLimiterService = rateLimiterService;
        this.loginAttemptRepository = loginAttemptRepository;
        this.detectionService = detectionService;
        this.captchaService = captchaService;
        this.otpService = otpService;
    }

    @Override
    public AuthResponse login(AuthLoginRequest request, String clientIp) {
        String finalIp = (clientIp != null && !clientIp.trim().isEmpty()) ? clientIp.trim() : "127.0.0.1";
        String username = request.getUsername().trim();

        // 1. Enforce in-memory rate limiting (max 5 attempts per 60s window per IP)
        rateLimiterService.checkRateLimit(finalIp);

        // 2. Enforce backend CAPTCHA verification when threshold of failed attempts is reached (or if token provided)
        if (captchaService.isCaptchaEnabled()) {
            boolean captchaRequired = isCaptchaRequired(username, finalIp);
            if (captchaRequired) {
                if (request.getCaptchaToken() == null || request.getCaptchaToken().trim().isEmpty()) {
                    log.warn("Login rejected: CAPTCHA required for user='{}', IP='{}' after exceeding failure threshold ({})",
                            username, finalIp, captchaFailureThreshold);
                    recordAttemptAndDetect(username, finalIp, LoginStatus.FAILURE);
                    throw new InvalidCaptchaException("CAPTCHA verification is required after repeated failed login attempts");
                }
                try {
                    captchaService.verifyCaptcha(request.getCaptchaToken(), finalIp);
                } catch (InvalidCaptchaException e) {
                    recordAttemptAndDetect(username, finalIp, LoginStatus.FAILURE);
                    throw e;
                }
            } else if (request.getCaptchaToken() != null && !request.getCaptchaToken().trim().isEmpty()) {
                // If token is provided before threshold (e.g. background v3 token), verify it
                try {
                    captchaService.verifyCaptcha(request.getCaptchaToken(), finalIp);
                } catch (InvalidCaptchaException e) {
                    recordAttemptAndDetect(username, finalIp, LoginStatus.FAILURE);
                    throw e;
                }
            }
        }

        // 3. Lookup registered user
        Optional<User> optionalUser = userRepository.findByUsernameIgnoreCase(username);

        // User does not exist -> record FAILURE, trigger detection, return generic 401
        if (optionalUser.isEmpty()) {
            recordAttemptAndDetect(username, finalIp, LoginStatus.FAILURE);
            log.warn("Login failed: username '{}' not found from IP '{}'", username, finalIp);
            throw new AuthenticationFailedException("Invalid username or password");
        }

        User user = optionalUser.get();

        // 4. Account is disabled -> record FAILURE, trigger detection, return 403
        if (!user.isEnabled()) {
            recordAttemptAndDetect(username, finalIp, LoginStatus.FAILURE);
            log.warn("Login rejected: account '{}' is disabled from IP '{}'", username, finalIp);
            throw new AccountDisabledException("Account is disabled. Please contact administrator.");
        }

        // 5. Verify submitted password against BCrypt hash
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            recordAttemptAndDetect(username, finalIp, LoginStatus.FAILURE);
            log.warn("Login failed: password mismatch for username '{}' from IP '{}'", username, finalIp);
            throw new AuthenticationFailedException("Invalid username or password");
        }

        // 6. Primary credentials valid -> Record SUCCESS audit
        recordAttemptAndDetect(username, finalIp, LoginStatus.SUCCESS);
        log.info("Primary credentials verified for user '{}' from IP '{}'", username, finalIp);

        // 7. Check if 2FA (OTP) is enabled (applies to ALL roles: USER, ADMIN, SUPERADMIN)
        if (otpService.isOtpEnabled()) {
            // Generate and send OTP via email. NO session is created at this stage.
            OtpChallenge challenge = otpService.createAndSendOtp(user);
            log.info("2FA OTP challenge initiated id='{}' for user '{}'", challenge.getChallengeId(), username);

            return AuthResponse.otpChallenge(
                    challenge.getChallengeId(),
                    user.getUsername(),
                    user.getRole(),
                    challenge.getExpiresAt()
            );
        }

        // 8. If OTP is disabled, fallback directly to creating a database session
        UserSession session = sessionService.createSession(user);
        return AuthResponse.authenticated(
                session.getSessionToken(),
                user.getUsername(),
                user.getRole(),
                session.getExpiresAt()
        );
    }

    @Override
    public AuthResponse verifyOtp(VerifyOtpRequest request, String clientIp) {
        String finalIp = (clientIp != null && !clientIp.trim().isEmpty()) ? clientIp.trim() : "127.0.0.1";

        // Rate limiting on OTP verification attempts
        rateLimiterService.checkRateLimit(finalIp);

        try {
            // Verify OTP challenge atomically
            User user = otpService.verifyOtp(request.getChallengeId(), request.getOtp(), finalIp);

            // Create database-backed user session upon successful 2FA
            UserSession session = sessionService.createSession(user);
            log.info("2FA completed successfully for user '{}'. Session created id='{}'", user.getUsername(), session.getId());

            return AuthResponse.authenticated(
                    session.getSessionToken(),
                    user.getUsername(),
                    user.getRole(),
                    session.getExpiresAt()
            );

        } catch (RuntimeException e) {
            // Audit failed OTP attempt to ensure visibility and trigger anomaly detection if brute forced
            recordAttemptAndDetect("2FA_ATTEMPT", finalIp, LoginStatus.FAILURE);
            throw e;
        }
    }

    @Override
    public ResendOtpResponse resendOtp(ResendOtpRequest request, String clientIp) {
        String finalIp = (clientIp != null && !clientIp.trim().isEmpty()) ? clientIp.trim() : "127.0.0.1";
        rateLimiterService.checkRateLimit(finalIp);
        return otpService.resendOtp(request.getChallengeId(), finalIp);
    }

    @Override
    public void logout(String sessionToken) {
        sessionService.invalidateSession(sessionToken);
    }

    @Override
    public boolean isCaptchaRequired(String username, String clientIp) {
        if (!captchaService.isCaptchaEnabled()) {
            return false;
        }

        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(windowMinutes);
        long ipFailures = (clientIp != null && !clientIp.trim().isEmpty())
                ? loginAttemptRepository.countByIpAddressAndStatusSince(clientIp.trim(), LoginStatus.FAILURE, windowStart)
                : 0;

        long userFailures = (username != null && !username.trim().isEmpty())
                ? loginAttemptRepository.countByUsernameAndStatusSince(username.trim(), LoginStatus.FAILURE, windowStart)
                : 0;

        return ipFailures >= captchaFailureThreshold || userFailures >= captchaFailureThreshold;
    }

    @Override
    public int getCaptchaFailureThreshold() {
        return captchaFailureThreshold;
    }

    /**
     * Records login attempt in MySQL login_attempts table and triggers immediate
     * suspicious activity detection rules (Brute Force IP, Brute Force User, Unusual Success).
     */
    private void recordAttemptAndDetect(String username, String ipAddress, LoginStatus status) {
        try {
            LoginAttempt attempt = new LoginAttempt(username, ipAddress, LocalDateTime.now(), status);
            LoginAttempt saved = loginAttemptRepository.save(attempt);
            detectionService.detectSuspiciousActivity(saved);
        } catch (Exception e) {
            log.error("Failed to record login attempt audit for user='{}': {}", username, e.getMessage(), e);
        }
    }
}
