package com.innspark.loginmonitor.service.impl;

import com.innspark.loginmonitor.dto.ResendOtpResponse;
import com.innspark.loginmonitor.entity.OtpChallenge;
import com.innspark.loginmonitor.entity.User;
import com.innspark.loginmonitor.enums.OtpChallengeStatus;
import com.innspark.loginmonitor.exception.AccountDisabledException;
import com.innspark.loginmonitor.exception.InvalidOtpException;
import com.innspark.loginmonitor.exception.OtpCooldownException;
import com.innspark.loginmonitor.exception.OtpExpiredException;
import com.innspark.loginmonitor.exception.OtpMaxAttemptsExceededException;
import com.innspark.loginmonitor.repository.OtpChallengeRepository;
import com.innspark.loginmonitor.service.OtpEmailService;
import com.innspark.loginmonitor.service.OtpService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service implementation managing OTP 2FA challenge creation, hashing, verification, and resend.
 *
 * Security Policies:
 * 1. Cryptographically secure 6-digit OTP generation using SecureRandom.
 * 2. OTP plaintext is NEVER stored in database or written to logs. Only BCrypt hashes are retained.
 * 3. Strict single-use policy: challenges are marked VERIFIED atomically upon first valid submission.
 * 4. Concurrency protected using pessimistic write locking during verification.
 * 5. Cooldowns and attempt limits prevent brute force and resend spam.
 */
@Service
public class OtpServiceImpl implements OtpService {

    private static final Logger log = LoggerFactory.getLogger(OtpServiceImpl.class);

    private final OtpChallengeRepository otpChallengeRepository;
    private final OtpEmailService otpEmailService;
    private final PasswordEncoder passwordEncoder;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${app.otp.enabled:true}")
    private boolean otpEnabled;

    @Value("${app.otp.expiration-minutes:5}")
    private int expirationMinutes;

    @Value("${app.otp.max-attempts:5}")
    private int maxAttempts;

    @Value("${app.otp.resend-cooldown-seconds:60}")
    private int resendCooldownSeconds;

    @Value("${app.otp.max-resends:3}")
    private int maxResends;

    public OtpServiceImpl(OtpChallengeRepository otpChallengeRepository,
                          OtpEmailService otpEmailService,
                          PasswordEncoder passwordEncoder) {
        this.otpChallengeRepository = otpChallengeRepository;
        this.otpEmailService = otpEmailService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public boolean isOtpEnabled() {
        return otpEnabled;
    }

    @Override
    @Transactional
    public OtpChallenge createAndSendOtp(User user) {
        String rawOtp = generateNumericOtp();
        String otpHash = passwordEncoder.encode(rawOtp);
        String challengeId = UUID.randomUUID().toString();

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiresAt = now.plusMinutes(expirationMinutes);

        OtpChallenge challenge = new OtpChallenge(challengeId, user, otpHash, now, expiresAt);
        OtpChallenge saved = otpChallengeRepository.save(challenge);

        // Send OTP email - if delivery fails, OtpDeliveryException is thrown and transaction rolls back
        otpEmailService.sendOtpEmail(user.getEmail(), user.getUsername(), rawOtp, expirationMinutes);

        log.info("Created and dispatched OTP challenge id='{}' for user='{}'", challengeId, user.getUsername());
        return saved;
    }

    @Override
    @Transactional
    public User verifyOtp(String challengeId, String otpCode, String clientIp) {
        if (challengeId == null || challengeId.trim().isEmpty()) {
            throw new InvalidOtpException("Challenge ID is required");
        }
        if (otpCode == null || otpCode.trim().isEmpty()) {
            throw new InvalidOtpException("OTP code is required");
        }

        // Retrieve challenge using pessimistic write lock to prevent concurrent verification races
        OtpChallenge challenge = otpChallengeRepository.findByChallengeIdWithLock(challengeId.trim())
                .orElseThrow(() -> {
                    log.warn("OTP verification failed: unknown challenge ID '{}' from IP '{}'", challengeId, clientIp);
                    return new InvalidOtpException("Invalid or unrecognized OTP challenge");
                });

        User user = challenge.getUser();

        // 1. Check account status
        if (!user.isEnabled()) {
            log.warn("OTP verification rejected: account '{}' is disabled from IP '{}'", user.getUsername(), clientIp);
            throw new AccountDisabledException("Account is disabled. Please contact administrator.");
        }

        // 2. Check challenge status
        if (challenge.getStatus() != OtpChallengeStatus.PENDING) {
            log.warn("OTP verification rejected: challenge '{}' has non-pending status '{}'", challengeId, challenge.getStatus());
            throw new InvalidOtpException("OTP challenge has already been used or is invalid. Please login again.");
        }

        // 3. Check expiration
        if (challenge.isExpired()) {
            challenge.setStatus(OtpChallengeStatus.EXPIRED);
            otpChallengeRepository.save(challenge);
            log.warn("OTP verification rejected: challenge '{}' expired at '{}'", challengeId, challenge.getExpiresAt());
            throw new OtpExpiredException("OTP code has expired. Please initiate a new login or request a resend.");
        }

        // 4. Check max failed attempts
        if (challenge.getFailedAttempts() >= maxAttempts) {
            challenge.setStatus(OtpChallengeStatus.FAILED);
            otpChallengeRepository.save(challenge);
            log.warn("OTP verification rejected: challenge '{}' exceeded max attempts ({})", challengeId, maxAttempts);
            throw new OtpMaxAttemptsExceededException("Maximum OTP verification attempts exceeded. Please initiate a new login.");
        }

        // 5. Verify submitted OTP using constant-time/BCrypt comparison
        if (!passwordEncoder.matches(otpCode.trim(), challenge.getOtpHash())) {
            challenge.setFailedAttempts(challenge.getFailedAttempts() + 1);
            if (challenge.getFailedAttempts() >= maxAttempts) {
                challenge.setStatus(OtpChallengeStatus.FAILED);
            }
            otpChallengeRepository.save(challenge);

            int remaining = Math.max(0, maxAttempts - challenge.getFailedAttempts());
            log.warn("Invalid OTP submitted for user='{}', challenge='{}'. Remaining attempts: {}",
                    user.getUsername(), challengeId, remaining);

            if (remaining == 0) {
                throw new OtpMaxAttemptsExceededException("Maximum OTP verification attempts exceeded. Please initiate a new login.");
            } else {
                throw new InvalidOtpException("Invalid OTP code. Remaining attempts: " + remaining);
            }
        }

        // 6. Verification successful: mark single-use VERIFIED
        challenge.setStatus(OtpChallengeStatus.VERIFIED);
        challenge.setVerifiedAt(LocalDateTime.now());
        otpChallengeRepository.save(challenge);

        log.info("OTP verification successful for user='{}', challenge='{}' from IP '{}'",
                user.getUsername(), challengeId, clientIp);

        return user;
    }

    @Override
    @Transactional
    public ResendOtpResponse resendOtp(String challengeId, String clientIp) {
        if (challengeId == null || challengeId.trim().isEmpty()) {
            throw new InvalidOtpException("Challenge ID is required");
        }

        OtpChallenge challenge = otpChallengeRepository.findByChallengeIdWithLock(challengeId.trim())
                .orElseThrow(() -> {
                    log.warn("OTP resend failed: challenge ID '{}' not found from IP '{}'", challengeId, clientIp);
                    return new InvalidOtpException("Invalid or unrecognized OTP challenge");
                });

        User user = challenge.getUser();

        if (!user.isEnabled()) {
            throw new AccountDisabledException("Account is disabled. Please contact administrator.");
        }

        if (challenge.getStatus() != OtpChallengeStatus.PENDING) {
            throw new InvalidOtpException("OTP challenge is no longer pending. Please initiate a new login.");
        }

        if (challenge.isExpired()) {
            challenge.setStatus(OtpChallengeStatus.EXPIRED);
            otpChallengeRepository.save(challenge);
            throw new OtpExpiredException("OTP challenge has expired. Please initiate a new login.");
        }

        // Check resend limits
        if (challenge.getResendCount() >= maxResends) {
            challenge.setStatus(OtpChallengeStatus.FAILED);
            otpChallengeRepository.save(challenge);
            log.warn("OTP resend rejected: challenge '{}' exceeded max resends ({})", challengeId, maxResends);
            throw new OtpMaxAttemptsExceededException("Maximum OTP resend limit reached. Please initiate a new login.");
        }

        // Enforce cooldown period
        LocalDateTime lastSentTime = challenge.getLastResentAt() != null
                ? challenge.getLastResentAt()
                : challenge.getCreatedAt();

        long secondsSince = Duration.between(lastSentTime, LocalDateTime.now()).getSeconds();
        if (secondsSince < resendCooldownSeconds) {
            long waitSeconds = resendCooldownSeconds - secondsSince;
            log.warn("OTP resend rejected due to cooldown for challenge '{}'. Seconds remaining: {}", challengeId, waitSeconds);
            throw new OtpCooldownException("Please wait " + waitSeconds + " seconds before requesting a new verification code.");
        }

        // Generate fresh OTP code and update challenge
        String newRawOtp = generateNumericOtp();
        challenge.setOtpHash(passwordEncoder.encode(newRawOtp));
        challenge.setExpiresAt(LocalDateTime.now().plusMinutes(expirationMinutes));
        challenge.setResendCount(challenge.getResendCount() + 1);
        challenge.setLastResentAt(LocalDateTime.now());
        challenge.setFailedAttempts(0); // reset failed attempts on fresh code dispatch

        otpChallengeRepository.save(challenge);

        // Send new OTP email
        otpEmailService.sendOtpEmail(user.getEmail(), user.getUsername(), newRawOtp, expirationMinutes);

        log.info("Dispatched new OTP for challenge '{}', user='{}' (resend count: {})",
                challengeId, user.getUsername(), challenge.getResendCount());

        return new ResendOtpResponse(
                challengeId,
                challenge.getExpiresAt(),
                "A new verification code has been sent to your registered email address."
        );
    }

    /**
     * Generates a cryptographically secure 6-digit numeric OTP code.
     */
    private String generateNumericOtp() {
        int code = 100000 + secureRandom.nextInt(900000);
        return String.valueOf(code);
    }

    /**
     * Periodic scheduled sweep to mark expired challenges.
     */
    @Scheduled(fixedRate = 300000)
    @Transactional
    public void cleanupExpiredChallenges() {
        try {
            int marked = otpChallengeRepository.markExpiredChallenges(LocalDateTime.now());
            if (marked > 0) {
                log.info("Scheduled cleanup: marked {} expired OTP challenges", marked);
            }
        } catch (Exception e) {
            log.error("Error during scheduled OTP challenge cleanup: {}", e.getMessage());
        }
    }
}
