package com.innspark.loginmonitor.service.impl;

import com.innspark.loginmonitor.entity.LoginAttempt;
import com.innspark.loginmonitor.entity.SuspiciousActivity;
import com.innspark.loginmonitor.enums.LoginStatus;
import com.innspark.loginmonitor.repository.LoginAttemptRepository;
import com.innspark.loginmonitor.repository.SuspiciousActivityRepository;
import com.innspark.loginmonitor.service.DetectionService;
import com.innspark.loginmonitor.service.EmailAlertService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Service implementation for suspicious login activity detection.
 * Implements Rule 1 (Brute Force by IP), Rule 2 (Brute Force by Username),
 * and Rule 3 (Unusual Success after Repeated Failures), complete with deduplication
 * and periodic background scanning.
 */
@Service
public class DetectionServiceImpl implements DetectionService {

    private static final Logger log = LoggerFactory.getLogger(DetectionServiceImpl.class);

    public static final String RULE_1_PREFIX = "Multiple failed login attempts from the same IP";
    public static final String RULE_1_REASON = "Multiple failed login attempts from the same IP within 10 minutes";

    public static final String RULE_2_PREFIX = "Multiple failed login attempts for the same username";
    public static final String RULE_2_REASON = "Multiple failed login attempts for the same username within 10 minutes";

    public static final String RULE_3_PREFIX = "Successful login following multiple failed attempts";
    public static final String RULE_3_REASON = "Successful login following multiple failed attempts within 10 minutes";

    private final LoginAttemptRepository loginAttemptRepository;
    private final SuspiciousActivityRepository suspiciousActivityRepository;
    private final EmailAlertService emailAlertService;

    @Value("${app.detection.window-minutes:10}")
    private int windowMinutes;

    @Value("${app.detection.ip-failure-threshold:5}")
    private int ipFailureThreshold;

    @Value("${app.detection.user-failure-threshold:5}")
    private int userFailureThreshold;

    @Value("${app.detection.unusual-success-failure-threshold:3}")
    private int unusualSuccessThreshold;

    public DetectionServiceImpl(LoginAttemptRepository loginAttemptRepository,
                                SuspiciousActivityRepository suspiciousActivityRepository,
                                EmailAlertService emailAlertService) {
        this.loginAttemptRepository = loginAttemptRepository;
        this.suspiciousActivityRepository = suspiciousActivityRepository;
        this.emailAlertService = emailAlertService;
    }

    @Override
    @Transactional
    public void detectSuspiciousActivity(LoginAttempt attempt) {
        if (attempt == null) {
            return;
        }

        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(windowMinutes);

        if (attempt.getStatus() == LoginStatus.FAILURE) {
            checkRule1BruteForceByIp(attempt.getIpAddress(), attempt.getUsername(), windowStart);
            checkRule2BruteForceByUsername(attempt.getUsername(), attempt.getIpAddress(), windowStart);
        } else if (attempt.getStatus() == LoginStatus.SUCCESS) {
            checkRule3UnusualSuccess(attempt.getUsername(), attempt.getIpAddress(), attempt.getId(), windowStart);
        }
    }

    /**
     * Detection Rule 1: Brute Force by IP
     * Detects when failed logins from the same IP within the time window reach or exceed threshold.
     */
    private void checkRule1BruteForceByIp(String ipAddress, String username, LocalDateTime windowStart) {
        if (ipAddress == null || ipAddress.trim().isEmpty()) {
            return;
        }

        long failureCount = loginAttemptRepository.countByIpAddressAndStatusSince(
                ipAddress, LoginStatus.FAILURE, windowStart
        );

        if (failureCount >= ipFailureThreshold) {
            // Deduplication: check if already reported for this IP within window
            boolean alreadyLogged = suspiciousActivityRepository.existsByIpAddressAndReasonPrefixSince(
                    ipAddress, RULE_1_PREFIX, windowStart
            );

            if (!alreadyLogged) {
                SuspiciousActivity activity = new SuspiciousActivity(
                        ipAddress,
                        username,
                        RULE_1_REASON,
                        LocalDateTime.now()
                );
                saveAndAlert(activity);
                log.warn("SUSPICIOUS DETECTED [RULE 1 - Brute Force IP]: IP='{}', Failures={}, Window={} mins",
                        ipAddress, failureCount, windowMinutes);
            }
        }
    }

    /**
     * Detection Rule 2: Brute Force by Username
     * Detects when failed logins against the same username within the time window reach or exceed threshold.
     */
    private void checkRule2BruteForceByUsername(String username, String ipAddress, LocalDateTime windowStart) {
        if (username == null || username.trim().isEmpty()) {
            return;
        }

        long failureCount = loginAttemptRepository.countByUsernameAndStatusSince(
                username, LoginStatus.FAILURE, windowStart
        );

        if (failureCount >= userFailureThreshold) {
            // Deduplication: check if already reported for this username within window
            boolean alreadyLogged = suspiciousActivityRepository.existsByUsernameAndReasonPrefixSince(
                    username, RULE_2_PREFIX, windowStart
            );

            if (!alreadyLogged) {
                SuspiciousActivity activity = new SuspiciousActivity(
                        ipAddress,
                        username,
                        RULE_2_REASON,
                        LocalDateTime.now()
                );
                saveAndAlert(activity);
                log.warn("SUSPICIOUS DETECTED [RULE 2 - Brute Force Username]: User='{}', Failures={}, Window={} mins",
                        username, failureCount, windowMinutes);
            }
        }
    }

    /**
     * Detection Rule 3: Unusual Success After Failures
     * Detects a successful login that immediately follows multiple failures within the time window.
     */
    private void checkRule3UnusualSuccess(String username, String ipAddress, Long currentAttemptId, LocalDateTime windowStart) {
        if (username == null || username.trim().isEmpty()) {
            return;
        }

        List<LoginAttempt> recentAttempts = loginAttemptRepository.findRecentAttemptsByUsername(username, windowStart);

        int consecutiveFailuresBeforeSuccess = 0;
        for (LoginAttempt attempt : recentAttempts) {
            // Skip the current successful attempt itself
            if (currentAttemptId != null && currentAttemptId.equals(attempt.getId())) {
                continue;
            }

            if (attempt.getStatus() == LoginStatus.FAILURE) {
                consecutiveFailuresBeforeSuccess++;
            } else {
                // Encountered an earlier success, stop counting consecutive failures
                break;
            }
        }

        if (consecutiveFailuresBeforeSuccess >= unusualSuccessThreshold) {
            // Deduplication: check if already reported for this username within window
            boolean alreadyLogged = suspiciousActivityRepository.existsByUsernameAndReasonPrefixSince(
                    username, RULE_3_PREFIX, windowStart
            );

            if (!alreadyLogged) {
                SuspiciousActivity activity = new SuspiciousActivity(
                        ipAddress,
                        username,
                        RULE_3_REASON,
                        LocalDateTime.now()
                );
                saveAndAlert(activity);
                log.warn("SUSPICIOUS DETECTED [RULE 3 - Unusual Success]: User='{}', Prior Failures={}, Window={} mins",
                        username, consecutiveFailuresBeforeSuccess, windowMinutes);
            }
        }
    }

    /**
     * Periodic background scan for suspicious activity.
     * Runs at the configured interval (default 60s).
     * Wrapped in a try-catch block so transient errors do not abort the scheduler.
     */
    @Override
    @Scheduled(fixedDelayString = "${app.detection.scan-interval-seconds:60}000", initialDelay = 10000)
    @Transactional
    public void runScheduledScan() {
        try {
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime windowStart = now.minusMinutes(windowMinutes);

            // Scan Rule 1: IPs with failures >= threshold strictly between windowStart and now
            List<String> suspiciousIps = loginAttemptRepository.findIpsWithFailureCountExceeding(
                    LoginStatus.FAILURE, windowStart, now, ipFailureThreshold
            );
            for (String ip : suspiciousIps) {
                if (ip == null || ip.trim().isEmpty() || "N/A".equalsIgnoreCase(ip.trim())) {
                    continue;
                }
                if (!suspiciousActivityRepository.existsByIpAddressAndReasonPrefixSince(ip, RULE_1_PREFIX, windowStart)) {
                    SuspiciousActivity activity = new SuspiciousActivity(ip, null, RULE_1_REASON, now);
                    saveAndAlert(activity);
                    log.warn("SCHEDULED SCAN: Flagged suspicious IP='{}'", ip);
                }
            }

            // Scan Rule 2: Usernames with failures >= threshold strictly between windowStart and now
            List<String> suspiciousUsers = loginAttemptRepository.findUsernamesWithFailureCountExceeding(
                    LoginStatus.FAILURE, windowStart, now, userFailureThreshold
            );
            for (String user : suspiciousUsers) {
                if (user == null || user.trim().isEmpty()) {
                    continue;
                }
                if (!suspiciousActivityRepository.existsByUsernameAndReasonPrefixSince(user, RULE_2_PREFIX, windowStart)) {
                    SuspiciousActivity activity = new SuspiciousActivity("N/A", user, RULE_2_REASON, now);
                    saveAndAlert(activity);
                    log.warn("SCHEDULED SCAN: Flagged suspicious Username='{}'", user);
                }
            }
        } catch (Exception e) {
            log.error("Error occurred during scheduled detection scan: {}", e.getMessage(), e);
        }
    }

    /**
     * Persists the suspicious activity entity and dispatches an email alert if enabled.
     */
    private void saveAndAlert(SuspiciousActivity activity) {
        SuspiciousActivity saved = suspiciousActivityRepository.save(activity);
        emailAlertService.sendSuspiciousActivityAlert(saved);
    }
}
