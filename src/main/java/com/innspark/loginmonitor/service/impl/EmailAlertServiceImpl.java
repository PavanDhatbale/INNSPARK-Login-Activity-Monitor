package com.innspark.loginmonitor.service.impl;

import com.innspark.loginmonitor.entity.SuspiciousActivity;
import com.innspark.loginmonitor.entity.User;
import com.innspark.loginmonitor.repository.UserRepository;
import com.innspark.loginmonitor.service.EmailAlertService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Service implementation for delivering security alert emails via SMTP.
 *
 * Implements assignment requirements:
 * 1. Admin Notification: Notifies when an IP address has triggered suspicious activity or brute force attacks.
 * 2. User Notification: When a specific account is involved in suspicious login attempts, notifies the user.
 *
 * Security & Reliability Policies:
 * 1. Disabled by default; zero SMTP connections made when disabled.
 * 2. Fail-safe: SMTP delivery failures are caught and logged as warnings/errors without throwing exceptions,
 *    guaranteeing that authentication, login attempts, and scheduled scanner operations are never disrupted.
 * 3. Never includes passwords, BCrypt hashes, session tokens, or SMTP credentials.
 */
@Service
public class EmailAlertServiceImpl implements EmailAlertService {

    private static final Logger log = LoggerFactory.getLogger(EmailAlertServiceImpl.class);

    private final Optional<JavaMailSender> mailSender;
    private final Optional<UserRepository> userRepository;

    @Value("${app.alerts.email.enabled:false}")
    private boolean emailEnabled;

    @Value("${app.alerts.email.admin-recipient:}")
    private String adminRecipient;

    @Value("${app.alerts.email.from:noreply@innspark.com}")
    private String mailFrom;

    @org.springframework.beans.factory.annotation.Autowired
    public EmailAlertServiceImpl(Optional<JavaMailSender> mailSender, Optional<UserRepository> userRepository) {
        this.mailSender = mailSender;
        this.userRepository = userRepository;
    }

    public EmailAlertServiceImpl(Optional<JavaMailSender> mailSender) {
        this(mailSender, Optional.empty());
    }

    @Override
    public boolean isEmailAlertEnabled() {
        return emailEnabled;
    }

    @Override
    public void sendSuspiciousActivityAlert(SuspiciousActivity activity) {
        if (!emailEnabled) {
            log.debug("Email alerts are disabled; skipping alert for activity id={}", activity != null ? activity.getId() : "null");
            return;
        }

        if (activity == null) {
            return;
        }

        if (mailSender.isEmpty()) {
            log.warn("Email alert skipped: JavaMailSender bean is not available");
            return;
        }

        String severity = resolveSeverity(activity.getReason());

        // 1. Send Administrator Notification
        sendAdminNotification(activity, severity);

        // 2. Send User Notification (if an individual registered account was involved)
        sendUserNotification(activity, severity);
    }

    /**
     * Dispatches notification email to system administrator.
     */
    private void sendAdminNotification(SuspiciousActivity activity, String severity) {
        if (adminRecipient == null || adminRecipient.trim().isEmpty()) {
            log.warn("Admin email alert skipped: admin recipient address is not configured");
            return;
        }

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(mailFrom);
            message.setTo(adminRecipient.trim());
            message.setSubject(String.format("[SECURITY ALERT - %s] Suspicious Login Activity Detected", severity));

            String targetUser = (activity.getUsername() != null && !activity.getUsername().trim().isEmpty() && !"N/A".equalsIgnoreCase(activity.getUsername().trim()))
                    ? activity.getUsername().trim()
                    : "N/A (IP-wide attack)";

            String body = String.format(
                    """
                    SECURITY ALERT: Suspicious Login Activity Detected

                    Incident Severity: %s
                    Timestamp: %s
                    Originating IP: %s
                    Target Username: %s
                    Detection Reason: %s

                    Recommended Administrator Action:
                    Please inspect the system security audit logs immediately. If unauthorized activity is confirmed, consider blocking the originating IP address or securing the affected user account.

                    ---
                    INNSPARK Login Activity Monitor
                    """,
                    severity,
                    activity.getTimestamp(),
                    activity.getIpAddress(),
                    targetUser,
                    activity.getReason()
            );

            message.setText(body);
            mailSender.get().send(message);
            log.info("Security alert email delivered to admin '{}' for activity id={}", adminRecipient, activity.getId());

        } catch (Exception e) {
            // Fail-safe: log safely without crashing caller or leaking secrets
            log.error("Failed to send admin security alert email to '{}': {}", adminRecipient, e.getMessage());
        }
    }

    /**
     * Dispatches security notification to affected user if an existing account was targeted.
     */
    private void sendUserNotification(SuspiciousActivity activity, String severity) {
        String username = activity.getUsername();
        if (username == null || username.trim().isEmpty() || "N/A".equalsIgnoreCase(username.trim())) {
            return;
        }

        if (userRepository.isEmpty()) {
            return;
        }

        try {
            Optional<User> userOpt = userRepository.get().findByUsernameIgnoreCase(username.trim());
            if (userOpt.isEmpty()) {
                log.debug("User alert skipped: username '{}' not found in system database", username);
                return;
            }

            User user = userOpt.get();
            String userEmail = user.getEmail();
            if (userEmail == null || userEmail.trim().isEmpty()) {
                log.warn("User alert skipped: user '{}' does not have a registered email address", username);
                return;
            }

            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(mailFrom);
            message.setTo(userEmail.trim());
            message.setSubject("[SECURITY NOTICE] Suspicious Activity Detected on Your Account");

            String body = String.format(
                    """
                    Hello %s,

                    This is an automated security notice from INNSPARK. Suspicious login activity was detected on your account:

                    Incident Severity: %s
                    Incident Details: %s
                    Timestamp: %s
                    Originating IP Address: %s

                    If you did not initiate these login attempts, we strongly recommend that you:
                    1. Change your password immediately.
                    2. Check your active sessions in the dashboard and terminate any unrecognized devices.
                    3. Contact your security administrator if you suspect unauthorized access.

                    ---
                    INNSPARK Security Operations
                    """,
                    user.getUsername(),
                    severity,
                    activity.getReason(),
                    activity.getTimestamp(),
                    activity.getIpAddress()
            );

            message.setText(body);
            mailSender.get().send(message);
            log.info("Security alert notice delivered to affected user '{}' ({})", username, userEmail);

        } catch (Exception e) {
            // Fail-safe: log safely without crashing caller
            log.error("Failed to send user security alert email for user '{}': {}", username, e.getMessage());
        }
    }

    /**
     * Derives severity level from detection reason.
     */
    private String resolveSeverity(String reason) {
        if (reason == null) return "HIGH";
        String lower = reason.toLowerCase();
        if (lower.contains("failed login attempts")) {
            return "HIGH";
        } else if (lower.contains("unusual success")) {
            return "MEDIUM";
        }
        return "HIGH";
    }
}
