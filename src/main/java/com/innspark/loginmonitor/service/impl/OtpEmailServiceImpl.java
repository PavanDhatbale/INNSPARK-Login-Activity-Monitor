package com.innspark.loginmonitor.service.impl;

import com.innspark.loginmonitor.exception.OtpDeliveryException;
import com.innspark.loginmonitor.service.OtpEmailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Service implementation for delivering OTP verification codes via SMTP.
 *
 * Security & Reliability Policies:
 * 1. Plaintext OTP codes are NEVER logged in logs, stack traces, or metrics.
 * 2. Sensitive data (passwords, BCrypt hashes, session tokens, SMTP credentials) are strictly excluded from emails.
 * 3. Failures throw a controlled OtpDeliveryException, ensuring no authenticated session is created.
 */
@Service
public class OtpEmailServiceImpl implements OtpEmailService {

    private static final Logger log = LoggerFactory.getLogger(OtpEmailServiceImpl.class);

    private final Optional<JavaMailSender> mailSender;

    @Value("${app.alerts.email.from:noreply@innspark.com}")
    private String mailFrom;

    public OtpEmailServiceImpl(Optional<JavaMailSender> mailSender) {
        this.mailSender = mailSender;
    }

    @Override
    public void sendOtpEmail(String recipientEmail, String username, String otp, int expirationMinutes) {
        if (recipientEmail == null || recipientEmail.trim().isEmpty()) {
            log.error("Failed to send OTP email: recipient address is empty for user '{}'", username);
            throw new OtpDeliveryException("Unable to deliver verification code: no registered email found");
        }

        if (mailSender.isEmpty()) {
            log.error("Failed to send OTP email to '{}': JavaMailSender is not available", recipientEmail);
            throw new OtpDeliveryException("Email verification service is temporarily unavailable. Please contact support.");
        }

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(mailFrom);
            message.setTo(recipientEmail.trim());
            message.setSubject("[INNSPARK] Your Login Verification Code");

            String body = String.format(
                    """
                    Hello %s,

                    Your INNSPARK one-time verification code is:

                        %s

                    This code will expire in %d minutes.

                    SECURITY WARNING:
                    Do not share this verification code with anyone. INNSPARK staff will never ask for your code.
                    If you did not initiate this login request, please secure your account immediately.

                    ---
                    INNSPARK Login Activity Monitor
                    """,
                    username,
                    otp,
                    expirationMinutes
            );

            message.setText(body);

            mailSender.get().send(message);
            log.info("OTP verification email delivered to '{}' for user '{}'", recipientEmail, username);

        } catch (MailException e) {
            log.error("SMTP error while delivering OTP email to '{}': {}", recipientEmail, e.getMessage());
            throw new OtpDeliveryException("Unable to deliver OTP verification email. Please try again or request a resend.");
        } catch (Exception e) {
            log.error("Unexpected error delivering OTP email to '{}': {}", recipientEmail, e.getMessage());
            throw new OtpDeliveryException("Failed to send OTP verification email. Please try again.");
        }
    }
}
