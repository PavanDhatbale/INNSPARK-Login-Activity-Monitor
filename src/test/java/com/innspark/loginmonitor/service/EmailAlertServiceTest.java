package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.entity.SuspiciousActivity;
import com.innspark.loginmonitor.entity.User;
import com.innspark.loginmonitor.enums.Role;
import com.innspark.loginmonitor.repository.UserRepository;
import com.innspark.loginmonitor.service.impl.EmailAlertServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailAlertServiceTest {

    @Mock
    private JavaMailSender mailSender;

    @Mock
    private UserRepository userRepository;

    private EmailAlertServiceImpl emailAlertService;

    @BeforeEach
    void setUp() {
        emailAlertService = new EmailAlertServiceImpl(Optional.of(mailSender), Optional.of(userRepository));
        ReflectionTestUtils.setField(emailAlertService, "emailEnabled", true);
        ReflectionTestUtils.setField(emailAlertService, "adminRecipient", "admin@innspark.com");
        ReflectionTestUtils.setField(emailAlertService, "mailFrom", "alerts@innspark.com");
    }

    @Test
    @DisplayName("Should deliver admin email alert with correct metadata and severity for IP attack")
    void sendSuspiciousActivityAlert_IpAttack_AdminEmailSent() {
        SuspiciousActivity activity = new SuspiciousActivity(
                "203.0.113.50",
                null,
                "Multiple failed login attempts from the same IP within 10 minutes",
                LocalDateTime.of(2026, 11, 8, 14, 30, 0)
        );

        emailAlertService.sendSuspiciousActivityAlert(activity);

        ArgumentCaptor<SimpleMailMessage> captor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender, times(1)).send(captor.capture());

        SimpleMailMessage sent = captor.getValue();
        assertEquals("alerts@innspark.com", sent.getFrom());
        assertNotNull(sent.getTo());
        assertEquals("admin@innspark.com", sent.getTo()[0]);
        assertTrue(sent.getSubject().contains("[SECURITY ALERT - HIGH]"));

        String text = sent.getText();
        assertNotNull(text);
        assertTrue(text.contains("203.0.113.50"));
        assertTrue(text.contains("N/A (IP-wide attack)"));
        assertTrue(text.contains("Multiple failed login attempts"));
        assertFalse(text.contains("password"));
        assertFalse(text.contains("secret"));

        verifyNoInteractions(userRepository);
    }

    @Test
    @DisplayName("Should deliver both admin alert and user security notice when registered user account is targeted")
    void sendSuspiciousActivityAlert_UsernameAttack_BothAdminAndUserNotified() {
        User user = new User("alice", "alice@example.com", "hash", Role.USER);
        when(userRepository.findByUsernameIgnoreCase("alice")).thenReturn(Optional.of(user));

        SuspiciousActivity activity = new SuspiciousActivity(
                "198.51.100.22",
                "alice",
                "Multiple failed login attempts for the same username within 10 minutes",
                LocalDateTime.of(2026, 11, 8, 15, 0, 0)
        );

        emailAlertService.sendSuspiciousActivityAlert(activity);

        ArgumentCaptor<SimpleMailMessage> captor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender, times(2)).send(captor.capture());

        List<SimpleMailMessage> sentMessages = captor.getAllValues();
        assertEquals(2, sentMessages.size());

        // Message 1: Admin Alert
        SimpleMailMessage adminMsg = sentMessages.get(0);
        assertEquals("admin@innspark.com", adminMsg.getTo()[0]);
        assertTrue(adminMsg.getSubject().contains("[SECURITY ALERT - HIGH]"));
        assertTrue(adminMsg.getText().contains("alice"));
        assertTrue(adminMsg.getText().contains("198.51.100.22"));

        // Message 2: User Security Notice
        SimpleMailMessage userMsg = sentMessages.get(1);
        assertEquals("alice@example.com", userMsg.getTo()[0]);
        assertTrue(userMsg.getSubject().contains("[SECURITY NOTICE] Suspicious Activity Detected on Your Account"));
        assertTrue(userMsg.getText().contains("Hello alice"));
        assertTrue(userMsg.getText().contains("198.51.100.22"));
        assertTrue(userMsg.getText().contains("Change your password immediately"));
    }

    @Test
    @DisplayName("Should deliver admin alert only when targeted username is not in userRepository")
    void sendSuspiciousActivityAlert_UserNotFound_SendsAdminOnly() {
        when(userRepository.findByUsernameIgnoreCase("unknown_user")).thenReturn(Optional.empty());

        SuspiciousActivity activity = new SuspiciousActivity(
                "198.51.100.22",
                "unknown_user",
                "Multiple failed login attempts for the same username within 10 minutes",
                LocalDateTime.now()
        );

        emailAlertService.sendSuspiciousActivityAlert(activity);

        ArgumentCaptor<SimpleMailMessage> captor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender, times(1)).send(captor.capture());
        assertEquals("admin@innspark.com", captor.getValue().getTo()[0]);
    }

    @Test
    @DisplayName("Should deliver admin alert only when targeted user has empty email")
    void sendSuspiciousActivityAlert_UserWithoutEmail_SendsAdminOnly() {
        User user = new User("alice", "   ", "hash", Role.USER);
        when(userRepository.findByUsernameIgnoreCase("alice")).thenReturn(Optional.of(user));

        SuspiciousActivity activity = new SuspiciousActivity("10.0.0.1", "alice", "Reason", LocalDateTime.now());
        emailAlertService.sendSuspiciousActivityAlert(activity);

        verify(mailSender, times(1)).send(any(SimpleMailMessage.class));
    }

    @Test
    @DisplayName("Should not send any email when email alerts are disabled")
    void sendSuspiciousActivityAlert_Disabled_NoEmailSent() {
        ReflectionTestUtils.setField(emailAlertService, "emailEnabled", false);

        SuspiciousActivity activity = new SuspiciousActivity("10.0.0.1", "user", "Reason", LocalDateTime.now());
        emailAlertService.sendSuspiciousActivityAlert(activity);

        verify(mailSender, never()).send(any(SimpleMailMessage.class));
    }

    @Test
    @DisplayName("Should not send admin email when admin recipient is not configured")
    void sendSuspiciousActivityAlert_MissingAdminRecipient_SkipsAdmin() {
        ReflectionTestUtils.setField(emailAlertService, "adminRecipient", "");

        SuspiciousActivity activity = new SuspiciousActivity("10.0.0.1", "N/A", "Reason", LocalDateTime.now());
        emailAlertService.sendSuspiciousActivityAlert(activity);

        verify(mailSender, never()).send(any(SimpleMailMessage.class));
    }

    @Test
    @DisplayName("Should handle missing JavaMailSender bean gracefully without exception")
    void sendSuspiciousActivityAlert_NoMailSenderBean_HandledSafely() {
        EmailAlertServiceImpl serviceWithoutBean = new EmailAlertServiceImpl(Optional.empty(), Optional.of(userRepository));
        ReflectionTestUtils.setField(serviceWithoutBean, "emailEnabled", true);
        ReflectionTestUtils.setField(serviceWithoutBean, "adminRecipient", "admin@innspark.com");

        SuspiciousActivity activity = new SuspiciousActivity("10.0.0.1", "user", "Reason", LocalDateTime.now());
        assertDoesNotThrow(() -> serviceWithoutBean.sendSuspiciousActivityAlert(activity));
    }

    @Test
    @DisplayName("Fail-safe: SMTP delivery exception does not throw and does not crash application")
    void sendSuspiciousActivityAlert_SmtpFailure_FailsSilently() {
        doThrow(new MailSendException("SMTP connection timed out"))
                .when(mailSender).send(any(SimpleMailMessage.class));

        SuspiciousActivity activity = new SuspiciousActivity("10.0.0.1", "user", "Reason", LocalDateTime.now());

        assertDoesNotThrow(() -> emailAlertService.sendSuspiciousActivityAlert(activity));
        verify(mailSender, times(1)).send(any(SimpleMailMessage.class));
    }
}
