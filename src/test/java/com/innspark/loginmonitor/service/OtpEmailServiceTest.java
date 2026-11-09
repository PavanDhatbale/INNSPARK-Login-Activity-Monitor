package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.exception.OtpDeliveryException;
import com.innspark.loginmonitor.service.impl.OtpEmailServiceImpl;
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

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OtpEmailServiceTest {

    @Mock
    private JavaMailSender mailSender;

    private OtpEmailServiceImpl otpEmailService;

    @BeforeEach
    void setUp() {
        otpEmailService = new OtpEmailServiceImpl(Optional.of(mailSender));
        ReflectionTestUtils.setField(otpEmailService, "mailFrom", "noreply@innspark.com");
    }

    @Test
    @DisplayName("Successfully delivers OTP verification email with proper formatting and security notice")
    void sendOtpEmail_Success() {
        otpEmailService.sendOtpEmail("user@example.com", "alice", "123456", 5);

        ArgumentCaptor<SimpleMailMessage> captor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender, times(1)).send(captor.capture());

        SimpleMailMessage message = captor.getValue();
        assertNotNull(message);
        assertEquals("user@example.com", message.getTo()[0]);
        assertEquals("noreply@innspark.com", message.getFrom());
        assertTrue(message.getSubject().contains("[INNSPARK] Your Login Verification Code"));

        String body = message.getText();
        assertNotNull(body);
        assertTrue(body.contains("alice"));
        assertTrue(body.contains("123456"));
        assertTrue(body.contains("5 minutes"));
        assertTrue(body.contains("Do not share this verification code"));
        // Ensure sensitive server details or passwords are not present
        assertFalse(body.contains("password"));
        assertFalse(body.contains("BCrypt"));
    }

    @Test
    @DisplayName("Empty or null recipient email throws OtpDeliveryException")
    void sendOtpEmail_EmptyRecipient_ThrowsException() {
        assertThrows(OtpDeliveryException.class,
                () -> otpEmailService.sendOtpEmail(null, "alice", "123456", 5));
        assertThrows(OtpDeliveryException.class,
                () -> otpEmailService.sendOtpEmail("   ", "alice", "123456", 5));

        verify(mailSender, never()).send(any(SimpleMailMessage.class));
    }

    @Test
    @DisplayName("Missing JavaMailSender bean throws OtpDeliveryException")
    void sendOtpEmail_NoMailSender_ThrowsException() {
        OtpEmailServiceImpl noSenderService = new OtpEmailServiceImpl(Optional.empty());

        OtpDeliveryException ex = assertThrows(OtpDeliveryException.class,
                () -> noSenderService.sendOtpEmail("user@example.com", "alice", "123456", 5));
        assertTrue(ex.getMessage().contains("temporarily unavailable"));
    }

    @Test
    @DisplayName("SMTP delivery error caught safely and throws controlled OtpDeliveryException")
    void sendOtpEmail_SmtpFailure_ThrowsExceptionSafely() {
        doThrow(new MailSendException("SMTP connection refused"))
                .when(mailSender).send(any(SimpleMailMessage.class));

        OtpDeliveryException ex = assertThrows(OtpDeliveryException.class,
                () -> otpEmailService.sendOtpEmail("user@example.com", "alice", "123456", 5));
        assertTrue(ex.getMessage().contains("Unable to deliver OTP verification email"));
    }
}
