package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.dto.ResendOtpResponse;
import com.innspark.loginmonitor.entity.OtpChallenge;
import com.innspark.loginmonitor.entity.User;
import com.innspark.loginmonitor.enums.OtpChallengeStatus;
import com.innspark.loginmonitor.enums.Role;
import com.innspark.loginmonitor.exception.AccountDisabledException;
import com.innspark.loginmonitor.exception.InvalidOtpException;
import com.innspark.loginmonitor.exception.OtpCooldownException;
import com.innspark.loginmonitor.exception.OtpExpiredException;
import com.innspark.loginmonitor.exception.OtpMaxAttemptsExceededException;
import com.innspark.loginmonitor.repository.OtpChallengeRepository;
import com.innspark.loginmonitor.service.impl.OtpServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
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
class OtpServiceTest {

    @Mock
    private OtpChallengeRepository otpChallengeRepository;

    @Mock
    private OtpEmailService otpEmailService;

    @Mock
    private PasswordEncoder passwordEncoder;

    private OtpServiceImpl otpService;

    private User sampleUser;

    @BeforeEach
    void setUp() {
        otpService = new OtpServiceImpl(otpChallengeRepository, otpEmailService, passwordEncoder);
        ReflectionTestUtils.setField(otpService, "otpEnabled", true);
        ReflectionTestUtils.setField(otpService, "expirationMinutes", 5);
        ReflectionTestUtils.setField(otpService, "maxAttempts", 5);
        ReflectionTestUtils.setField(otpService, "resendCooldownSeconds", 60);
        ReflectionTestUtils.setField(otpService, "maxResends", 3);

        sampleUser = new User("alice", "alice@example.com", "$2a$10$hashedPass", Role.USER);
        sampleUser.setId(10L);
        sampleUser.setEnabled(true);
    }

    @Test
    @DisplayName("createAndSendOtp generates 6-digit OTP, stores hash, sends email, and returns challenge")
    void createAndSendOtp_Success() {
        when(passwordEncoder.encode(anyString())).thenReturn("$2a$10$hashedOtp123456");
        when(otpChallengeRepository.save(any(OtpChallenge.class))).thenAnswer(i -> i.getArgument(0));

        OtpChallenge challenge = otpService.createAndSendOtp(sampleUser);

        assertNotNull(challenge);
        assertNotNull(challenge.getChallengeId());
        assertEquals("$2a$10$hashedOtp123456", challenge.getOtpHash());
        assertEquals(OtpChallengeStatus.PENDING, challenge.getStatus());
        assertEquals(sampleUser, challenge.getUser());

        // Verify email service called with raw 6-digit code
        ArgumentCaptor<String> otpCaptor = ArgumentCaptor.forClass(String.class);
        verify(otpEmailService, times(1)).sendOtpEmail(eq("alice@example.com"), eq("alice"), otpCaptor.capture(), eq(5));

        String rawOtp = otpCaptor.getValue();
        assertNotNull(rawOtp);
        assertEquals(6, rawOtp.length());
        assertTrue(rawOtp.matches("^\\d{6}$"), "OTP should be a 6-digit numeric string");

        // Verify the stored hash is NOT the raw OTP (plaintext protection)
        assertNotEquals(rawOtp, challenge.getOtpHash());
    }

    @Test
    @DisplayName("verifyOtp with valid code marks challenge VERIFIED and returns user")
    void verifyOtp_ValidCode_Success() {
        OtpChallenge challenge = new OtpChallenge("ch-123", sampleUser, "$2a$10$hashedOtp",
                LocalDateTime.now().minusMinutes(1), LocalDateTime.now().plusMinutes(4));

        when(otpChallengeRepository.findByChallengeIdWithLock("ch-123")).thenReturn(Optional.of(challenge));
        when(passwordEncoder.matches("123456", "$2a$10$hashedOtp")).thenReturn(true);
        when(otpChallengeRepository.save(any(OtpChallenge.class))).thenAnswer(i -> i.getArgument(0));

        User resultUser = otpService.verifyOtp("ch-123", "123456", "192.168.1.100");

        assertNotNull(resultUser);
        assertEquals("alice", resultUser.getUsername());
        assertEquals(OtpChallengeStatus.VERIFIED, challenge.getStatus());
        assertNotNull(challenge.getVerifiedAt());

        verify(otpChallengeRepository, times(1)).save(challenge);
    }

    @Test
    @DisplayName("verifyOtp rejects already VERIFIED challenge (single-use / replay protection)")
    void verifyOtp_AlreadyVerified_ReplayProtection() {
        OtpChallenge challenge = new OtpChallenge("ch-123", sampleUser, "$2a$10$hashedOtp",
                LocalDateTime.now().minusMinutes(2), LocalDateTime.now().plusMinutes(3));
        challenge.setStatus(OtpChallengeStatus.VERIFIED);
        challenge.setVerifiedAt(LocalDateTime.now().minusMinutes(1));

        when(otpChallengeRepository.findByChallengeIdWithLock("ch-123")).thenReturn(Optional.of(challenge));

        InvalidOtpException ex = assertThrows(InvalidOtpException.class,
                () -> otpService.verifyOtp("ch-123", "123456", "192.168.1.100"));
        assertTrue(ex.getMessage().contains("already been used or is invalid"));
    }

    @Test
    @DisplayName("verifyOtp with wrong code increments failed attempts and throws InvalidOtpException with remaining count")
    void verifyOtp_WrongCode_IncrementsAttempts() {
        OtpChallenge challenge = new OtpChallenge("ch-123", sampleUser, "$2a$10$hashedOtp",
                LocalDateTime.now().minusMinutes(1), LocalDateTime.now().plusMinutes(4));

        when(otpChallengeRepository.findByChallengeIdWithLock("ch-123")).thenReturn(Optional.of(challenge));
        when(passwordEncoder.matches("999999", "$2a$10$hashedOtp")).thenReturn(false);
        when(otpChallengeRepository.save(any(OtpChallenge.class))).thenAnswer(i -> i.getArgument(0));

        InvalidOtpException ex = assertThrows(InvalidOtpException.class,
                () -> otpService.verifyOtp("ch-123", "999999", "192.168.1.100"));

        assertEquals(1, challenge.getFailedAttempts());
        assertTrue(ex.getMessage().contains("Remaining attempts: 4"));
    }

    @Test
    @DisplayName("verifyOtp exceeding max attempts marks challenge FAILED and throws OtpMaxAttemptsExceededException")
    void verifyOtp_ExceedMaxAttempts_MarksFailed() {
        OtpChallenge challenge = new OtpChallenge("ch-123", sampleUser, "$2a$10$hashedOtp",
                LocalDateTime.now().minusMinutes(1), LocalDateTime.now().plusMinutes(4));
        challenge.setFailedAttempts(4); // 5th attempt will fail

        when(otpChallengeRepository.findByChallengeIdWithLock("ch-123")).thenReturn(Optional.of(challenge));
        when(passwordEncoder.matches("999999", "$2a$10$hashedOtp")).thenReturn(false);
        when(otpChallengeRepository.save(any(OtpChallenge.class))).thenAnswer(i -> i.getArgument(0));

        OtpMaxAttemptsExceededException ex = assertThrows(OtpMaxAttemptsExceededException.class,
                () -> otpService.verifyOtp("ch-123", "999999", "192.168.1.100"));

        assertEquals(5, challenge.getFailedAttempts());
        assertEquals(OtpChallengeStatus.FAILED, challenge.getStatus());
        assertTrue(ex.getMessage().contains("Maximum OTP verification attempts exceeded"));
    }

    @Test
    @DisplayName("verifyOtp on expired challenge marks EXPIRED and throws OtpExpiredException")
    void verifyOtp_Expired_ThrowsOtpExpiredException() {
        OtpChallenge challenge = new OtpChallenge("ch-123", sampleUser, "$2a$10$hashedOtp",
                LocalDateTime.now().minusMinutes(10), LocalDateTime.now().minusMinutes(5));

        when(otpChallengeRepository.findByChallengeIdWithLock("ch-123")).thenReturn(Optional.of(challenge));
        when(otpChallengeRepository.save(any(OtpChallenge.class))).thenAnswer(i -> i.getArgument(0));

        OtpExpiredException ex = assertThrows(OtpExpiredException.class,
                () -> otpService.verifyOtp("ch-123", "123456", "192.168.1.100"));

        assertEquals(OtpChallengeStatus.EXPIRED, challenge.getStatus());
        assertTrue(ex.getMessage().contains("expired"));
    }

    @Test
    @DisplayName("verifyOtp rejects verification for disabled user")
    void verifyOtp_DisabledUser_ThrowsAccountDisabledException() {
        sampleUser.setEnabled(false);
        OtpChallenge challenge = new OtpChallenge("ch-123", sampleUser, "$2a$10$hashedOtp",
                LocalDateTime.now().minusMinutes(1), LocalDateTime.now().plusMinutes(4));

        when(otpChallengeRepository.findByChallengeIdWithLock("ch-123")).thenReturn(Optional.of(challenge));

        AccountDisabledException ex = assertThrows(AccountDisabledException.class,
                () -> otpService.verifyOtp("ch-123", "123456", "192.168.1.100"));
        assertTrue(ex.getMessage().contains("Account is disabled"));
    }

    @Test
    @DisplayName("verifyOtp with unknown challenge ID throws InvalidOtpException")
    void verifyOtp_UnknownChallenge_ThrowsException() {
        when(otpChallengeRepository.findByChallengeIdWithLock("unknown-ch")).thenReturn(Optional.empty());

        InvalidOtpException ex = assertThrows(InvalidOtpException.class,
                () -> otpService.verifyOtp("unknown-ch", "123456", "192.168.1.100"));
        assertTrue(ex.getMessage().contains("Invalid or unrecognized OTP challenge"));
    }

    @Test
    @DisplayName("resendOtp within cooldown period throws OtpCooldownException")
    void resendOtp_WithinCooldown_ThrowsOtpCooldownException() {
        OtpChallenge challenge = new OtpChallenge("ch-123", sampleUser, "$2a$10$hashedOtp",
                LocalDateTime.now().minusSeconds(20), LocalDateTime.now().plusMinutes(5));
        challenge.setLastResentAt(LocalDateTime.now().minusSeconds(20)); // only 20s ago (cooldown 60s)

        when(otpChallengeRepository.findByChallengeIdWithLock("ch-123")).thenReturn(Optional.of(challenge));

        OtpCooldownException ex = assertThrows(OtpCooldownException.class,
                () -> otpService.resendOtp("ch-123", "192.168.1.100"));
        assertTrue(ex.getMessage().contains("Please wait"));
        verify(otpEmailService, never()).sendOtpEmail(anyString(), anyString(), anyString(), anyInt());
    }

    @Test
    @DisplayName("resendOtp exceeding max resends throws OtpMaxAttemptsExceededException")
    void resendOtp_ExceedMaxResends_ThrowsException() {
        OtpChallenge challenge = new OtpChallenge("ch-123", sampleUser, "$2a$10$hashedOtp",
                LocalDateTime.now().minusMinutes(4), LocalDateTime.now().plusMinutes(1));
        challenge.setLastResentAt(LocalDateTime.now().minusSeconds(70));
        challenge.setResendCount(3); // maxResends = 3

        when(otpChallengeRepository.findByChallengeIdWithLock("ch-123")).thenReturn(Optional.of(challenge));

        OtpMaxAttemptsExceededException ex = assertThrows(OtpMaxAttemptsExceededException.class,
                () -> otpService.resendOtp("ch-123", "192.168.1.100"));
        assertEquals(OtpChallengeStatus.FAILED, challenge.getStatus());
        assertTrue(ex.getMessage().contains("Maximum OTP resend limit reached"));
        verify(otpEmailService, never()).sendOtpEmail(anyString(), anyString(), anyString(), anyInt());
    }

    @Test
    @DisplayName("resendOtp after cooldown succeeds, updates hash, extends expiry, and delivers new email")
    void resendOtp_AfterCooldown_Success() {
        OtpChallenge challenge = new OtpChallenge("ch-123", sampleUser, "$2a$10$hashedOtpOld",
                LocalDateTime.now().minusMinutes(2), LocalDateTime.now().plusMinutes(3));
        challenge.setLastResentAt(LocalDateTime.now().minusSeconds(65)); // 65s ago (> 60s cooldown)
        challenge.setResendCount(1);
        challenge.setFailedAttempts(2);

        when(otpChallengeRepository.findByChallengeIdWithLock("ch-123")).thenReturn(Optional.of(challenge));
        when(passwordEncoder.encode(anyString())).thenReturn("$2a$10$hashedOtpNew");
        when(otpChallengeRepository.save(any(OtpChallenge.class))).thenAnswer(i -> i.getArgument(0));

        ResendOtpResponse response = otpService.resendOtp("ch-123", "192.168.1.100");

        assertNotNull(response);
        assertEquals("ch-123", response.getChallengeId());
        assertEquals(2, challenge.getResendCount());
        assertEquals(0, challenge.getFailedAttempts()); // reset failed attempts
        assertEquals("$2a$10$hashedOtpNew", challenge.getOtpHash());

        verify(otpEmailService, times(1)).sendOtpEmail(eq("alice@example.com"), eq("alice"), anyString(), eq(5));
    }
}
