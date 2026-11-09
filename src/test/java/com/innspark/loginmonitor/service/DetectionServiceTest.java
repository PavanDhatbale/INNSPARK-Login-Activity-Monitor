package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.entity.LoginAttempt;
import com.innspark.loginmonitor.entity.SuspiciousActivity;
import com.innspark.loginmonitor.enums.LoginStatus;
import com.innspark.loginmonitor.repository.LoginAttemptRepository;
import com.innspark.loginmonitor.repository.SuspiciousActivityRepository;
import com.innspark.loginmonitor.service.impl.DetectionServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DetectionServiceTest {

    @Mock
    private LoginAttemptRepository loginAttemptRepository;

    @Mock
    private SuspiciousActivityRepository suspiciousActivityRepository;

    @Mock
    private EmailAlertService emailAlertService;

    @InjectMocks
    private DetectionServiceImpl detectionService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(detectionService, "windowMinutes", 10);
        ReflectionTestUtils.setField(detectionService, "ipFailureThreshold", 5);
        ReflectionTestUtils.setField(detectionService, "userFailureThreshold", 5);
        ReflectionTestUtils.setField(detectionService, "unusualSuccessThreshold", 3);
    }

    @Test
    @DisplayName("Rule 1: Should flag suspicious activity when IP failures reach threshold (5)")
    void detect_Rule1_IpBruteForce_Success() {
        LoginAttempt attempt = new LoginAttempt("user1", "192.168.1.100", LocalDateTime.now(), LoginStatus.FAILURE);

        when(loginAttemptRepository.countByIpAddressAndStatusSince(eq("192.168.1.100"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(5L);
        when(suspiciousActivityRepository.existsByIpAddressAndReasonPrefixSince(eq("192.168.1.100"), anyString(), any(LocalDateTime.class)))
                .thenReturn(false);

        detectionService.detectSuspiciousActivity(attempt);

        ArgumentCaptor<SuspiciousActivity> captor = ArgumentCaptor.forClass(SuspiciousActivity.class);
        verify(suspiciousActivityRepository, times(1)).save(captor.capture());
        SuspiciousActivity saved = captor.getValue();

        assertEquals("192.168.1.100", saved.getIpAddress());
        assertTrue(saved.getReason().contains("Multiple failed login attempts from the same IP"));
    }

    @Test
    @DisplayName("Rule 1: Should NOT flag suspicious activity when IP failures are below threshold (4)")
    void detect_Rule1_IpBruteForce_BelowThreshold() {
        LoginAttempt attempt = new LoginAttempt("user1", "192.168.1.100", LocalDateTime.now(), LoginStatus.FAILURE);

        when(loginAttemptRepository.countByIpAddressAndStatusSince(eq("192.168.1.100"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(4L);

        detectionService.detectSuspiciousActivity(attempt);

        verify(suspiciousActivityRepository, never()).save(any(SuspiciousActivity.class));
    }

    @Test
    @DisplayName("Rule 1: Deduplication should prevent duplicate alerts for same IP within window")
    void detect_Rule1_Deduplication() {
        LoginAttempt attempt = new LoginAttempt("user1", "192.168.1.100", LocalDateTime.now(), LoginStatus.FAILURE);

        when(loginAttemptRepository.countByIpAddressAndStatusSince(eq("192.168.1.100"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(6L);
        // Already logged within window
        when(suspiciousActivityRepository.existsByIpAddressAndReasonPrefixSince(eq("192.168.1.100"), anyString(), any(LocalDateTime.class)))
                .thenReturn(true);

        detectionService.detectSuspiciousActivity(attempt);

        verify(suspiciousActivityRepository, never()).save(any(SuspiciousActivity.class));
    }

    @Test
    @DisplayName("Rule 2: Should flag suspicious activity when username failures reach threshold (5)")
    void detect_Rule2_UsernameBruteForce_Success() {
        LoginAttempt attempt = new LoginAttempt("targetUser", "192.168.1.10", LocalDateTime.now(), LoginStatus.FAILURE);

        when(loginAttemptRepository.countByIpAddressAndStatusSince(anyString(), any(), any())).thenReturn(1L);
        when(loginAttemptRepository.countByUsernameAndStatusSince(eq("targetUser"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(5L);
        when(suspiciousActivityRepository.existsByUsernameAndReasonPrefixSince(eq("targetUser"), anyString(), any(LocalDateTime.class)))
                .thenReturn(false);

        detectionService.detectSuspiciousActivity(attempt);

        ArgumentCaptor<SuspiciousActivity> captor = ArgumentCaptor.forClass(SuspiciousActivity.class);
        verify(suspiciousActivityRepository, times(1)).save(captor.capture());
        SuspiciousActivity saved = captor.getValue();

        assertEquals("targetUser", saved.getUsername());
        assertTrue(saved.getReason().contains("Multiple failed login attempts for the same username"));
    }

    @Test
    @DisplayName("Rule 2: Deduplication should prevent duplicate alerts for same username within window")
    void detect_Rule2_Deduplication() {
        LoginAttempt attempt = new LoginAttempt("targetUser", "192.168.1.10", LocalDateTime.now(), LoginStatus.FAILURE);

        when(loginAttemptRepository.countByIpAddressAndStatusSince(anyString(), any(), any())).thenReturn(1L);
        when(loginAttemptRepository.countByUsernameAndStatusSince(eq("targetUser"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(6L);
        // Already logged within window
        when(suspiciousActivityRepository.existsByUsernameAndReasonPrefixSince(eq("targetUser"), anyString(), any(LocalDateTime.class)))
                .thenReturn(true);

        detectionService.detectSuspiciousActivity(attempt);

        verify(suspiciousActivityRepository, never()).save(any(SuspiciousActivity.class));
    }

    @Test
    @DisplayName("Rule 3: Should flag unusual success after 3 consecutive failures")
    void detect_Rule3_UnusualSuccess_Detected() {
        LoginAttempt currentSuccess = new LoginAttempt("john", "10.0.0.1", LocalDateTime.now(), LoginStatus.SUCCESS);
        currentSuccess.setId(99L);

        LoginAttempt fail1 = new LoginAttempt("john", "10.0.0.1", LocalDateTime.now().minusMinutes(1), LoginStatus.FAILURE);
        fail1.setId(98L);
        LoginAttempt fail2 = new LoginAttempt("john", "10.0.0.1", LocalDateTime.now().minusMinutes(2), LoginStatus.FAILURE);
        fail2.setId(97L);
        LoginAttempt fail3 = new LoginAttempt("john", "10.0.0.1", LocalDateTime.now().minusMinutes(3), LoginStatus.FAILURE);
        fail3.setId(96L);

        when(loginAttemptRepository.findRecentAttemptsByUsername(eq("john"), any(LocalDateTime.class)))
                .thenReturn(List.of(currentSuccess, fail1, fail2, fail3));
        when(suspiciousActivityRepository.existsByUsernameAndReasonPrefixSince(eq("john"), anyString(), any(LocalDateTime.class)))
                .thenReturn(false);

        detectionService.detectSuspiciousActivity(currentSuccess);

        ArgumentCaptor<SuspiciousActivity> captor = ArgumentCaptor.forClass(SuspiciousActivity.class);
        verify(suspiciousActivityRepository, times(1)).save(captor.capture());
        SuspiciousActivity saved = captor.getValue();

        assertEquals("john", saved.getUsername());
        assertEquals("10.0.0.1", saved.getIpAddress());
        assertTrue(saved.getReason().contains("Successful login following multiple failed attempts"));
    }

    @Test
    @DisplayName("Rule 3: Should NOT flag unusual success when prior failures are fewer than threshold (2)")
    void detect_Rule3_UnusualSuccess_BelowThreshold() {
        LoginAttempt currentSuccess = new LoginAttempt("john", "10.0.0.1", LocalDateTime.now(), LoginStatus.SUCCESS);
        currentSuccess.setId(99L);

        LoginAttempt fail1 = new LoginAttempt("john", "10.0.0.1", LocalDateTime.now().minusMinutes(1), LoginStatus.FAILURE);
        fail1.setId(98L);
        LoginAttempt fail2 = new LoginAttempt("john", "10.0.0.1", LocalDateTime.now().minusMinutes(2), LoginStatus.FAILURE);
        fail2.setId(97L);

        when(loginAttemptRepository.findRecentAttemptsByUsername(eq("john"), any(LocalDateTime.class)))
                .thenReturn(List.of(currentSuccess, fail1, fail2));

        detectionService.detectSuspiciousActivity(currentSuccess);

        verify(suspiciousActivityRepository, never()).save(any(SuspiciousActivity.class));
    }

    @Test
    @DisplayName("Rule 3: Deduplication prevents duplicate alert for unusual success")
    void detect_Rule3_Deduplication() {
        LoginAttempt currentSuccess = new LoginAttempt("john", "10.0.0.1", LocalDateTime.now(), LoginStatus.SUCCESS);
        currentSuccess.setId(99L);

        LoginAttempt fail1 = new LoginAttempt("john", "10.0.0.1", LocalDateTime.now().minusMinutes(1), LoginStatus.FAILURE);
        LoginAttempt fail2 = new LoginAttempt("john", "10.0.0.1", LocalDateTime.now().minusMinutes(2), LoginStatus.FAILURE);
        LoginAttempt fail3 = new LoginAttempt("john", "10.0.0.1", LocalDateTime.now().minusMinutes(3), LoginStatus.FAILURE);

        when(loginAttemptRepository.findRecentAttemptsByUsername(eq("john"), any(LocalDateTime.class)))
                .thenReturn(List.of(currentSuccess, fail1, fail2, fail3));
        when(suspiciousActivityRepository.existsByUsernameAndReasonPrefixSince(eq("john"), anyString(), any(LocalDateTime.class)))
                .thenReturn(true);

        detectionService.detectSuspiciousActivity(currentSuccess);

        verify(suspiciousActivityRepository, never()).save(any(SuspiciousActivity.class));
    }

    @Test
    @DisplayName("Scheduled Scan: Successfully flags un-logged suspicious IPs and Usernames within time window")
    void runScheduledScan_Success() {
        when(loginAttemptRepository.findIpsWithFailureCountExceeding(eq(LoginStatus.FAILURE), any(LocalDateTime.class), any(LocalDateTime.class), eq(5L)))
                .thenReturn(List.of("192.168.1.200"));
        when(suspiciousActivityRepository.existsByIpAddressAndReasonPrefixSince(eq("192.168.1.200"), anyString(), any(LocalDateTime.class)))
                .thenReturn(false);

        when(loginAttemptRepository.findUsernamesWithFailureCountExceeding(eq(LoginStatus.FAILURE), any(LocalDateTime.class), any(LocalDateTime.class), eq(5L)))
                .thenReturn(List.of("compromisedUser"));
        when(suspiciousActivityRepository.existsByUsernameAndReasonPrefixSince(eq("compromisedUser"), anyString(), any(LocalDateTime.class)))
                .thenReturn(false);

        when(suspiciousActivityRepository.save(any(SuspiciousActivity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        detectionService.runScheduledScan();

        verify(suspiciousActivityRepository, times(2)).save(any(SuspiciousActivity.class));
        verify(emailAlertService, times(2)).sendSuspiciousActivityAlert(any(SuspiciousActivity.class));
    }

    @Test
    @DisplayName("Scheduled Scan: Future-dated failed attempts do not trigger detection")
    void runScheduledScan_ExcludesFutureDatedAttempts() {
        // When queries restrict between [since, now], future-dated attempts (timestamp > now) return no eligible results
        when(loginAttemptRepository.findIpsWithFailureCountExceeding(eq(LoginStatus.FAILURE), any(LocalDateTime.class), any(LocalDateTime.class), eq(5L)))
                .thenReturn(List.of());
        when(loginAttemptRepository.findUsernamesWithFailureCountExceeding(eq(LoginStatus.FAILURE), any(LocalDateTime.class), any(LocalDateTime.class), eq(5L)))
                .thenReturn(List.of());

        detectionService.runScheduledScan();

        verify(suspiciousActivityRepository, never()).save(any(SuspiciousActivity.class));
        verify(emailAlertService, never()).sendSuspiciousActivityAlert(any(SuspiciousActivity.class));
    }

    @Test
    @DisplayName("Scheduled Scan: IP-based detection flags suspicious IP and sends email alert")
    void runScheduledScan_IpBasedDetection_Success() {
        when(loginAttemptRepository.findIpsWithFailureCountExceeding(eq(LoginStatus.FAILURE), any(LocalDateTime.class), any(LocalDateTime.class), eq(5L)))
                .thenReturn(List.of("10.50.0.1"));
        when(suspiciousActivityRepository.existsByIpAddressAndReasonPrefixSince(eq("10.50.0.1"), anyString(), any(LocalDateTime.class)))
                .thenReturn(false);

        when(loginAttemptRepository.findUsernamesWithFailureCountExceeding(eq(LoginStatus.FAILURE), any(LocalDateTime.class), any(LocalDateTime.class), eq(5L)))
                .thenReturn(List.of());

        when(suspiciousActivityRepository.save(any(SuspiciousActivity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        detectionService.runScheduledScan();

        ArgumentCaptor<SuspiciousActivity> captor = ArgumentCaptor.forClass(SuspiciousActivity.class);
        verify(suspiciousActivityRepository, times(1)).save(captor.capture());
        SuspiciousActivity saved = captor.getValue();
        assertEquals("10.50.0.1", saved.getIpAddress());
        assertNull(saved.getUsername());
        assertTrue(saved.getReason().contains("Multiple failed login attempts from the same IP"));

        verify(emailAlertService, times(1)).sendSuspiciousActivityAlert(saved);
    }

    @Test
    @DisplayName("Scheduled Scan: Username-based detection flags suspicious user and sends email alert")
    void runScheduledScan_UsernameBasedDetection_Success() {
        when(loginAttemptRepository.findIpsWithFailureCountExceeding(eq(LoginStatus.FAILURE), any(LocalDateTime.class), any(LocalDateTime.class), eq(5L)))
                .thenReturn(List.of());

        when(loginAttemptRepository.findUsernamesWithFailureCountExceeding(eq(LoginStatus.FAILURE), any(LocalDateTime.class), any(LocalDateTime.class), eq(5L)))
                .thenReturn(List.of("targetedUser"));
        when(suspiciousActivityRepository.existsByUsernameAndReasonPrefixSince(eq("targetedUser"), anyString(), any(LocalDateTime.class)))
                .thenReturn(false);

        when(suspiciousActivityRepository.save(any(SuspiciousActivity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        detectionService.runScheduledScan();

        ArgumentCaptor<SuspiciousActivity> captor = ArgumentCaptor.forClass(SuspiciousActivity.class);
        verify(suspiciousActivityRepository, times(1)).save(captor.capture());
        SuspiciousActivity saved = captor.getValue();
        assertEquals("targetedUser", saved.getUsername());
        assertEquals("N/A", saved.getIpAddress());
        assertTrue(saved.getReason().contains("Multiple failed login attempts for the same username"));

        verify(emailAlertService, times(1)).sendSuspiciousActivityAlert(saved);
    }

    @Test
    @DisplayName("Scheduled Scan: Deduplication prevents re-logging already reported incidents in 10-minute window")
    void runScheduledScan_Deduplication_SkipsAlreadyLogged() {
        when(loginAttemptRepository.findIpsWithFailureCountExceeding(eq(LoginStatus.FAILURE), any(LocalDateTime.class), any(LocalDateTime.class), eq(5L)))
                .thenReturn(List.of("192.168.1.200"));
        when(suspiciousActivityRepository.existsByIpAddressAndReasonPrefixSince(eq("192.168.1.200"), anyString(), any(LocalDateTime.class)))
                .thenReturn(true); // Already logged!

        when(loginAttemptRepository.findUsernamesWithFailureCountExceeding(eq(LoginStatus.FAILURE), any(LocalDateTime.class), any(LocalDateTime.class), eq(5L)))
                .thenReturn(List.of("compromisedUser"));
        when(suspiciousActivityRepository.existsByUsernameAndReasonPrefixSince(eq("compromisedUser"), anyString(), any(LocalDateTime.class)))
                .thenReturn(true); // Already logged!

        detectionService.runScheduledScan();

        verify(suspiciousActivityRepository, never()).save(any(SuspiciousActivity.class));
        verify(emailAlertService, never()).sendSuspiciousActivityAlert(any(SuspiciousActivity.class));
    }

    @Test
    @DisplayName("Scheduled Scan: Skips invalid, null, empty, or N/A candidate entries")
    void runScheduledScan_SkipsInvalidCandidates() {
        when(loginAttemptRepository.findIpsWithFailureCountExceeding(eq(LoginStatus.FAILURE), any(LocalDateTime.class), any(LocalDateTime.class), eq(5L)))
                .thenReturn(java.util.Arrays.asList(null, "", "   ", "N/A"));
        when(loginAttemptRepository.findUsernamesWithFailureCountExceeding(eq(LoginStatus.FAILURE), any(LocalDateTime.class), any(LocalDateTime.class), eq(5L)))
                .thenReturn(java.util.Arrays.asList(null, "", "   "));

        detectionService.runScheduledScan();

        verify(suspiciousActivityRepository, never()).save(any(SuspiciousActivity.class));
        verify(emailAlertService, never()).sendSuspiciousActivityAlert(any(SuspiciousActivity.class));
    }
}
