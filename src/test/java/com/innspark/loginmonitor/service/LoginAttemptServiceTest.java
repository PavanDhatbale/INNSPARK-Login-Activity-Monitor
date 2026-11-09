package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.dto.LoginAttemptResponse;
import com.innspark.loginmonitor.dto.LoginRequest;
import com.innspark.loginmonitor.dto.LoginResponse;
import com.innspark.loginmonitor.entity.LoginAttempt;
import com.innspark.loginmonitor.enums.LoginStatus;
import com.innspark.loginmonitor.repository.LoginAttemptRepository;
import com.innspark.loginmonitor.service.impl.LoginAttemptServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LoginAttemptServiceTest {

    @Mock
    private LoginAttemptRepository loginAttemptRepository;

    @Mock
    private DetectionService detectionService;

    @InjectMocks
    private LoginAttemptServiceImpl loginAttemptService;

    private LoginAttempt mockAttempt;

    @BeforeEach
    void setUp() {
        mockAttempt = new LoginAttempt("testuser", "192.168.1.10", LocalDateTime.now(), LoginStatus.SUCCESS);
        mockAttempt.setId(1L);
    }

    @Test
    @DisplayName("Should successfully record a valid login attempt as SUCCESS and trigger detection")
    void processLogin_Success() {
        LoginRequest request = new LoginRequest("admin", "admin123");

        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(invocation -> {
            LoginAttempt attempt = invocation.getArgument(0);
            attempt.setId(101L);
            return attempt;
        });

        LoginResponse response = loginAttemptService.processLogin(request, "192.168.1.50");

        assertNotNull(response);
        assertEquals(101L, response.getId());
        assertEquals("admin", response.getUsername());
        assertEquals("192.168.1.50", response.getIpAddress());
        assertEquals(LoginStatus.SUCCESS, response.getStatus());
        assertEquals("Login successful", response.getMessage());

        ArgumentCaptor<LoginAttempt> captor = ArgumentCaptor.forClass(LoginAttempt.class);
        verify(loginAttemptRepository, times(1)).save(captor.capture());
        assertEquals(LoginStatus.SUCCESS, captor.getValue().getStatus());

        // Verify detection was triggered
        verify(detectionService, times(1)).detectSuspiciousActivity(any(LoginAttempt.class));
    }

    @Test
    @DisplayName("Should record an invalid login attempt as FAILURE and trigger detection")
    void processLogin_Failure() {
        LoginRequest request = new LoginRequest("admin", "wrongpassword");

        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(invocation -> {
            LoginAttempt attempt = invocation.getArgument(0);
            attempt.setId(102L);
            return attempt;
        });

        LoginResponse response = loginAttemptService.processLogin(request, "10.0.0.1");

        assertNotNull(response);
        assertEquals(102L, response.getId());
        assertEquals("admin", response.getUsername());
        assertEquals("10.0.0.1", response.getIpAddress());
        assertEquals(LoginStatus.FAILURE, response.getStatus());
        assertEquals("Invalid username or password", response.getMessage());

        ArgumentCaptor<LoginAttempt> captor = ArgumentCaptor.forClass(LoginAttempt.class);
        verify(loginAttemptRepository, times(1)).save(captor.capture());
        assertEquals(LoginStatus.FAILURE, captor.getValue().getStatus());

        // Verify detection was triggered
        verify(detectionService, times(1)).detectSuspiciousActivity(any(LoginAttempt.class));
    }

    @Test
    @DisplayName("Should prefer IP from request body if explicitly provided")
    void processLogin_WithExplicitIpInPayload() {
        LoginRequest request = new LoginRequest("testuser", "password123", "172.16.0.5");

        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenAnswer(invocation -> invocation.getArgument(0));

        LoginResponse response = loginAttemptService.processLogin(request, "192.168.1.1");

        assertEquals("172.16.0.5", response.getIpAddress());
        verify(detectionService, times(1)).detectSuspiciousActivity(any(LoginAttempt.class));
    }

    @Test
    @DisplayName("Should retrieve login history with filters")
    void getLoginHistory_WithFilters() {
        when(loginAttemptRepository.filterLoginAttempts("testuser", "192.168.1.10", LoginStatus.SUCCESS))
                .thenReturn(List.of(mockAttempt));

        List<LoginAttemptResponse> results = loginAttemptService.getLoginHistory("testuser", "192.168.1.10", LoginStatus.SUCCESS);

        assertNotNull(results);
        assertEquals(1, results.size());
        assertEquals("testuser", results.get(0).getUsername());
        assertEquals(LoginStatus.SUCCESS, results.get(0).getStatus());
        verify(loginAttemptRepository, times(1)).filterLoginAttempts("testuser", "192.168.1.10", LoginStatus.SUCCESS);
    }

    @Test
    @DisplayName("Should return all login history when no filters are provided")
    void getLoginHistory_NoFilters() {
        when(loginAttemptRepository.filterLoginAttempts(null, null, null))
                .thenReturn(List.of(mockAttempt));

        List<LoginAttemptResponse> results = loginAttemptService.getLoginHistory(null, null, null);

        assertNotNull(results);
        assertEquals(1, results.size());
        verify(loginAttemptRepository, times(1)).filterLoginAttempts(null, null, null);
    }
}
