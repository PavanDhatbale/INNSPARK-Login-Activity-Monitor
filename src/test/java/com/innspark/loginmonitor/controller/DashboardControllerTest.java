package com.innspark.loginmonitor.controller;

import com.innspark.loginmonitor.dto.LoginAttemptResponse;
import com.innspark.loginmonitor.dto.PageResponse;
import com.innspark.loginmonitor.dto.SuspiciousActivityResponse;
import com.innspark.loginmonitor.dto.UserDashboardStatsResponse;
import com.innspark.loginmonitor.enums.LoginStatus;
import com.innspark.loginmonitor.exception.GlobalExceptionHandler;
import com.innspark.loginmonitor.service.DashboardService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(DashboardController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(GlobalExceptionHandler.class)
class DashboardControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DashboardService dashboardService;

    @Test
    @DisplayName("GET /dashboard/stats returns 200 OK and UserDashboardStatsResponse for authenticated user")
    void getUserStats_Authenticated_Success() throws Exception {
        UserDashboardStatsResponse stats = new UserDashboardStatsResponse(20, 15, 5, 1, LocalDateTime.now(), LocalDateTime.now());

        when(dashboardService.getUserStats("alice")).thenReturn(stats);

        mockMvc.perform(get("/dashboard/stats")
                        .principal(() -> "alice")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalLoginAttempts").value(20))
                .andExpect(jsonPath("$.successfulLogins").value(15))
                .andExpect(jsonPath("$.failedLogins").value(5))
                .andExpect(jsonPath("$.suspiciousActivities").value(1));

        verify(dashboardService, times(1)).getUserStats("alice");
    }

    @Test
    @DisplayName("GET /dashboard/stats returns 401 Unauthorized when unauthenticated")
    void getUserStats_Unauthenticated_Returns401() throws Exception {
        mockMvc.perform(get("/dashboard/stats"))
                .andExpect(status().isUnauthorized());

        verify(dashboardService, never()).getUserStats(anyString());
    }

    @Test
    @DisplayName("GET /dashboard/stats as USER requesting another username returns 403 Forbidden")
    void getUserStats_User_OtherUser_Forbidden() throws Exception {
        UsernamePasswordAuthenticationToken userAuth = new UsernamePasswordAuthenticationToken(
                "alice", null, List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        mockMvc.perform(get("/dashboard/stats")
                        .principal(userAuth)
                        .param("username", "bob"))
                .andExpect(status().isForbidden());

        verify(dashboardService, never()).getUserStats("bob");
    }

    @Test
    @DisplayName("GET /dashboard/login-history returns 200 OK with paginated login attempts")
    void getUserLoginHistory_Success() throws Exception {
        LoginAttemptResponse attempt = new LoginAttemptResponse(1L, "alice", "192.168.1.1", LoginStatus.SUCCESS, LocalDateTime.now());
        PageResponse<LoginAttemptResponse> pageResponse = new PageResponse<>(List.of(attempt), 0, 10, 1, 1, true, true);

        when(dashboardService.getUserLoginHistory(eq("alice"), isNull(), eq(0), eq(10)))
                .thenReturn(pageResponse);

        mockMvc.perform(get("/dashboard/login-history")
                        .principal(() -> "alice")
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].username").value("alice"))
                .andExpect(jsonPath("$.content[0].status").value("SUCCESS"))
                .andExpect(jsonPath("$.totalElements").value(1));
    }

    @Test
    @DisplayName("GET /dashboard/login-history returns 401 Unauthorized when unauthenticated")
    void getUserLoginHistory_Unauthenticated_Returns401() throws Exception {
        mockMvc.perform(get("/dashboard/login-history"))
                .andExpect(status().isUnauthorized());

        verify(dashboardService, never()).getUserLoginHistory(anyString(), any(), anyInt(), anyInt());
    }

    @Test
    @DisplayName("GET /dashboard/login-history as USER requesting another username returns 403 Forbidden")
    void getUserLoginHistory_User_OtherUser_Forbidden() throws Exception {
        UsernamePasswordAuthenticationToken userAuth = new UsernamePasswordAuthenticationToken(
                "alice", null, List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        mockMvc.perform(get("/dashboard/login-history")
                        .principal(userAuth)
                        .param("username", "bob"))
                .andExpect(status().isForbidden());

        verify(dashboardService, never()).getUserLoginHistory(anyString(), any(), anyInt(), anyInt());
    }

    @Test
    @DisplayName("GET /dashboard/login-history as ADMIN requesting another username returns 200 OK")
    void getUserLoginHistory_Admin_OtherUser_Success() throws Exception {
        UsernamePasswordAuthenticationToken adminAuth = new UsernamePasswordAuthenticationToken(
                "admin1", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
        LoginAttemptResponse attempt = new LoginAttemptResponse(5L, "bob", "192.168.1.5", LoginStatus.SUCCESS, LocalDateTime.now());
        PageResponse<LoginAttemptResponse> pageResponse = new PageResponse<>(List.of(attempt), 0, 10, 1, 1, true, true);

        when(dashboardService.getUserLoginHistory(eq("bob"), isNull(), eq(0), eq(10)))
                .thenReturn(pageResponse);

        mockMvc.perform(get("/dashboard/login-history")
                        .principal(adminAuth)
                        .param("username", "bob"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].username").value("bob"));
    }

    @Test
    @DisplayName("GET /dashboard/login-history with invalid status filter returns 400 Bad Request")
    void getUserLoginHistory_InvalidStatus_Returns400() throws Exception {
        mockMvc.perform(get("/dashboard/login-history")
                        .principal(() -> "alice")
                        .param("status", "INVALID_STATUS"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value("Invalid status filter 'INVALID_STATUS'. Allowed values: SUCCESS, FAILURE"));
    }

    @Test
    @DisplayName("GET /dashboard/suspicious-activities returns 200 OK with user suspicious activity timeline")
    void getUserSuspiciousActivities_Success() throws Exception {
        SuspiciousActivityResponse item = new SuspiciousActivityResponse(10L, "10.0.0.1", "alice", "Failed attempts", LocalDateTime.now(), "HIGH");
        PageResponse<SuspiciousActivityResponse> pageResponse = new PageResponse<>(List.of(item), 0, 10, 1, 1, true, true);

        when(dashboardService.getUserSuspiciousActivities(eq("alice"), eq(0), eq(10)))
                .thenReturn(pageResponse);

        mockMvc.perform(get("/dashboard/suspicious-activities")
                        .principal(() -> "alice")
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].username").value("alice"))
                .andExpect(jsonPath("$.content[0].severity").value("HIGH"))
                .andExpect(jsonPath("$.totalElements").value(1));
    }

    @Test
    @DisplayName("GET /dashboard/suspicious-activities as USER requesting another username returns 403 Forbidden")
    void getUserSuspiciousActivities_User_OtherUser_Forbidden() throws Exception {
        UsernamePasswordAuthenticationToken userAuth = new UsernamePasswordAuthenticationToken(
                "alice", null, List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        mockMvc.perform(get("/dashboard/suspicious-activities")
                        .principal(userAuth)
                        .param("username", "bob"))
                .andExpect(status().isForbidden());

        verify(dashboardService, never()).getUserSuspiciousActivities(anyString(), anyInt(), anyInt());
    }
}
