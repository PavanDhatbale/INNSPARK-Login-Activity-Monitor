package com.innspark.loginmonitor.controller;

import com.innspark.loginmonitor.config.SecurityConfig;
import com.innspark.loginmonitor.dto.AdminDashboardStatsResponse;
import com.innspark.loginmonitor.exception.GlobalExceptionHandler;
import com.innspark.loginmonitor.service.DashboardService;
import com.innspark.loginmonitor.service.SessionService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AdminDashboardController.class)
@Import({SecurityConfig.class, GlobalExceptionHandler.class})
class AdminDashboardControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DashboardService dashboardService;

    @MockBean
    private SessionService sessionService;

    @Test
    @WithMockUser(username = "admin_user", roles = {"ADMIN"})
    @DisplayName("GET /admin/dashboard/stats returns 200 OK for ADMIN role")
    void getAdminStats_AdminRole_Success() throws Exception {
        AdminDashboardStatsResponse response = new AdminDashboardStatsResponse(25, 250, 200, 50, 10, 3);
        when(dashboardService.getAdminStats()).thenReturn(response);

        mockMvc.perform(get("/admin/dashboard/stats")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalUsers").value(25))
                .andExpect(jsonPath("$.totalLoginAttempts").value(250))
                .andExpect(jsonPath("$.totalSuccessfulLogins").value(200))
                .andExpect(jsonPath("$.totalFailedLogins").value(50))
                .andExpect(jsonPath("$.totalSuspiciousActivities").value(10))
                .andExpect(jsonPath("$.recentSuspiciousActivities").value(3));

        verify(dashboardService, times(1)).getAdminStats();
    }

    @Test
    @WithMockUser(username = "super_admin", roles = {"SUPERADMIN"})
    @DisplayName("GET /admin/dashboard/stats returns 200 OK for SUPERADMIN role")
    void getAdminStats_SuperAdminRole_Success() throws Exception {
        AdminDashboardStatsResponse response = new AdminDashboardStatsResponse(50, 500, 450, 50, 12, 1);
        when(dashboardService.getAdminStats()).thenReturn(response);

        mockMvc.perform(get("/admin/dashboard/stats")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalUsers").value(50))
                .andExpect(jsonPath("$.totalLoginAttempts").value(500));

        verify(dashboardService, times(1)).getAdminStats();
    }

    @Test
    @WithMockUser(username = "normal_user", roles = {"USER"})
    @DisplayName("GET /admin/dashboard/stats returns 403 Forbidden for USER role")
    void getAdminStats_UserRole_Forbidden() throws Exception {
        mockMvc.perform(get("/admin/dashboard/stats")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());

        verify(dashboardService, never()).getAdminStats();
    }

    @Test
    @DisplayName("GET /admin/dashboard/stats returns 401 Unauthorized when unauthenticated")
    void getAdminStats_Unauthenticated_Returns401() throws Exception {
        mockMvc.perform(get("/admin/dashboard/stats")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());

        verify(dashboardService, never()).getAdminStats();
    }
}
