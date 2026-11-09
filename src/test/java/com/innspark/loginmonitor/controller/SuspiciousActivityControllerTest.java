package com.innspark.loginmonitor.controller;

import com.innspark.loginmonitor.config.SecurityConfig;
import com.innspark.loginmonitor.dto.SuspiciousActivityResponse;
import com.innspark.loginmonitor.exception.GlobalExceptionHandler;
import com.innspark.loginmonitor.service.SessionService;
import com.innspark.loginmonitor.service.SuspiciousActivityService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(SuspiciousActivityController.class)
@Import({SecurityConfig.class, GlobalExceptionHandler.class})
class SuspiciousActivityControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private SuspiciousActivityService suspiciousActivityService;

    @MockBean
    private SessionService sessionService;

    @Test
    @WithMockUser(username = "admin_user", roles = {"ADMIN"})
    @DisplayName("GET /suspicious returns 200 OK for ADMIN role when empty")
    void getSuspicious_AdminRole_EmptyList() throws Exception {
        when(suspiciousActivityService.getAllSuspiciousActivities()).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/suspicious")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));

        verify(suspiciousActivityService, times(1)).getAllSuspiciousActivities();
    }

    @Test
    @WithMockUser(username = "admin_user", roles = {"ADMIN"})
    @DisplayName("GET /suspicious returns 200 OK for ADMIN role with activities")
    void getSuspicious_AdminRole_WithActivities() throws Exception {
        SuspiciousActivityResponse response = new SuspiciousActivityResponse(
                1L,
                "192.168.1.100",
                "admin",
                "Multiple failed login attempts from the same IP within 10 minutes",
                LocalDateTime.now()
        );

        when(suspiciousActivityService.getAllSuspiciousActivities()).thenReturn(List.of(response));

        mockMvc.perform(get("/suspicious")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(1L))
                .andExpect(jsonPath("$[0].ipAddress").value("192.168.1.100"))
                .andExpect(jsonPath("$[0].username").value("admin"))
                .andExpect(jsonPath("$[0].reason").value("Multiple failed login attempts from the same IP within 10 minutes"));

        verify(suspiciousActivityService, times(1)).getAllSuspiciousActivities();
    }

    @Test
    @WithMockUser(username = "super_admin", roles = {"SUPERADMIN"})
    @DisplayName("GET /suspicious returns 200 OK for SUPERADMIN role")
    void getSuspicious_SuperAdminRole_Success() throws Exception {
        when(suspiciousActivityService.getAllSuspiciousActivities()).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/suspicious")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        verify(suspiciousActivityService, times(1)).getAllSuspiciousActivities();
    }

    @Test
    @WithMockUser(username = "regular_user", roles = {"USER"})
    @DisplayName("GET /suspicious returns 403 Forbidden for regular USER role")
    void getSuspicious_UserRole_Forbidden() throws Exception {
        mockMvc.perform(get("/suspicious")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());

        verify(suspiciousActivityService, never()).getAllSuspiciousActivities();
    }

    @Test
    @DisplayName("GET /suspicious returns 401 Unauthorized when unauthenticated")
    void getSuspicious_Unauthenticated_Returns401() throws Exception {
        mockMvc.perform(get("/suspicious")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());

        verify(suspiciousActivityService, never()).getAllSuspiciousActivities();
    }
}
