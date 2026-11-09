package com.innspark.loginmonitor.controller;

import com.innspark.loginmonitor.config.SecurityConfig;
import com.innspark.loginmonitor.exception.GlobalExceptionHandler;
import com.innspark.loginmonitor.service.SessionService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AdminSessionController.class)
@Import({SecurityConfig.class, GlobalExceptionHandler.class})
class AdminSessionControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private SessionService sessionService;

    @Test
    @DisplayName("DELETE /admin/sessions/{sessionId} as ADMIN succeeds with 200 OK")
    @WithMockUser(username = "adminUser", roles = {"ADMIN"})
    void revokeSessionById_AsAdmin_Success() throws Exception {
        doNothing().when(sessionService).revokeSessionById(123L);

        mockMvc.perform(delete("/admin/sessions/123"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Session #123 revoked successfully"));

        verify(sessionService, times(1)).revokeSessionById(123L);
    }

    @Test
    @DisplayName("DELETE /admin/sessions/{sessionId} as USER is rejected with 403 Forbidden")
    @WithMockUser(username = "regularUser", roles = {"USER"})
    void revokeSessionById_AsUser_Forbidden() throws Exception {
        mockMvc.perform(delete("/admin/sessions/123"))
                .andExpect(status().isForbidden());

        verify(sessionService, never()).revokeSessionById(anyLong());
    }

    @Test
    @DisplayName("DELETE /admin/sessions/{sessionId} unauthenticated is rejected with 401 Unauthorized")
    void revokeSessionById_Unauthenticated_Unauthorized() throws Exception {
        mockMvc.perform(delete("/admin/sessions/123"))
                .andExpect(status().isUnauthorized());

        verify(sessionService, never()).revokeSessionById(anyLong());
    }
}
