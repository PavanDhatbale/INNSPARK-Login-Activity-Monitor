package com.innspark.loginmonitor.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innspark.loginmonitor.config.SecurityConfig;
import com.innspark.loginmonitor.dto.UpdateUserRoleRequest;
import com.innspark.loginmonitor.dto.UpdateUserStatusRequest;
import com.innspark.loginmonitor.dto.UserResponse;
import com.innspark.loginmonitor.dto.UserSessionResponse;
import com.innspark.loginmonitor.enums.Role;
import com.innspark.loginmonitor.exception.GlobalExceptionHandler;
import com.innspark.loginmonitor.exception.UserNotFoundException;
import com.innspark.loginmonitor.service.SessionService;
import com.innspark.loginmonitor.service.UserService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AdminUserController.class)
@Import({SecurityConfig.class, GlobalExceptionHandler.class})
class AdminUserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private UserService userService;

    @MockBean
    private SessionService sessionService;

    // --- GET /admin/users (RBAC & Pagination) ---

    @Test
    @DisplayName("GET /admin/users with ADMIN role succeeds with 200 OK")
    @WithMockUser(username = "adminUser", roles = {"ADMIN"})
    void listUsers_AsAdmin_Success() throws Exception {
        UserResponse user = new UserResponse(1L, "bob", "bob@example.com", Role.USER, true, LocalDateTime.now());
        Page<UserResponse> page = new PageImpl<>(List.of(user));
        when(userService.listUsers(isNull(), any(Pageable.class))).thenReturn(page);

        mockMvc.perform(get("/admin/users")
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].username").value("bob"));
    }

    @Test
    @DisplayName("GET /admin/users with SUPERADMIN role succeeds with 200 OK")
    @WithMockUser(username = "superAdmin", roles = {"SUPERADMIN"})
    void listUsers_AsSuperadmin_Success() throws Exception {
        Page<UserResponse> page = new PageImpl<>(List.of());
        when(userService.listUsers(isNull(), any(Pageable.class))).thenReturn(page);

        mockMvc.perform(get("/admin/users"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("GET /admin/users with USER role is rejected with 403 Forbidden")
    @WithMockUser(username = "regularUser", roles = {"USER"})
    void listUsers_AsUser_Forbidden() throws Exception {
        mockMvc.perform(get("/admin/users"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.error").value("Forbidden"));
    }

    @Test
    @DisplayName("GET /admin/users unauthenticated is rejected with 401 Unauthorized")
    void listUsers_Unauthenticated_Unauthorized() throws Exception {
        mockMvc.perform(get("/admin/users"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"));
    }

    // --- GET /admin/users/{id} ---

    @Test
    @DisplayName("GET /admin/users/{id} as ADMIN returns 200 OK and safe UserResponse")
    @WithMockUser(username = "adminUser", roles = {"ADMIN"})
    void getUserById_Success() throws Exception {
        UserResponse user = new UserResponse(5L, "alice", "alice@example.com", Role.USER, true, LocalDateTime.now());
        when(userService.getUserById(5L)).thenReturn(user);

        mockMvc.perform(get("/admin/users/5"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(5))
                .andExpect(jsonPath("$.username").value("alice"));
    }

    @Test
    @DisplayName("GET /admin/users/{id} for nonexistent user returns 404 Not Found")
    @WithMockUser(username = "adminUser", roles = {"ADMIN"})
    void getUserById_NotFound() throws Exception {
        when(userService.getUserById(999L)).thenThrow(new UserNotFoundException("User not found with id: 999"));

        mockMvc.perform(get("/admin/users/999"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.message").value("User not found with id: 999"));
    }

    // --- PATCH /admin/users/{id}/role ---

    @Test
    @DisplayName("PATCH /admin/users/{id}/role as SUPERADMIN changing USER to ADMIN succeeds")
    @WithMockUser(username = "superAdmin", roles = {"SUPERADMIN"})
    void updateUserRole_AsSuperadmin_UserToAdmin_Success() throws Exception {
        UpdateUserRoleRequest req = new UpdateUserRoleRequest(Role.ADMIN);
        UserResponse updated = new UserResponse(5L, "alice", "alice@example.com", Role.ADMIN, true, LocalDateTime.now());

        when(userService.updateUserRole(eq(5L), eq(Role.ADMIN), eq("superAdmin"))).thenReturn(updated);

        mockMvc.perform(patch("/admin/users/5/role")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ADMIN"));
    }

    @Test
    @DisplayName("PATCH /admin/users/{id}/role as SUPERADMIN changing ADMIN to USER succeeds")
    @WithMockUser(username = "superAdmin", roles = {"SUPERADMIN"})
    void updateUserRole_AsSuperadmin_AdminToUser_Success() throws Exception {
        UpdateUserRoleRequest req = new UpdateUserRoleRequest(Role.USER);
        UserResponse updated = new UserResponse(5L, "charlie", "charlie@example.com", Role.USER, true, LocalDateTime.now());

        when(userService.updateUserRole(eq(5L), eq(Role.USER), eq("superAdmin"))).thenReturn(updated);

        mockMvc.perform(patch("/admin/users/5/role")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    @DisplayName("PATCH /admin/users/{id}/role as SUPERADMIN promoting user to SUPERADMIN succeeds")
    @WithMockUser(username = "superAdmin", roles = {"SUPERADMIN"})
    void updateUserRole_AsSuperadmin_ToSuperadmin_Success() throws Exception {
        UpdateUserRoleRequest req = new UpdateUserRoleRequest(Role.SUPERADMIN);
        UserResponse updated = new UserResponse(5L, "alice", "alice@example.com", Role.SUPERADMIN, true, LocalDateTime.now());

        when(userService.updateUserRole(eq(5L), eq(Role.SUPERADMIN), eq("superAdmin"))).thenReturn(updated);

        mockMvc.perform(patch("/admin/users/5/role")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("SUPERADMIN"));
    }

    @Test
    @DisplayName("PUT /admin/users/{id}/role method is supported and succeeds")
    @WithMockUser(username = "superAdmin", roles = {"SUPERADMIN"})
    void updateUserRole_PutMethod_Success() throws Exception {
        UpdateUserRoleRequest req = new UpdateUserRoleRequest(Role.ADMIN);
        UserResponse updated = new UserResponse(5L, "alice", "alice@example.com", Role.ADMIN, true, LocalDateTime.now());

        when(userService.updateUserRole(eq(5L), eq(Role.ADMIN), eq("superAdmin"))).thenReturn(updated);

        mockMvc.perform(put("/admin/users/5/role")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ADMIN"));
    }

    @Test
    @DisplayName("PATCH /admin/users/{id}/role as ADMIN attempting to assign SUPERADMIN is rejected with 403")
    @WithMockUser(username = "adminUser", roles = {"ADMIN"})
    void updateUserRole_AsAdmin_ToSuperadmin_Forbidden() throws Exception {
        UpdateUserRoleRequest req = new UpdateUserRoleRequest(Role.SUPERADMIN);

        when(userService.updateUserRole(eq(5L), eq(Role.SUPERADMIN), eq("adminUser")))
                .thenThrow(new AccessDeniedException("Only SUPERADMIN users can grant SUPERADMIN privileges"));

        mockMvc.perform(patch("/admin/users/5/role")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("Only SUPERADMIN users can grant SUPERADMIN privileges"));
    }

    @Test
    @DisplayName("PATCH /admin/users/{id}/role unauthenticated returns 401 Unauthorized")
    void updateUserRole_Unauthenticated_Unauthorized() throws Exception {
        UpdateUserRoleRequest req = new UpdateUserRoleRequest(Role.ADMIN);

        mockMvc.perform(patch("/admin/users/5/role")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("PATCH /admin/users/{id}/role with invalid role returns 400 Bad Request")
    @WithMockUser(username = "superAdmin", roles = {"SUPERADMIN"})
    void updateUserRole_InvalidRole_BadRequest() throws Exception {
        mockMvc.perform(patch("/admin/users/5/role")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"INVALID_ROLE\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("PATCH /admin/users/{id}/role as ADMIN succeeds")
    @WithMockUser(username = "adminUser", roles = {"ADMIN"})
    void updateUserRole_Success() throws Exception {
        UpdateUserRoleRequest req = new UpdateUserRoleRequest(Role.ADMIN);
        UserResponse updated = new UserResponse(5L, "alice", "alice@example.com", Role.ADMIN, true, LocalDateTime.now());

        when(userService.updateUserRole(eq(5L), eq(Role.ADMIN), eq("adminUser"))).thenReturn(updated);

        mockMvc.perform(patch("/admin/users/5/role")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ADMIN"));
    }

    @Test
    @DisplayName("PATCH /admin/users/{id}/role as ADMIN attempting self-modification returns 403 Forbidden")
    @WithMockUser(username = "adminUser", roles = {"ADMIN"})
    void updateUserRole_SelfModification_Forbidden() throws Exception {
        UpdateUserRoleRequest req = new UpdateUserRoleRequest(Role.SUPERADMIN);

        when(userService.updateUserRole(eq(1L), eq(Role.SUPERADMIN), eq("adminUser")))
                .thenThrow(new AccessDeniedException("Users are not permitted to modify their own role"));

        mockMvc.perform(patch("/admin/users/1/role")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.message").value("Users are not permitted to modify their own role"));
    }

    @Test
    @DisplayName("PATCH /admin/users/{id}/role as USER returns 403 Forbidden")
    @WithMockUser(username = "regularUser", roles = {"USER"})
    void updateUserRole_AsUser_Forbidden() throws Exception {
        UpdateUserRoleRequest req = new UpdateUserRoleRequest(Role.ADMIN);

        mockMvc.perform(patch("/admin/users/5/role")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isForbidden());
    }

    // --- PATCH /admin/users/{id}/status ---

    @Test
    @DisplayName("PATCH /admin/users/{id}/status as ADMIN disabling account succeeds")
    @WithMockUser(username = "adminUser", roles = {"ADMIN"})
    void updateUserStatus_Success() throws Exception {
        UpdateUserStatusRequest req = new UpdateUserStatusRequest(false);
        UserResponse updated = new UserResponse(5L, "alice", "alice@example.com", Role.USER, false, LocalDateTime.now());

        when(userService.updateUserStatus(eq(5L), eq(false), eq("adminUser"))).thenReturn(updated);

        mockMvc.perform(patch("/admin/users/5/status")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false));
    }

    @Test
    @DisplayName("PATCH /admin/users/{id}/status as ADMIN disabling self returns 403 Forbidden")
    @WithMockUser(username = "adminUser", roles = {"ADMIN"})
    void updateUserStatus_SelfDisable_Forbidden() throws Exception {
        UpdateUserStatusRequest req = new UpdateUserStatusRequest(false);

        when(userService.updateUserStatus(eq(1L), eq(false), eq("adminUser")))
                .thenThrow(new AccessDeniedException("Administrators are not permitted to disable their own account"));

        mockMvc.perform(patch("/admin/users/1/status")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.message").value("Administrators are not permitted to disable their own account"));
    }

    // --- DELETE /admin/users/{id} ---

    @Test
    @DisplayName("DELETE /admin/users/{id} as SUPERADMIN succeeds with 200 OK")
    @WithMockUser(username = "saUser", roles = {"SUPERADMIN"})
    void deleteUser_AsSuperadmin_Success() throws Exception {
        doNothing().when(userService).deleteUser(5L, "saUser");

        mockMvc.perform(delete("/admin/users/5"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User deleted successfully"));

        verify(userService, times(1)).deleteUser(5L, "saUser");
    }

    @Test
    @DisplayName("DELETE /admin/users/{id} as ADMIN is rejected with 403 Forbidden")
    @WithMockUser(username = "adminUser", roles = {"ADMIN"})
    void deleteUser_AsAdmin_Forbidden() throws Exception {
        mockMvc.perform(delete("/admin/users/5"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403));

        verify(userService, never()).deleteUser(anyLong(), anyString());
    }

    @Test
    @DisplayName("DELETE /admin/users/{id} as USER is rejected with 403 Forbidden")
    @WithMockUser(username = "regularUser", roles = {"USER"})
    void deleteUser_AsUser_Forbidden() throws Exception {
        mockMvc.perform(delete("/admin/users/5"))
                .andExpect(status().isForbidden());

        verify(userService, never()).deleteUser(anyLong(), anyString());
    }

    // --- GET /admin/users/{id}/sessions (Admin Active Sessions Inspection) ---

    @Test
    @DisplayName("GET /admin/users/{id}/sessions as ADMIN succeeds with 200 OK")
    @WithMockUser(username = "adminUser", roles = {"ADMIN"})
    void getUserSessions_AsAdmin_Success() throws Exception {
        LocalDateTime now = LocalDateTime.now();
        UserSessionResponse s = new UserSessionResponse(100L, 5L, "alice", now.minusMinutes(2), now.minusMinutes(1), now.plusMinutes(14), true);
        when(sessionService.getActiveSessionsForUser(5L)).thenReturn(List.of(s));

        mockMvc.perform(get("/admin/users/5/sessions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(100))
                .andExpect(jsonPath("$[0].userId").value(5))
                .andExpect(jsonPath("$[0].username").value("alice"))
                .andExpect(jsonPath("$[0].active").value(true));

        verify(sessionService, times(1)).getActiveSessionsForUser(5L);
    }

    @Test
    @DisplayName("GET /admin/users/{id}/sessions as USER is rejected with 403 Forbidden")
    @WithMockUser(username = "regularUser", roles = {"USER"})
    void getUserSessions_AsUser_Forbidden() throws Exception {
        mockMvc.perform(get("/admin/users/5/sessions"))
                .andExpect(status().isForbidden());

        verify(sessionService, never()).getActiveSessionsForUser(anyLong());
    }

    // --- DELETE /admin/users/{userId}/sessions/{sessionId} (Admin Session Revocation) ---

    @Test
    @DisplayName("DELETE /admin/users/{userId}/sessions/{sessionId} as ADMIN succeeds with 200 OK")
    @WithMockUser(username = "adminUser", roles = {"ADMIN"})
    void revokeSession_AsAdmin_Success() throws Exception {
        doNothing().when(sessionService).revokeSession(5L, 100L);

        mockMvc.perform(delete("/admin/users/5/sessions/100"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Session #100 revoked successfully"));

        verify(sessionService, times(1)).revokeSession(5L, 100L);
    }

    @Test
    @DisplayName("DELETE /admin/users/{userId}/sessions/{sessionId} as SUPERADMIN succeeds with 200 OK")
    @WithMockUser(username = "saUser", roles = {"SUPERADMIN"})
    void revokeSession_AsSuperadmin_Success() throws Exception {
        doNothing().when(sessionService).revokeSession(5L, 100L);

        mockMvc.perform(delete("/admin/users/5/sessions/100"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Session #100 revoked successfully"));

        verify(sessionService, times(1)).revokeSession(5L, 100L);
    }

    @Test
    @DisplayName("DELETE /admin/users/{userId}/sessions/{sessionId} as USER is rejected with 403 Forbidden")
    @WithMockUser(username = "regularUser", roles = {"USER"})
    void revokeSession_AsUser_Forbidden() throws Exception {
        mockMvc.perform(delete("/admin/users/5/sessions/100"))
                .andExpect(status().isForbidden());

        verify(sessionService, never()).revokeSession(anyLong(), anyLong());
    }

    @Test
    @DisplayName("DELETE /admin/users/{userId}/sessions/{sessionId} unauthenticated is rejected with 401 Unauthorized")
    void revokeSession_Unauthenticated_Unauthorized() throws Exception {
        mockMvc.perform(delete("/admin/users/5/sessions/100"))
                .andExpect(status().isUnauthorized());

        verify(sessionService, never()).revokeSession(anyLong(), anyLong());
    }

    // --- DELETE /admin/users/{userId}/sessions (Revoke All Sessions for User) ---

    @Test
    @DisplayName("DELETE /admin/users/{userId}/sessions as ADMIN succeeds with 200 OK and revoked count")
    @WithMockUser(username = "adminUser", roles = {"ADMIN"})
    void revokeAllSessions_AsAdmin_Success() throws Exception {
        when(sessionService.revokeAllSessionsForUser(5L)).thenReturn(2);

        mockMvc.perform(delete("/admin/users/5/sessions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("2 active session(s) revoked successfully"));

        verify(sessionService, times(1)).revokeAllSessionsForUser(5L);
    }

    @Test
    @DisplayName("DELETE /admin/users/{userId}/sessions as USER is rejected with 403 Forbidden")
    @WithMockUser(username = "regularUser", roles = {"USER"})
    void revokeAllSessions_AsUser_Forbidden() throws Exception {
        mockMvc.perform(delete("/admin/users/5/sessions"))
                .andExpect(status().isForbidden());

        verify(sessionService, never()).revokeAllSessionsForUser(anyLong());
    }

    @Test
    @DisplayName("DELETE /admin/users/{userId}/sessions unauthenticated is rejected with 401 Unauthorized")
    void revokeAllSessions_Unauthenticated_Unauthorized() throws Exception {
        mockMvc.perform(delete("/admin/users/5/sessions"))
                .andExpect(status().isUnauthorized());

        verify(sessionService, never()).revokeAllSessionsForUser(anyLong());
    }
}
