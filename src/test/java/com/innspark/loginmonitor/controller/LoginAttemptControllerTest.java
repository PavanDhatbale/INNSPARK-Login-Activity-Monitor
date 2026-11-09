package com.innspark.loginmonitor.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innspark.loginmonitor.dto.LoginAttemptResponse;
import com.innspark.loginmonitor.dto.LoginRequest;
import com.innspark.loginmonitor.dto.LoginResponse;
import com.innspark.loginmonitor.enums.LoginStatus;
import com.innspark.loginmonitor.exception.GlobalExceptionHandler;
import com.innspark.loginmonitor.service.LoginAttemptService;
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
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(LoginAttemptController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(GlobalExceptionHandler.class)
class LoginAttemptControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private LoginAttemptService loginAttemptService;

    @Test
    @DisplayName("POST /login with valid credentials returns 200 OK and SUCCESS")
    void login_Success() throws Exception {
        LoginRequest request = new LoginRequest("admin", "admin123");
        LoginResponse response = new LoginResponse(1L, "admin", "127.0.0.1", LoginStatus.SUCCESS, "Login successful", LocalDateTime.now());

        when(loginAttemptService.processLogin(any(LoginRequest.class), anyString())).thenReturn(response);

        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1L))
                .andExpect(jsonPath("$.username").value("admin"))
                .andExpect(jsonPath("$.status").value("SUCCESS"))
                .andExpect(jsonPath("$.message").value("Login successful"));
    }

    @Test
    @DisplayName("POST /login with invalid credentials returns 401 Unauthorized and FAILURE")
    void login_Failure() throws Exception {
        LoginRequest request = new LoginRequest("admin", "wrongpass");
        LoginResponse response = new LoginResponse(2L, "admin", "127.0.0.1", LoginStatus.FAILURE, "Invalid username or password", LocalDateTime.now());

        when(loginAttemptService.processLogin(any(LoginRequest.class), anyString())).thenReturn(response);

        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.id").value(2L))
                .andExpect(jsonPath("$.username").value("admin"))
                .andExpect(jsonPath("$.status").value("FAILURE"))
                .andExpect(jsonPath("$.message").value("Invalid username or password"));
    }

    @Test
    @DisplayName("POST /login with missing username returns 400 Bad Request")
    void login_MissingUsername() throws Exception {
        LoginRequest request = new LoginRequest("", "admin123");

        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.validationErrors.username").exists());
    }

    @Test
    @DisplayName("POST /login with missing password returns 400 Bad Request")
    void login_MissingPassword() throws Exception {
        LoginRequest request = new LoginRequest("admin", "");

        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.validationErrors.password").exists());
    }

    @Test
    @DisplayName("GET /login unauthenticated returns 401 Unauthorized")
    void getLoginHistory_Unauthenticated_Returns401() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /login as USER viewing own history returns 200 OK")
    void getLoginHistory_User_OwnHistory_Success() throws Exception {
        UsernamePasswordAuthenticationToken userAuth = new UsernamePasswordAuthenticationToken(
                "user1", null, List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        LoginAttemptResponse attempt = new LoginAttemptResponse(1L, "user1", "10.0.0.1", LoginStatus.SUCCESS, LocalDateTime.now());
        when(loginAttemptService.getLoginHistory(eq("user1"), isNull(), isNull())).thenReturn(List.of(attempt));

        mockMvc.perform(get("/login")
                        .principal(userAuth))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].username").value("user1"))
                .andExpect(jsonPath("$[0].status").value("SUCCESS"));
    }

    @Test
    @DisplayName("GET /login as USER requesting another user's history returns 403 Forbidden")
    void getLoginHistory_User_OtherUser_Forbidden() throws Exception {
        UsernamePasswordAuthenticationToken userAuth = new UsernamePasswordAuthenticationToken(
                "user1", null, List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        mockMvc.perform(get("/login")
                        .principal(userAuth)
                        .param("username", "victimUser"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("GET /login as ADMIN returns all history when no query params passed")
    void getLoginHistory_Admin_NoParams() throws Exception {
        UsernamePasswordAuthenticationToken adminAuth = new UsernamePasswordAuthenticationToken(
                "admin1", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
        LoginAttemptResponse attempt = new LoginAttemptResponse(1L, "user1", "10.0.0.1", LoginStatus.SUCCESS, LocalDateTime.now());
        when(loginAttemptService.getLoginHistory(isNull(), isNull(), isNull())).thenReturn(List.of(attempt));

        mockMvc.perform(get("/login")
                        .principal(adminAuth))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].username").value("user1"))
                .andExpect(jsonPath("$[0].status").value("SUCCESS"));
    }

    @Test
    @DisplayName("GET /login as ADMIN with filters returns matching records for target user")
    void getLoginHistory_Admin_WithFilters() throws Exception {
        UsernamePasswordAuthenticationToken adminAuth = new UsernamePasswordAuthenticationToken(
                "admin1", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
        LoginAttemptResponse attempt = new LoginAttemptResponse(2L, "user2", "192.168.1.10", LoginStatus.FAILURE, LocalDateTime.now());
        when(loginAttemptService.getLoginHistory("user2", "192.168.1.10", LoginStatus.FAILURE)).thenReturn(List.of(attempt));

        mockMvc.perform(get("/login")
                        .principal(adminAuth)
                        .param("username", "user2")
                        .param("ipAddress", "192.168.1.10")
                        .param("status", "FAILURE"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].username").value("user2"))
                .andExpect(jsonPath("$[0].status").value("FAILURE"));
    }

    @Test
    @DisplayName("GET /login as SUPERADMIN with target user returns 200 OK")
    void getLoginHistory_Superadmin_WithTargetUser() throws Exception {
        UsernamePasswordAuthenticationToken superadminAuth = new UsernamePasswordAuthenticationToken(
                "superadmin", null, List.of(new SimpleGrantedAuthority("ROLE_SUPERADMIN"))
        );
        LoginAttemptResponse attempt = new LoginAttemptResponse(3L, "user3", "10.0.0.5", LoginStatus.SUCCESS, LocalDateTime.now());
        when(loginAttemptService.getLoginHistory("user3", null, null)).thenReturn(List.of(attempt));

        mockMvc.perform(get("/login")
                        .principal(superadminAuth)
                        .param("username", "user3"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].username").value("user3"));
    }

    @Test
    @DisplayName("GET /login with invalid status returns 400 Bad Request")
    void getLoginHistory_InvalidStatus() throws Exception {
        UsernamePasswordAuthenticationToken userAuth = new UsernamePasswordAuthenticationToken(
                "user1", null, List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        mockMvc.perform(get("/login")
                        .principal(userAuth)
                        .param("status", "INVALID_STATUS"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Invalid status filter 'INVALID_STATUS'. Allowed values: SUCCESS, FAILURE"));
    }
}
