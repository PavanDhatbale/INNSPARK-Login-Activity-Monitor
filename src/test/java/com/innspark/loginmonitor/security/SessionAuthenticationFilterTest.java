package com.innspark.loginmonitor.security;

import com.innspark.loginmonitor.entity.User;
import com.innspark.loginmonitor.entity.UserSession;
import com.innspark.loginmonitor.enums.Role;
import com.innspark.loginmonitor.service.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SessionAuthenticationFilterTest {

    @Mock
    private SessionService sessionService;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private SessionAuthenticationFilter filter;

    private User sampleUser;
    private UserSession sampleSession;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        sampleUser = new User("sessionUser", "session@example.com", "hash", Role.USER);
        sampleSession = new UserSession(sampleUser, "valid_token", LocalDateTime.now(), LocalDateTime.now(), LocalDateTime.now().plusMinutes(15));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Valid Bearer token sets authenticated user in SecurityContext")
    void doFilter_ValidBearerToken() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer valid_token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(sessionService.validateAndRefreshSession("valid_token")).thenReturn(Optional.of(sampleSession));

        filter.doFilterInternal(request, response, filterChain);

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("sessionUser", SecurityContextHolder.getContext().getAuthentication().getName());
        assertTrue(SecurityContextHolder.getContext().getAuthentication().getAuthorities()
                .stream().anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    @DisplayName("Valid X-Session-Token header sets authenticated user in SecurityContext")
    void doFilter_ValidXSessionToken() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Session-Token", "valid_token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(sessionService.validateAndRefreshSession("valid_token")).thenReturn(Optional.of(sampleSession));

        filter.doFilterInternal(request, response, filterChain);

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("sessionUser", SecurityContextHolder.getContext().getAuthentication().getName());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    @DisplayName("Invalid or expired session token does NOT set SecurityContext")
    void doFilter_InvalidToken() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer invalid_token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(sessionService.validateAndRefreshSession("invalid_token")).thenReturn(Optional.empty());

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    @DisplayName("Request without session token continues without setting SecurityContext")
    void doFilter_NoToken() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(sessionService, never()).validateAndRefreshSession(anyString());
        verify(filterChain, times(1)).doFilter(request, response);
    }
}
