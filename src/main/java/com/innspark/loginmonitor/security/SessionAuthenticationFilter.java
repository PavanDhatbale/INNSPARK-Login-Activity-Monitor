package com.innspark.loginmonitor.security;

import com.innspark.loginmonitor.entity.User;
import com.innspark.loginmonitor.entity.UserSession;
import com.innspark.loginmonitor.service.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Filter that intercepts incoming HTTP requests to validate database-backed session tokens.
 *
 * Behavior:
 * - Checks Authorization header (Bearer &lt;token&gt;) or X-Session-Token header.
 * - Validates that the session exists, is active, and has not exceeded the 15-minute inactivity window.
 * - Automatically refreshes the session activity timestamp on valid requests.
 * - Verifies user account is enabled before granting authentication.
 * - Sets the authenticated user principal in the Spring SecurityContext.
 */
public class SessionAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(SessionAuthenticationFilter.class);

    private final SessionService sessionService;

    public SessionAuthenticationFilter(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String token = extractToken(request);

        if (token != null && !token.trim().isEmpty()) {
            Optional<UserSession> optionalSession = sessionService.validateAndRefreshSession(token);

            if (optionalSession.isPresent()) {
                UserSession session = optionalSession.get();
                User user = session.getUser();

                if (user.isEnabled()) {
                    SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + user.getRole().name());
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            user.getUsername(),
                            null,
                            List.of(authority)
                    );

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } else {
                    log.warn("Session token presented for disabled user '{}'. Rejecting authentication.", user.getUsername());
                }
            }
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extracts token from Authorization header or X-Session-Token header.
     */
    private String extractToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7).trim();
        }

        String sessionHeader = request.getHeader("X-Session-Token");
        if (sessionHeader != null && !sessionHeader.trim().isEmpty()) {
            return sessionHeader.trim();
        }

        return null;
    }
}
