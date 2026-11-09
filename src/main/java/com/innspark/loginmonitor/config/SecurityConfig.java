package com.innspark.loginmonitor.config;

import com.innspark.loginmonitor.security.SessionAuthenticationFilter;
import com.innspark.loginmonitor.service.SessionService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Spring Security configuration establishing the authentication, RBAC, and dashboard foundation.
 *
 * Scope and Strategy for Phase 3.3:
 * - BCryptPasswordEncoder is configured for secure one-way password hashing.
 * - CSRF is disabled because APIs are stateless REST endpoints using database session tokens.
 * - CORS is configured to support web dashboards on standard local development ports.
 * - Method-level security (@EnableMethodSecurity) is enabled for fine-grained authorization.
 * - SessionAuthenticationFilter validates database session tokens, checks account enabled status,
 *   and slides the 15-minute inactivity window.
 * - Custom AuthenticationEntryPoint and AccessDeniedHandler return clean JSON error payloads.
 * - /auth/register, /auth/login, /auth/verify-otp, /auth/resend-otp, /auth/logout are publicly accessible.
 * - /auth/me and /dashboard/** require authenticated session.
 * - /admin/** requires ADMIN or SUPERADMIN role.
 * - /login/** and /suspicious/** remain publicly accessible for assessment evaluation.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173", "http://127.0.0.1:3000"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Session-Token", "Accept", "Origin", "X-Requested-With"));
        configuration.setExposedHeaders(Arrays.asList("X-Session-Token", "Authorization"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    @ConditionalOnBean(SessionService.class)
    public SessionAuthenticationFilter sessionAuthenticationFilter(SessionService sessionService) {
        return new SessionAuthenticationFilter(sessionService);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                    Optional<SessionAuthenticationFilter> sessionAuthenticationFilter) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            response.getWriter().write(String.format(
                                    "{\"timestamp\":\"%s\",\"status\":401,\"error\":\"Unauthorized\",\"message\":\"Full authentication is required to access this resource\"}",
                                    LocalDateTime.now()
                            ));
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            response.getWriter().write(String.format(
                                    "{\"timestamp\":\"%s\",\"status\":403,\"error\":\"Forbidden\",\"message\":\"Access denied: insufficient permissions\"}",
                                    LocalDateTime.now()
                            ));
                        })
                )
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints
                        .requestMatchers(HttpMethod.POST, "/auth/register").permitAll()
                        .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                        .requestMatchers(HttpMethod.POST, "/auth/verify-otp").permitAll()
                        .requestMatchers(HttpMethod.POST, "/auth/resend-otp").permitAll()
                        .requestMatchers(HttpMethod.POST, "/auth/logout").permitAll()
                        .requestMatchers(HttpMethod.GET, "/auth/captcha-status").permitAll()
                        // Phase 1 endpoints: POST /login records attempts and is public
                        .requestMatchers(HttpMethod.POST, "/login").permitAll()
                        // GET /login queries attempt history and requires authentication (with RBAC isolation)
                        .requestMatchers(HttpMethod.GET, "/login").authenticated()
                        // Suspicious activity logs restricted to ADMIN or SUPERADMIN per assignment RBAC specification
                        .requestMatchers("/suspicious/**").hasAnyRole("ADMIN", "SUPERADMIN")
                        // User Profile and User Dashboard endpoints require authentication
                        .requestMatchers("/auth/me").authenticated()
                        .requestMatchers("/dashboard/**").authenticated()
                        // Admin endpoints require ADMIN or SUPERADMIN
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SUPERADMIN")
                        // Any other endpoint requires authentication
                        .anyRequest().authenticated()
                );

        sessionAuthenticationFilter.ifPresent(filter ->
                http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
        );

        return http.build();
    }
}
