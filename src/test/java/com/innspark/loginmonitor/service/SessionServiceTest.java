package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.dto.UserSessionResponse;
import com.innspark.loginmonitor.entity.User;
import com.innspark.loginmonitor.entity.UserSession;
import com.innspark.loginmonitor.enums.Role;
import com.innspark.loginmonitor.exception.SessionNotFoundException;
import com.innspark.loginmonitor.exception.UserNotFoundException;
import com.innspark.loginmonitor.repository.UserRepository;
import com.innspark.loginmonitor.repository.UserSessionRepository;
import com.innspark.loginmonitor.service.impl.SessionServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SessionServiceTest {

    @Mock
    private UserSessionRepository userSessionRepository;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private SessionServiceImpl sessionService;

    private User sampleUser;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(sessionService, "sessionTimeoutMinutes", 15);
        sampleUser = new User("testuser", "test@example.com", "$2a$10$hash", Role.USER);
        sampleUser.setId(10L);
    }

    @Test
    @DisplayName("Should create an active session with secure unpredictable token and 15-minute expiration")
    void createSession_Success() {
        when(userSessionRepository.save(any(UserSession.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UserSession session = sessionService.createSession(sampleUser);

        assertNotNull(session);
        assertEquals(sampleUser, session.getUser());
        assertNotNull(session.getSessionToken());
        assertTrue(session.getSessionToken().length() >= 32);
        assertTrue(session.isActive());
        assertNotNull(session.getExpiresAt());
        assertTrue(session.getExpiresAt().isAfter(LocalDateTime.now().plusMinutes(14)));

        ArgumentCaptor<UserSession> captor = ArgumentCaptor.forClass(UserSession.class);
        verify(userSessionRepository, times(1)).save(captor.capture());
        assertTrue(captor.getValue().isActive());
    }

    @Test
    @DisplayName("Should validate active session and slide the 15-minute inactivity window")
    void validateAndRefreshSession_ActiveSessionRefreshed() {
        LocalDateTime now = LocalDateTime.now();
        UserSession activeSession = new UserSession(sampleUser, "token123", now.minusMinutes(2), now.minusMinutes(2), now.plusMinutes(13));
        activeSession.setActive(true);

        when(userSessionRepository.findBySessionToken(anyString())).thenReturn(Optional.of(activeSession));
        when(userSessionRepository.save(any(UserSession.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Optional<UserSession> result = sessionService.validateAndRefreshSession("token123");

        assertTrue(result.isPresent());
        UserSession refreshed = result.get();
        assertTrue(refreshed.getLastActivityAt().isAfter(now.minusSeconds(2)));
        assertTrue(refreshed.getExpiresAt().isAfter(now.plusMinutes(14)));
        verify(userSessionRepository, times(1)).save(refreshed);
    }

    @Test
    @DisplayName("Should reject and deactivate expired session")
    void validateAndRefreshSession_ExpiredSession() {
        LocalDateTime past = LocalDateTime.now().minusMinutes(20);
        UserSession expiredSession = new UserSession(sampleUser, "expiredToken", past, past, past.plusMinutes(15));
        expiredSession.setActive(true);

        when(userSessionRepository.findBySessionToken(anyString())).thenReturn(Optional.of(expiredSession));

        Optional<UserSession> result = sessionService.validateAndRefreshSession("expiredToken");

        assertTrue(result.isEmpty());
        assertFalse(expiredSession.isActive());
        verify(userSessionRepository, times(1)).save(expiredSession);
    }

    @Test
    @DisplayName("Should invalidate session on logout")
    void invalidateSession_Success() {
        UserSession session = new UserSession(sampleUser, "activeToken", LocalDateTime.now(), LocalDateTime.now(), LocalDateTime.now().plusMinutes(15));
        session.setActive(true);

        when(userSessionRepository.findBySessionToken(anyString())).thenReturn(Optional.of(session));

        sessionService.invalidateSession("activeToken");

        assertFalse(session.isActive());
        verify(userSessionRepository, times(1)).save(session);
    }

    @Test
    @DisplayName("Should invoke repository cleanup query for expired sessions")
    void cleanExpiredSessions_InvokesRepository() {
        when(userSessionRepository.invalidateExpiredSessions(any(LocalDateTime.class))).thenReturn(3);

        sessionService.cleanExpiredSessions();

        verify(userSessionRepository, times(1)).invalidateExpiredSessions(any(LocalDateTime.class));
    }

    @Test
    @DisplayName("Should deactivate session if last activity was more than 15 minutes ago")
    void validateAndRefreshSession_InactiveBeyond15Minutes_Deactivated() {
        LocalDateTime now = LocalDateTime.now();
        // Session created 30m ago, last activity 16m ago, expiresAt was set to 1m ago
        UserSession inactiveSession = new UserSession(sampleUser, "inactiveToken", now.minusMinutes(30), now.minusMinutes(16), now.minusMinutes(1));
        inactiveSession.setActive(true);

        when(userSessionRepository.findBySessionToken(anyString())).thenReturn(Optional.of(inactiveSession));

        Optional<UserSession> result = sessionService.validateAndRefreshSession("inactiveToken");

        assertTrue(result.isEmpty(), "Session inactive for > 15 minutes must be rejected");
        assertFalse(inactiveSession.isActive(), "Session must be marked inactive in database");
        verify(userSessionRepository, times(1)).save(inactiveSession);
    }

    @Test
    @DisplayName("Should retrieve active unexpired sessions for user")
    void getActiveSessionsForUser_Success() {
        LocalDateTime now = LocalDateTime.now();
        UserSession s1 = new UserSession(sampleUser, "tok1", now.minusMinutes(5), now.minusMinutes(1), now.plusMinutes(14));
        s1.setId(50L);

        when(userSessionRepository.findActiveSessionsByUserId(eq(10L), any(LocalDateTime.class)))
                .thenReturn(List.of(s1));

        List<UserSessionResponse> sessions = sessionService.getActiveSessionsForUser(10L);

        assertNotNull(sessions);
        assertEquals(1, sessions.size());
        assertEquals(50L, sessions.get(0).getId());
        assertEquals(10L, sessions.get(0).getUserId());
        assertEquals("testuser", sessions.get(0).getUsername());
        assertTrue(sessions.get(0).isActive());
    }

    @Test
    @DisplayName("Should return empty list when user ID is null or has no active sessions")
    void getActiveSessionsForUser_Empty() {
        List<UserSessionResponse> nullResult = sessionService.getActiveSessionsForUser(null);
        assertTrue(nullResult.isEmpty());

        when(userSessionRepository.findActiveSessionsByUserId(eq(99L), any(LocalDateTime.class)))
                .thenReturn(List.of());

        List<UserSessionResponse> emptyResult = sessionService.getActiveSessionsForUser(99L);
        assertTrue(emptyResult.isEmpty());
    }

    @Test
    @DisplayName("Should successfully revoke a specific active session belonging to user")
    void revokeSession_Success() {
        UserSession activeSession = new UserSession(sampleUser, "tokenHash", LocalDateTime.now(), LocalDateTime.now(), LocalDateTime.now().plusMinutes(15));
        activeSession.setId(101L);
        activeSession.setActive(true);

        when(userRepository.findById(10L)).thenReturn(Optional.of(sampleUser));
        when(userSessionRepository.findById(101L)).thenReturn(Optional.of(activeSession));
        when(userSessionRepository.saveAndFlush(any(UserSession.class))).thenAnswer(invocation -> invocation.getArgument(0));

        sessionService.revokeSession(10L, 101L);

        assertFalse(activeSession.isActive());
        verify(userSessionRepository, times(1)).saveAndFlush(activeSession);
        verify(userSessionRepository, times(1)).invalidateSessionByIdAndUserId(101L, 10L);
    }

    @Test
    @DisplayName("Should throw SessionNotFoundException when revoking non-existent session")
    void revokeSession_NotFound_ThrowsException() {
        when(userRepository.findById(10L)).thenReturn(Optional.of(sampleUser));
        when(userSessionRepository.findById(999L)).thenReturn(Optional.empty());

        assertThrows(SessionNotFoundException.class, () -> sessionService.revokeSession(10L, 999L));
        verify(userSessionRepository, never()).saveAndFlush(any());
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when revoking session belonging to another user")
    void revokeSession_UserMismatch_ThrowsException() {
        User anotherUser = new User("otheruser", "other@example.com", "hash", Role.USER);
        anotherUser.setId(20L);

        UserSession otherUserSession = new UserSession(anotherUser, "tokenHash2", LocalDateTime.now(), LocalDateTime.now(), LocalDateTime.now().plusMinutes(15));
        otherUserSession.setId(202L);

        when(userRepository.findById(10L)).thenReturn(Optional.of(sampleUser));
        when(userSessionRepository.findById(202L)).thenReturn(Optional.of(otherUserSession));

        assertThrows(IllegalArgumentException.class, () -> sessionService.revokeSession(10L, 202L));
        verify(userSessionRepository, never()).saveAndFlush(any());
    }

    @Test
    @DisplayName("Should revoke all active sessions for a user and return count")
    void revokeAllSessionsForUser_Success() {
        when(userRepository.findById(10L)).thenReturn(Optional.of(sampleUser));
        when(userSessionRepository.invalidateAllUserSessions(sampleUser)).thenReturn(3);

        int revokedCount = sessionService.revokeAllSessionsForUser(10L);

        assertEquals(3, revokedCount);
        verify(userSessionRepository, times(1)).invalidateAllUserSessions(sampleUser);
    }

    @Test
    @DisplayName("Should revoke session directly by ID")
    void revokeSessionById_Success() {
        UserSession activeSession = new UserSession(sampleUser, "tokenHash3", LocalDateTime.now(), LocalDateTime.now(), LocalDateTime.now().plusMinutes(15));
        activeSession.setId(303L);
        activeSession.setActive(true);

        when(userSessionRepository.findById(303L)).thenReturn(Optional.of(activeSession));
        when(userSessionRepository.saveAndFlush(any(UserSession.class))).thenAnswer(invocation -> invocation.getArgument(0));

        sessionService.revokeSessionById(303L);

        assertFalse(activeSession.isActive());
        verify(userSessionRepository, times(1)).saveAndFlush(activeSession);
        verify(userSessionRepository, times(1)).invalidateSessionById(303L);
    }
}
