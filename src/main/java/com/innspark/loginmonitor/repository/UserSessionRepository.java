package com.innspark.loginmonitor.repository;

import com.innspark.loginmonitor.entity.User;
import com.innspark.loginmonitor.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA Repository for UserSession entity.
 */
@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    Optional<UserSession> findBySessionToken(String sessionToken);

    List<UserSession> findByUserOrderByCreatedAtDesc(User user);

    @Query("SELECT s FROM UserSession s WHERE s.user.id = :userId AND s.active = true AND s.expiresAt > :now ORDER BY s.lastActivityAt DESC")
    List<UserSession> findActiveSessionsByUserId(@Param("userId") Long userId, @Param("now") LocalDateTime now);

    @Query("SELECT s FROM UserSession s WHERE s.user = :user AND s.active = true AND s.expiresAt > :now ORDER BY s.lastActivityAt DESC")
    List<UserSession> findActiveSessionsByUser(@Param("user") User user, @Param("now") LocalDateTime now);

    List<UserSession> findByActiveTrueAndExpiresAtBefore(LocalDateTime now);

    @Modifying
    @Query("UPDATE UserSession s SET s.active = false WHERE s.active = true AND s.expiresAt < :now")
    int invalidateExpiredSessions(@Param("now") LocalDateTime now);

    @Modifying
    @Query("UPDATE UserSession s SET s.active = false WHERE s.active = true AND s.user = :user")
    int invalidateAllUserSessions(@Param("user") User user);

    @Modifying
    @Query("UPDATE UserSession s SET s.active = false WHERE s.id = :sessionId")
    int invalidateSessionById(@Param("sessionId") Long sessionId);

    @Modifying
    @Query("UPDATE UserSession s SET s.active = false WHERE s.id = :sessionId AND s.user.id = :userId")
    int invalidateSessionByIdAndUserId(@Param("sessionId") Long sessionId, @Param("userId") Long userId);

    @Modifying
    @Query("DELETE FROM UserSession s WHERE s.user = :user")
    int deleteAllByUser(@Param("user") User user);
}
