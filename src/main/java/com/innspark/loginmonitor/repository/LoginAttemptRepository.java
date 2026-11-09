package com.innspark.loginmonitor.repository;

import com.innspark.loginmonitor.entity.LoginAttempt;
import com.innspark.loginmonitor.enums.LoginStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA Repository for LoginAttempt entity.
 */
@Repository
public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

    // --- Dashboard Aggregations and Queries (Phase 3.3) ---

    long countByUsernameIgnoreCase(String username);

    long countByUsernameIgnoreCaseAndStatus(String username, LoginStatus status);

    Optional<LoginAttempt> findFirstByUsernameIgnoreCaseOrderByTimestampDesc(String username);

    Optional<LoginAttempt> findFirstByUsernameIgnoreCaseAndStatusOrderByTimestampDesc(String username, LoginStatus status);

    Page<LoginAttempt> findByUsernameIgnoreCaseOrderByTimestampDesc(String username, Pageable pageable);

    Page<LoginAttempt> findByUsernameIgnoreCaseAndStatusOrderByTimestampDesc(String username, LoginStatus status, Pageable pageable);

    long countByStatus(LoginStatus status);

    List<LoginAttempt> findByUsernameIgnoreCaseOrderByTimestampDesc(String username);

    List<LoginAttempt> findByIpAddressOrderByTimestampDesc(String ipAddress);

    List<LoginAttempt> findByStatusOrderByTimestampDesc(LoginStatus status);

    List<LoginAttempt> findByTimestampBetweenOrderByTimestampDesc(LocalDateTime start, LocalDateTime end);

    /**
     * Finds login attempts with flexible filtering across optional parameters: username, ipAddress, and status.
     * When any parameter is null, that filter condition is ignored.
     * Results are ordered with most recent attempts first.
     */
    @Query("SELECT l FROM LoginAttempt l WHERE " +
           "(:username IS NULL OR LOWER(l.username) = LOWER(:username)) AND " +
           "(:ipAddress IS NULL OR l.ipAddress = :ipAddress) AND " +
           "(:status IS NULL OR l.status = :status) " +
           "ORDER BY l.timestamp DESC")
    List<LoginAttempt> filterLoginAttempts(
            @Param("username") String username,
            @Param("ipAddress") String ipAddress,
            @Param("status") LoginStatus status
    );

    /**
     * Counts failed login attempts from a given IP within a time window.
     */
    @Query("SELECT COUNT(l) FROM LoginAttempt l WHERE l.ipAddress = :ipAddress AND l.status = :status AND l.timestamp >= :since")
    long countByIpAddressAndStatusSince(
            @Param("ipAddress") String ipAddress,
            @Param("status") LoginStatus status,
            @Param("since") LocalDateTime since
    );

    /**
     * Counts failed login attempts for a given username within a time window.
     */
    @Query("SELECT COUNT(l) FROM LoginAttempt l WHERE LOWER(l.username) = LOWER(:username) AND l.status = :status AND l.timestamp >= :since")
    long countByUsernameAndStatusSince(
            @Param("username") String username,
            @Param("status") LoginStatus status,
            @Param("since") LocalDateTime since
    );

    /**
     * Retrieves recent attempts for a user since a given time, ordered newest first.
     */
    @Query("SELECT l FROM LoginAttempt l WHERE LOWER(l.username) = LOWER(:username) AND l.timestamp >= :since ORDER BY l.timestamp DESC")
    List<LoginAttempt> findRecentAttemptsByUsername(
            @Param("username") String username,
            @Param("since") LocalDateTime since
    );

    /**
     * Finds all IP addresses with failed login counts reaching or exceeding the threshold strictly within the time window [since, until].
     * Excludes null/empty IPs and future-dated records (where timestamp > until) to prevent phantom triggers.
     */
    @Query("SELECT l.ipAddress FROM LoginAttempt l " +
           "WHERE l.status = :status " +
           "AND l.ipAddress IS NOT NULL AND TRIM(l.ipAddress) != '' " +
           "AND l.timestamp >= :since AND l.timestamp <= :until " +
           "GROUP BY l.ipAddress HAVING COUNT(l) >= :threshold")
    List<String> findIpsWithFailureCountExceeding(
            @Param("status") LoginStatus status,
            @Param("since") LocalDateTime since,
            @Param("until") LocalDateTime until,
            @Param("threshold") long threshold
    );

    /**
     * Finds all usernames with failed login counts reaching or exceeding the threshold strictly within the time window [since, until].
     * Excludes null/empty usernames and future-dated records (where timestamp > until) to prevent phantom triggers.
     */
    @Query("SELECT l.username FROM LoginAttempt l " +
           "WHERE l.status = :status " +
           "AND l.username IS NOT NULL AND TRIM(l.username) != '' " +
           "AND l.timestamp >= :since AND l.timestamp <= :until " +
           "GROUP BY l.username HAVING COUNT(l) >= :threshold")
    List<String> findUsernamesWithFailureCountExceeding(
            @Param("status") LoginStatus status,
            @Param("since") LocalDateTime since,
            @Param("until") LocalDateTime until,
            @Param("threshold") long threshold
    );

    /**
     * Backward-compatible overload defaulting upper bound to the current time.
     */
    default List<String> findIpsWithFailureCountExceeding(LoginStatus status, LocalDateTime since, long threshold) {
        return findIpsWithFailureCountExceeding(status, since, LocalDateTime.now(), threshold);
    }

    /**
     * Backward-compatible overload defaulting upper bound to the current time.
     */
    default List<String> findUsernamesWithFailureCountExceeding(LoginStatus status, LocalDateTime since, long threshold) {
        return findUsernamesWithFailureCountExceeding(status, since, LocalDateTime.now(), threshold);
    }

    /**
     * Finds attempts by status within a time window, ordered newest first.
     */
    @Query("SELECT l FROM LoginAttempt l WHERE l.status = :status AND l.timestamp >= :since ORDER BY l.timestamp DESC")
    List<LoginAttempt> findAttemptsByStatusSince(
            @Param("status") LoginStatus status,
            @Param("since") LocalDateTime since
    );
}
