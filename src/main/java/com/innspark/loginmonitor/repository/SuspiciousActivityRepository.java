package com.innspark.loginmonitor.repository;

import com.innspark.loginmonitor.entity.SuspiciousActivity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Spring Data JPA Repository for SuspiciousActivity entity.
 */
@Repository
public interface SuspiciousActivityRepository extends JpaRepository<SuspiciousActivity, Long> {

    // --- Dashboard Queries (Phase 3.3) ---

    long countByUsernameIgnoreCase(String username);

    Page<SuspiciousActivity> findByUsernameIgnoreCaseOrderByTimestampDesc(String username, Pageable pageable);

    long countByTimestampGreaterThanEqual(LocalDateTime since);

    List<SuspiciousActivity> findByIpAddressOrderByTimestampDesc(String ipAddress);

    List<SuspiciousActivity> findByUsernameOrderByTimestampDesc(String username);

    List<SuspiciousActivity> findAllByOrderByTimestampDesc();

    /**
     * Checks if a suspicious activity record matching the specified IP and reason prefix already exists
     * within the specified time window, used for deduplication.
     */
    @Query("SELECT COUNT(s) > 0 FROM SuspiciousActivity s WHERE s.ipAddress = :ipAddress AND s.reason LIKE CONCAT(:reasonPrefix, '%') AND s.timestamp >= :since")
    boolean existsByIpAddressAndReasonPrefixSince(
            @Param("ipAddress") String ipAddress,
            @Param("reasonPrefix") String reasonPrefix,
            @Param("since") LocalDateTime since
    );

    /**
     * Checks if a suspicious activity record matching the specified username and reason prefix already exists
     * within the specified time window, used for deduplication.
     */
    @Query("SELECT COUNT(s) > 0 FROM SuspiciousActivity s WHERE LOWER(s.username) = LOWER(:username) AND s.reason LIKE CONCAT(:reasonPrefix, '%') AND s.timestamp >= :since")
    boolean existsByUsernameAndReasonPrefixSince(
            @Param("username") String username,
            @Param("reasonPrefix") String reasonPrefix,
            @Param("since") LocalDateTime since
    );
}
