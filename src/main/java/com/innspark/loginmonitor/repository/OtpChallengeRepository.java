package com.innspark.loginmonitor.repository;

import com.innspark.loginmonitor.entity.OtpChallenge;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Spring Data JPA repository for managing OtpChallenge entities.
 */
@Repository
public interface OtpChallengeRepository extends JpaRepository<OtpChallenge, Long> {

    /**
     * Finds an OTP challenge by its unique public challenge UUID token.
     */
    Optional<OtpChallenge> findByChallengeId(String challengeId);

    /**
     * Finds an OTP challenge with a pessimistic write lock to prevent race conditions during verification.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT c FROM OtpChallenge c WHERE c.challengeId = :challengeId")
    Optional<OtpChallenge> findByChallengeIdWithLock(@Param("challengeId") String challengeId);

    /**
     * Marks all pending challenges that have exceeded their expiration time as EXPIRED.
     */
    @Modifying
    @Query("UPDATE OtpChallenge c SET c.status = com.innspark.loginmonitor.enums.OtpChallengeStatus.EXPIRED WHERE c.status = com.innspark.loginmonitor.enums.OtpChallengeStatus.PENDING AND c.expiresAt < :now")
    int markExpiredChallenges(@Param("now") LocalDateTime now);

    /**
     * Deletes challenge records older than the specified cutoff timestamp.
     */
    @Modifying
    @Query("DELETE FROM OtpChallenge c WHERE c.expiresAt < :cutoff")
    int deleteOlderThan(@Param("cutoff") LocalDateTime cutoff);
}
