package com.innspark.loginmonitor.entity;

import com.innspark.loginmonitor.enums.OtpChallengeStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.LocalDateTime;

/**
 * Entity representing an active or completed OTP two-factor authentication challenge.
 *
 * Security & Data Integrity Policies:
 * 1. Plaintext OTPs are NEVER stored. Only a secure salted/BCrypt hash is retained.
 * 2. Every challenge is strictly single-use; once verified or failed, its status transitions terminal.
 * 3. Challenge identifier is a cryptographically random UUID to prevent sequential ID enumeration.
 */
@Entity
@Table(
        name = "otp_challenges",
        indexes = {
                @Index(name = "idx_otp_challenge_id", columnList = "challenge_id", unique = true),
                @Index(name = "idx_otp_user_id", columnList = "user_id"),
                @Index(name = "idx_otp_expires_at", columnList = "expires_at"),
                @Index(name = "idx_otp_status", columnList = "status")
        }
)
public class OtpChallenge {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "challenge_id", nullable = false, unique = true, length = 64)
    private String challengeId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "otp_hash", nullable = false, length = 255)
    private String otpHash;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "verified_at")
    private LocalDateTime verifiedAt;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts = 0;

    @Column(name = "resend_count", nullable = false)
    private int resendCount = 0;

    @Column(name = "last_resent_at")
    private LocalDateTime lastResentAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private OtpChallengeStatus status = OtpChallengeStatus.PENDING;

    public OtpChallenge() {
    }

    public OtpChallenge(String challengeId, User user, String otpHash, LocalDateTime createdAt, LocalDateTime expiresAt) {
        this.challengeId = challengeId;
        this.user = user;
        this.otpHash = otpHash;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.status = OtpChallengeStatus.PENDING;
        this.failedAttempts = 0;
        this.resendCount = 0;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getChallengeId() {
        return challengeId;
    }

    public void setChallengeId(String challengeId) {
        this.challengeId = challengeId;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getOtpHash() {
        return otpHash;
    }

    public void setOtpHash(String otpHash) {
        this.otpHash = otpHash;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public LocalDateTime getVerifiedAt() {
        return verifiedAt;
    }

    public void setVerifiedAt(LocalDateTime verifiedAt) {
        this.verifiedAt = verifiedAt;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public void setFailedAttempts(int failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    public int getResendCount() {
        return resendCount;
    }

    public void setResendCount(int resendCount) {
        this.resendCount = resendCount;
    }

    public LocalDateTime getLastResentAt() {
        return lastResentAt;
    }

    public void setLastResentAt(LocalDateTime lastResentAt) {
        this.lastResentAt = lastResentAt;
    }

    public OtpChallengeStatus getStatus() {
        return status;
    }

    public void setStatus(OtpChallengeStatus status) {
        this.status = status;
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }

    public boolean isPending() {
        return this.status == OtpChallengeStatus.PENDING;
    }
}
