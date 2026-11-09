package com.innspark.loginmonitor.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.LocalDateTime;

/**
 * Entity representing an identified suspicious activity.
 * Persisted in the "suspicious_activity" database table.
 */
@Entity
@Table(name = "suspicious_activity")
public class SuspiciousActivity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "IP address cannot be blank")
    @Column(name = "ip_address", nullable = false, length = 45)
    private String ipAddress;

    @Column(name = "username", nullable = true, length = 50)
    private String username;

    @NotBlank(message = "Reason cannot be blank")
    @Column(name = "reason", nullable = false, length = 255)
    private String reason;

    @NotNull(message = "Timestamp cannot be null")
    @Column(name = "timestamp", nullable = false)
    private LocalDateTime timestamp;

    public SuspiciousActivity() {
    }

    public SuspiciousActivity(String ipAddress, String username, String reason) {
        this.ipAddress = ipAddress;
        this.username = username;
        this.reason = reason;
        this.timestamp = LocalDateTime.now();
    }

    public SuspiciousActivity(String ipAddress, String username, String reason, LocalDateTime timestamp) {
        this.ipAddress = ipAddress;
        this.username = username;
        this.reason = reason;
        this.timestamp = timestamp;
    }

    @PrePersist
    public void prePersist() {
        if (this.timestamp == null) {
            this.timestamp = LocalDateTime.now();
        }
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}
