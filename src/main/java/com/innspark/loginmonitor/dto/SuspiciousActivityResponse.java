package com.innspark.loginmonitor.dto;

import com.innspark.loginmonitor.entity.SuspiciousActivity;
import java.time.LocalDateTime;

/**
 * DTO representing an identified suspicious activity returned by GET /suspicious
 * and GET /dashboard/suspicious-activities.
 */
public class SuspiciousActivityResponse {

    private Long id;
    private String ipAddress;
    private String username;
    private String reason;
    private LocalDateTime timestamp;
    private String severity;

    public SuspiciousActivityResponse() {
    }

    public SuspiciousActivityResponse(Long id, String ipAddress, String username, String reason, LocalDateTime timestamp) {
        this.id = id;
        this.ipAddress = ipAddress;
        this.username = username;
        this.reason = reason;
        this.timestamp = timestamp;
        this.severity = determineSeverity(reason);
    }

    public SuspiciousActivityResponse(Long id, String ipAddress, String username, String reason, LocalDateTime timestamp, String severity) {
        this.id = id;
        this.ipAddress = ipAddress;
        this.username = username;
        this.reason = reason;
        this.timestamp = timestamp;
        this.severity = severity != null ? severity : determineSeverity(reason);
    }

    public static SuspiciousActivityResponse fromEntity(SuspiciousActivity activity) {
        return new SuspiciousActivityResponse(
                activity.getId(),
                activity.getIpAddress(),
                activity.getUsername(),
                activity.getReason(),
                activity.getTimestamp(),
                determineSeverity(activity.getReason())
        );
    }

    private static String determineSeverity(String reason) {
        if (reason == null) {
            return "LOW";
        }
        String lower = reason.toLowerCase();
        if (lower.contains("ip") && lower.contains("failed") || lower.contains("5 failed") || lower.contains("brute")) {
            return "HIGH";
        }
        if (lower.contains("failed") || lower.contains("rapid") || lower.contains("different ip")) {
            return "MEDIUM";
        }
        return "LOW";
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
        this.severity = determineSeverity(reason);
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getSeverity() {
        return severity != null ? severity : determineSeverity(reason);
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }
}
