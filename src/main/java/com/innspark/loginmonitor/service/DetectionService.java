package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.entity.LoginAttempt;

/**
 * Service interface for detecting suspicious activity across login attempts.
 */
public interface DetectionService {

    /**
     * Performs immediate detection analysis upon recording a login attempt.
     *
     * @param attempt the newly recorded login attempt
     */
    void detectSuspiciousActivity(LoginAttempt attempt);

    /**
     * Periodically scans recent login attempts within the configured sliding window.
     */
    void runScheduledScan();
}
