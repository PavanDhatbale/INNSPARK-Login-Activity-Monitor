package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.entity.SuspiciousActivity;

/**
 * Service interface for dispatching security alert notifications to system administrators and affected users.
 */
public interface EmailAlertService {

    /**
     * Dispatches security alert notifications when a new suspicious activity is detected:
     * - Sends alert to the configured administrator email.
     * - If an individual user account was targeted and has a registered email, sends an alert to the user.
     * When email alerts are disabled or delivery fails, execution does not fail or throw an exception.
     *
     * @param activity the newly detected suspicious activity record
     */
    void sendSuspiciousActivityAlert(SuspiciousActivity activity);

    /**
     * Checks whether email alerts are currently enabled in application configuration.
     *
     * @return true if email alerts are enabled, false otherwise
     */
    boolean isEmailAlertEnabled();
}
