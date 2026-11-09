package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.dto.SuspiciousActivityResponse;
import com.innspark.loginmonitor.entity.SuspiciousActivity;

import java.util.List;

/**
 * Service interface for querying and saving suspicious activities.
 */
public interface SuspiciousActivityService {

    /**
     * Retrieves all detected suspicious activities ordered by detection timestamp descending.
     */
    List<SuspiciousActivityResponse> getAllSuspiciousActivities();

    /**
     * Persists a newly detected suspicious activity into the database.
     */
    SuspiciousActivity saveSuspiciousActivity(SuspiciousActivity activity);
}
