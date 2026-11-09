package com.innspark.loginmonitor.service.impl;

import com.innspark.loginmonitor.dto.SuspiciousActivityResponse;
import com.innspark.loginmonitor.entity.SuspiciousActivity;
import com.innspark.loginmonitor.repository.SuspiciousActivityRepository;
import com.innspark.loginmonitor.service.SuspiciousActivityService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Service implementation for managing suspicious activities.
 */
@Service
public class SuspiciousActivityServiceImpl implements SuspiciousActivityService {

    private final SuspiciousActivityRepository suspiciousActivityRepository;

    public SuspiciousActivityServiceImpl(SuspiciousActivityRepository suspiciousActivityRepository) {
        this.suspiciousActivityRepository = suspiciousActivityRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public List<SuspiciousActivityResponse> getAllSuspiciousActivities() {
        List<SuspiciousActivity> activities = suspiciousActivityRepository.findAllByOrderByTimestampDesc();
        return activities.stream()
                .map(SuspiciousActivityResponse::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public SuspiciousActivity saveSuspiciousActivity(SuspiciousActivity activity) {
        return suspiciousActivityRepository.save(activity);
    }
}
