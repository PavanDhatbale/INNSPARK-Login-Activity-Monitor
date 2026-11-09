package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.dto.LoginAttemptResponse;
import com.innspark.loginmonitor.dto.LoginRequest;
import com.innspark.loginmonitor.dto.LoginResponse;
import com.innspark.loginmonitor.enums.LoginStatus;

import java.util.List;

/**
 * Service interface for handling login attempts and history retrieval.
 */
public interface LoginAttemptService {

    /**
     * Processes a login attempt with simulated authentication,
     * persists the attempt in the database, and returns the response.
     *
     * @param request the incoming login request containing credentials
     * @param clientIp the extracted client IP address
     * @return LoginResponse with status SUCCESS or FAILURE
     */
    LoginResponse processLogin(LoginRequest request, String clientIp);

    /**
     * Retrieves login attempt history filtered by optional criteria.
     *
     * @param username optional username filter
     * @param ipAddress optional IP address filter
     * @param status optional status filter (SUCCESS or FAILURE)
     * @return list of login attempts
     */
    List<LoginAttemptResponse> getLoginHistory(String username, String ipAddress, LoginStatus status);
}
