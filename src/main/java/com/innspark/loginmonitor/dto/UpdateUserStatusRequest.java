package com.innspark.loginmonitor.dto;

import jakarta.validation.constraints.NotNull;

/**
 * Request payload for enabling or disabling a user account.
 */
public class UpdateUserStatusRequest {

    @NotNull(message = "Enabled status cannot be null")
    private Boolean enabled;

    public UpdateUserStatusRequest() {
    }

    public UpdateUserStatusRequest(Boolean enabled) {
        this.enabled = enabled;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }
}
