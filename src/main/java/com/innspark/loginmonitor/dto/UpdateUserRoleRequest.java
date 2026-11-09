package com.innspark.loginmonitor.dto;

import com.innspark.loginmonitor.enums.Role;
import jakarta.validation.constraints.NotNull;

/**
 * Request payload for updating a user's assigned role.
 */
public class UpdateUserRoleRequest {

    @NotNull(message = "Role cannot be null")
    private Role role;

    public UpdateUserRoleRequest() {
    }

    public UpdateUserRoleRequest(Role role) {
        this.role = role;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }
}
