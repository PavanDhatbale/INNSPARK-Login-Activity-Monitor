package com.innspark.loginmonitor.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Diagnostic component to safely verify database configuration on startup
 * without ever printing or logging the actual password.
 */
@Component
public class DatabaseConfigDiagnostic {

    private static final Logger log = LoggerFactory.getLogger(DatabaseConfigDiagnostic.class);

    @Value("${spring.datasource.url:}")
    private String datasourceUrl;

    @Value("${spring.datasource.username:}")
    private String datasourceUsername;

    @Value("${spring.datasource.password:}")
    private String datasourcePassword;

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        boolean passwordPresent = datasourcePassword != null && !datasourcePassword.trim().isEmpty();
        log.info("[Config Diagnostic] DataSource initialized: URL='{}', Username='{}', Password Configured: {}",
                datasourceUrl,
                datasourceUsername,
                passwordPresent ? "YES (masked, length=" + datasourcePassword.length() + ")" : "NO");
    }
}
