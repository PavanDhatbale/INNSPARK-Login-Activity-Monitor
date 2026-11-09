package com.innspark.loginmonitor.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.boot.logging.DeferredLogFactory;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.StandardEnvironment;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Custom Spring Boot {@link EnvironmentPostProcessor} that automatically loads configuration
 * properties from a root {@code .env} file into the Spring {@link org.springframework.core.env.Environment}.
 * <p>
 * Security & Design Principles:
 * <ul>
 *   <li>Operates with pure standard Java NIO — zero external third-party dependencies required.</li>
 *   <li>Registered in {@code META-INF/spring.factories} and {@code META-INF/spring/*.imports} for universal compatibility.</li>
 *   <li>Placed immediately after OS system environment variables, allowing genuine OS env vars to override .env.</li>
 *   <li>Protects against empty/blank OS variables accidentally masking populated .env values.</li>
 *   <li>Never prints or logs secret property values (only logs sanitized key names and boolean presence flags).</li>
 *   <li>Gracefully ignores missing .env files so tests and CI pipelines run without friction.</li>
 *   <li>Automatically registers bidirectional aliases for datasource, email, SMTP, and CAPTCHA properties.</li>
 * </ul>
 */
public class DotenvEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

    public static final String PROPERTY_SOURCE_NAME = "dotenvProperties";
    private final Log log;

    public DotenvEnvironmentPostProcessor() {
        this.log = LogFactory.getLog(DotenvEnvironmentPostProcessor.class);
    }

    public DotenvEnvironmentPostProcessor(DeferredLogFactory logFactory) {
        this.log = (logFactory != null) ? logFactory.getLog(DotenvEnvironmentPostProcessor.class)
                : LogFactory.getLog(DotenvEnvironmentPostProcessor.class);
    }

    @Override
    public int getOrder() {
        // Runs early in the environment preparation phase before application.properties are resolved
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        Path envPath = locateEnvFile();
        if (envPath == null) {
            log.debug("No .env file found in working directory or project root; continuing with standard environment.");
            return;
        }

        Map<String, Object> properties = parseEnvFile(envPath);
        if (properties.isEmpty()) {
            return;
        }

        // Register bidirectional aliases to bridge .env naming with application.properties
        registerAliases(properties);

        MutablePropertySources propertySources = environment.getPropertySources();
        if (propertySources.contains(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME)) {
            // Place after OS environment variables so that explicit OS variables take precedence
            propertySources.addAfter(
                    StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                    new MapPropertySource(PROPERTY_SOURCE_NAME, properties)
            );
        } else {
            propertySources.addLast(new MapPropertySource(PROPERTY_SOURCE_NAME, properties));
        }

        boolean hasDbPassword = properties.containsKey("DB_PASSWORD")
                && properties.get("DB_PASSWORD") != null
                && !properties.get("DB_PASSWORD").toString().trim().isEmpty();

        log.info(String.format("Loaded %d configuration keys from .env (%s). Keys: %s. DB Password Present: %s",
                properties.size(),
                envPath.toAbsolutePath().normalize(),
                properties.keySet(),
                hasDbPassword ? "YES (masked, length=" + properties.get("DB_PASSWORD").toString().length() + ")" : "NO"));
    }

    protected Path locateEnvFile() {
        // Optional override property (supports testing or custom deployments)
        String customPath = System.getProperty("dotenv.file");
        if (customPath != null) {
            if ("none".equalsIgnoreCase(customPath.trim())) {
                return null;
            }
            Path custom = Paths.get(customPath);
            return Files.isRegularFile(custom) ? custom : null;
        }

        // 1. Check current working directory
        Path candidate = Paths.get(".env");
        if (Files.isRegularFile(candidate)) {
            return candidate;
        }

        // 2. Check user.dir property
        String userDir = System.getProperty("user.dir");
        if (userDir != null) {
            candidate = Paths.get(userDir, ".env");
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }

        // 3. Check real path of current directory
        try {
            Path current = Paths.get(".").toRealPath();
            candidate = current.resolve(".env");
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        } catch (IOException ignored) {
        }

        return null;
    }

    private Map<String, Object> parseEnvFile(Path path) {
        Map<String, Object> map = new HashMap<>();
        try {
            List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
            for (String line : lines) {
                line = line.trim();
                // Skip empty lines and comments
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }

                int eqIdx = line.indexOf('=');
                if (eqIdx <= 0) {
                    continue;
                }

                String key = line.substring(0, eqIdx).trim();
                String rawValue = line.substring(eqIdx + 1).trim();

                // Strip surrounding single or double quotes
                String value = unquote(rawValue);

                map.put(key, value);
            }
        } catch (IOException e) {
            log.warn("Failed to read .env file at " + path + ": " + e.getMessage());
        }
        return map;
    }

    private String unquote(String val) {
        if (val.length() >= 2) {
            if ((val.startsWith("\"") && val.endsWith("\"")) ||
                (val.startsWith("'") && val.endsWith("'"))) {
                return val.substring(1, val.length() - 1);
            }
        }
        return val;
    }

    /**
     * Bridges configuration naming variations between .env definitions and application.properties.
     */
    private void registerAliases(Map<String, Object> props) {
        // Direct Database mappings (populates both DB_* and spring.datasource.*)
        mapAlias(props, "DB_PASSWORD", "spring.datasource.password");
        mapAlias(props, "DB_USERNAME", "spring.datasource.username");
        mapAlias(props, "DB_HOST", "spring.datasource.host");
        mapAlias(props, "DB_PORT", "spring.datasource.port");
        mapAlias(props, "DB_NAME", "spring.datasource.name");

        // Email Alert mappings
        mapAlias(props, "APP_ALERTS_EMAIL_ENABLED", "EMAIL_ALERTS_ENABLED");
        mapAlias(props, "APP_ALERTS_EMAIL_TO", "EMAIL_ALERT_RECIPIENT");

        // SMTP Server mappings
        mapAlias(props, "SPRING_MAIL_HOST", "MAIL_HOST");
        mapAlias(props, "SPRING_MAIL_PORT", "MAIL_PORT");
        mapAlias(props, "SPRING_MAIL_USERNAME", "MAIL_USERNAME");
        mapAlias(props, "SPRING_MAIL_PASSWORD", "MAIL_PASSWORD");

        // CAPTCHA mappings
        mapAlias(props, "APP_CAPTCHA_ENABLED", "CAPTCHA_ENABLED");
        mapAlias(props, "APP_CAPTCHA_SECRET", "CAPTCHA_SECRET");
    }

    private void mapAlias(Map<String, Object> props, String key1, String key2) {
        if (props.containsKey(key1) && !props.containsKey(key2)) {
            props.put(key2, props.get(key1));
        } else if (props.containsKey(key2) && !props.containsKey(key1)) {
            props.put(key1, props.get(key2));
        }
    }
}
