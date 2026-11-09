package com.innspark.loginmonitor.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.SpringApplication;
import org.springframework.core.Ordered;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class DotenvEnvironmentPostProcessorTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("Should have correct execution order (HIGHEST_PRECEDENCE + 10)")
    void getOrder_ShouldBeEarly() {
        DotenvEnvironmentPostProcessor processor = new DotenvEnvironmentPostProcessor();
        assertThat(processor.getOrder()).isEqualTo(Ordered.HIGHEST_PRECEDENCE + 10);
    }

    @Test
    @DisplayName("Should gracefully handle absence of .env file")
    void postProcessEnvironment_NoEnvFile_ShouldNotThrow() {
        System.setProperty("dotenv.file", "none");
        try {
            DotenvEnvironmentPostProcessor processor = new DotenvEnvironmentPostProcessor();
            StandardEnvironment environment = new StandardEnvironment();

            assertDoesNotThrow(() -> processor.postProcessEnvironment(environment, new SpringApplication()));
            assertThat(environment.getPropertySources().contains(DotenvEnvironmentPostProcessor.PROPERTY_SOURCE_NAME))
                    .isFalse();
        } finally {
            System.clearProperty("dotenv.file");
        }
    }

    @Test
    @DisplayName("Should parse .env file and map properties and aliases")
    void postProcessEnvironment_WithEnvFile_ShouldLoadPropertiesAndAliases() throws IOException {
        Path envFile = tempDir.resolve(".env");
        List<String> lines = List.of(
                "# Sample configuration",
                "DB_HOST=127.0.0.1",
                "DB_PORT=3307",
                "DB_USERNAME=custom_root",
                "DB_PASSWORD=my_test_password_123",
                "APP_ALERTS_EMAIL_ENABLED=true",
                "APP_ALERTS_EMAIL_TO=admin@test.com",
                "SPRING_MAIL_HOST=smtp.test.com",
                "SPRING_MAIL_PORT=2525",
                "SPRING_MAIL_USERNAME='user@test.com'",
                "SPRING_MAIL_PASSWORD=\"secret123\"",
                "APP_CAPTCHA_ENABLED=true",
                "APP_CAPTCHA_SECRET=site_secret_key",
                "",
                "# Empty line above and comment"
        );
        Files.write(envFile, lines);

        System.setProperty("dotenv.file", envFile.toAbsolutePath().toString());
        try {
            DotenvEnvironmentPostProcessor processor = new DotenvEnvironmentPostProcessor();
            StandardEnvironment environment = new StandardEnvironment();

            processor.postProcessEnvironment(environment, new SpringApplication());

            assertThat(environment.getPropertySources().contains(DotenvEnvironmentPostProcessor.PROPERTY_SOURCE_NAME))
                    .isTrue();

            // Direct properties
            assertThat(environment.getProperty("DB_HOST")).isEqualTo("127.0.0.1");
            assertThat(environment.getProperty("DB_PORT")).isEqualTo("3307");
            assertThat(environment.getProperty("DB_USERNAME")).isEqualTo("custom_root");
            assertThat(environment.getProperty("DB_PASSWORD")).isEqualTo("my_test_password_123");
            assertThat(environment.getProperty("spring.datasource.password")).isEqualTo("my_test_password_123");
            assertThat(environment.getProperty("spring.datasource.username")).isEqualTo("custom_root");
            assertThat(environment.getProperty("APP_ALERTS_EMAIL_ENABLED")).isEqualTo("true");
            assertThat(environment.getProperty("SPRING_MAIL_HOST")).isEqualTo("smtp.test.com");
            assertThat(environment.getProperty("SPRING_MAIL_PORT")).isEqualTo("2525");
            assertThat(environment.getProperty("SPRING_MAIL_USERNAME")).isEqualTo("user@test.com");
            assertThat(environment.getProperty("SPRING_MAIL_PASSWORD")).isEqualTo("secret123");
            assertThat(environment.getProperty("APP_CAPTCHA_ENABLED")).isEqualTo("true");
            assertThat(environment.getProperty("APP_CAPTCHA_SECRET")).isEqualTo("site_secret_key");

            // Aliased properties
            assertThat(environment.getProperty("EMAIL_ALERTS_ENABLED")).isEqualTo("true");
            assertThat(environment.getProperty("EMAIL_ALERT_RECIPIENT")).isEqualTo("admin@test.com");
            assertThat(environment.getProperty("MAIL_HOST")).isEqualTo("smtp.test.com");
            assertThat(environment.getProperty("MAIL_PORT")).isEqualTo("2525");
            assertThat(environment.getProperty("MAIL_USERNAME")).isEqualTo("user@test.com");
            assertThat(environment.getProperty("MAIL_PASSWORD")).isEqualTo("secret123");
            assertThat(environment.getProperty("CAPTCHA_ENABLED")).isEqualTo("true");
            assertThat(environment.getProperty("CAPTCHA_SECRET")).isEqualTo("site_secret_key");
        } finally {
            System.clearProperty("dotenv.file");
        }
    }

    @Test
    @DisplayName("OS environment variables should take precedence over .env properties")
    void postProcessEnvironment_OsEnvTakesPrecedence() throws IOException {
        Path envFile = tempDir.resolve(".env");
        Files.write(envFile, List.of("DB_HOST=from_dotenv.com"));

        System.setProperty("dotenv.file", envFile.toAbsolutePath().toString());
        try {
            DotenvEnvironmentPostProcessor processor = new DotenvEnvironmentPostProcessor();
            StandardEnvironment environment = new StandardEnvironment();

            // Simulate OS environment variable with higher priority
            environment.getPropertySources().addFirst(
                    new MapPropertySource(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                            Collections.singletonMap("DB_HOST", "from_system_env.com"))
            );

            processor.postProcessEnvironment(environment, new SpringApplication());

            // OS env var should win
            assertThat(environment.getProperty("DB_HOST")).isEqualTo("from_system_env.com");
        } finally {
            System.clearProperty("dotenv.file");
        }
    }

    @Test
    @DisplayName("Should be registered in META-INF/spring.factories for EnvironmentPostProcessor")
    void springFactories_ShouldRegisterPostProcessor() {
        ClassLoader classLoader = DotenvEnvironmentPostProcessor.class.getClassLoader();
        List<String> names = org.springframework.core.io.support.SpringFactoriesLoader.loadFactoryNames(
                org.springframework.boot.env.EnvironmentPostProcessor.class, classLoader
        );

        assertThat(names).contains(DotenvEnvironmentPostProcessor.class.getName());
    }
}
