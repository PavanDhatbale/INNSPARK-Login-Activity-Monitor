package com.innspark.loginmonitor.service.impl;

import com.innspark.loginmonitor.dto.CaptchaVerifyResponse;
import com.innspark.loginmonitor.exception.InvalidCaptchaException;
import com.innspark.loginmonitor.service.CaptchaService;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;

/**
 * Service implementation for validating client CAPTCHA tokens against an external provider (e.g. Google reCAPTCHA).
 *
 * Security & Reliability Policies:
 * 1. Disabled by default; zero external network requests made when disabled.
 * 2. Secrets and provider responses are never leaked in client error messages.
 * 3. Network or provider communication failures fail safely with a controlled message.
 */
@Service
public class CaptchaServiceImpl implements CaptchaService {

    private static final Logger log = LoggerFactory.getLogger(CaptchaServiceImpl.class);

    private final RestTemplate restTemplate;
    private final Environment environment;

    @Value("${app.captcha.enabled:false}")
    private boolean captchaEnabled;

    @Value("${app.captcha.secret:}")
    private String captchaSecret;

    @Value("${app.captcha.verify-url:https://www.google.com/recaptcha/api/siteverify}")
    private String verifyUrl;

    @Value("${app.captcha.score-threshold:0.5}")
    private double scoreThreshold;

    public CaptchaServiceImpl(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
        this.environment = null;
    }

    @Autowired
    public CaptchaServiceImpl(RestTemplate restTemplate, Environment environment) {
        this.restTemplate = restTemplate;
        this.environment = environment;
    }

    @PostConstruct
    public void validateProductionConfiguration() {
        if (environment == null) {
            return;
        }
        boolean isProduction = Arrays.stream(environment.getActiveProfiles())
                .anyMatch(p -> p.equalsIgnoreCase("prod") || p.equalsIgnoreCase("production"));

        if (isProduction) {
            if (!captchaEnabled) {
                log.error("SECURITY VIOLATION: CAPTCHA is disabled in production profile!");
                throw new IllegalStateException("CAPTCHA cannot be disabled in production profile ('prod' or 'production'). Set app.captcha.enabled=true.");
            }
            if (captchaSecret == null || captchaSecret.trim().isEmpty()) {
                log.error("SECURITY VIOLATION: CAPTCHA secret is not configured in production profile!");
                throw new IllegalStateException("CAPTCHA secret (app.captcha.secret) must be provided in production profile.");
            }
        }
    }

    @Override
    public boolean isCaptchaEnabled() {
        return captchaEnabled;
    }

    @Override
    public void verifyCaptcha(String captchaToken, String clientIp) {
        if (!captchaEnabled) {
            return;
        }

        if (captchaToken == null || captchaToken.trim().isEmpty()) {
            log.warn("CAPTCHA verification failed: missing token from IP '{}'", clientIp);
            throw new InvalidCaptchaException("CAPTCHA response token is required");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("secret", captchaSecret != null ? captchaSecret.trim() : "");
            params.add("response", captchaToken.trim());
            if (clientIp != null && !clientIp.trim().isEmpty()) {
                params.add("remoteip", clientIp.trim());
            }

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

            CaptchaVerifyResponse response = restTemplate.postForObject(
                    verifyUrl,
                    request,
                    CaptchaVerifyResponse.class
            );

            if (response == null || !response.isSuccess()) {
                log.warn("CAPTCHA verification rejected for IP '{}'. Provider error codes: {}",
                        clientIp, response != null ? response.getErrorCodes() : "null response");
                throw new InvalidCaptchaException("CAPTCHA verification failed. Please try again.");
            }

            // If score-based CAPTCHA (e.g. reCAPTCHA v3)
            if (response.getScore() != null && response.getScore() < scoreThreshold) {
                log.warn("CAPTCHA verification rejected due to low score ({}) for IP '{}'",
                        response.getScore(), clientIp);
                throw new InvalidCaptchaException("CAPTCHA verification failed due to low score. Please try again.");
            }

            log.info("CAPTCHA verification succeeded for IP '{}'", clientIp);

        } catch (RestClientException e) {
            log.error("CAPTCHA provider communication error for IP '{}': {}", clientIp, e.getMessage());
            throw new InvalidCaptchaException("CAPTCHA verification service is temporarily unavailable. Please try again later.");
        }
    }
}
