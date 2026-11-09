package com.innspark.loginmonitor.service;

import com.innspark.loginmonitor.dto.CaptchaVerifyResponse;
import com.innspark.loginmonitor.exception.InvalidCaptchaException;
import com.innspark.loginmonitor.service.impl.CaptchaServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CaptchaServiceTest {

    @Mock
    private RestTemplate restTemplate;

    private CaptchaServiceImpl captchaService;

    @BeforeEach
    void setUp() {
        captchaService = new CaptchaServiceImpl(restTemplate);
    }

    @Test
    @DisplayName("Disabled CAPTCHA skips verification completely and does not call remote API")
    void verifyCaptcha_Disabled_BypassesVerification() {
        ReflectionTestUtils.setField(captchaService, "captchaEnabled", false);

        assertDoesNotThrow(() -> captchaService.verifyCaptcha(null, "127.0.0.1"));
        assertDoesNotThrow(() -> captchaService.verifyCaptcha("", "127.0.0.1"));
        assertDoesNotThrow(() -> captchaService.verifyCaptcha("any-token", "127.0.0.1"));

        verify(restTemplate, never()).postForObject(anyString(), any(), any());
    }

    @Test
    @DisplayName("Enabled CAPTCHA with missing or empty token throws InvalidCaptchaException")
    void verifyCaptcha_Enabled_MissingToken_ThrowsException() {
        ReflectionTestUtils.setField(captchaService, "captchaEnabled", true);

        InvalidCaptchaException ex1 = assertThrows(InvalidCaptchaException.class,
                () -> captchaService.verifyCaptcha(null, "127.0.0.1"));
        assertEquals("CAPTCHA response token is required", ex1.getMessage());

        InvalidCaptchaException ex2 = assertThrows(InvalidCaptchaException.class,
                () -> captchaService.verifyCaptcha("   ", "127.0.0.1"));
        assertEquals("CAPTCHA response token is required", ex2.getMessage());

        verify(restTemplate, never()).postForObject(anyString(), any(), any());
    }

    @Test
    @DisplayName("Enabled CAPTCHA with valid provider response passes verification")
    void verifyCaptcha_Enabled_ValidResponse_Succeeds() {
        ReflectionTestUtils.setField(captchaService, "captchaEnabled", true);
        ReflectionTestUtils.setField(captchaService, "captchaSecret", "test-secret");
        ReflectionTestUtils.setField(captchaService, "verifyUrl", "https://www.google.com/recaptcha/api/siteverify");
        ReflectionTestUtils.setField(captchaService, "scoreThreshold", 0.5);

        CaptchaVerifyResponse responseBody = new CaptchaVerifyResponse();
        responseBody.setSuccess(true);
        responseBody.setScore(0.9);
        responseBody.setAction("login");

        when(restTemplate.postForObject(eq("https://www.google.com/recaptcha/api/siteverify"), any(HttpEntity.class), eq(CaptchaVerifyResponse.class)))
                .thenReturn(responseBody);

        assertDoesNotThrow(() -> captchaService.verifyCaptcha("valid-token", "127.0.0.1"));
    }

    @Test
    @DisplayName("Enabled CAPTCHA with provider returning success=false throws InvalidCaptchaException")
    void verifyCaptcha_Enabled_ProviderFailed_ThrowsException() {
        ReflectionTestUtils.setField(captchaService, "captchaEnabled", true);
        ReflectionTestUtils.setField(captchaService, "captchaSecret", "test-secret");
        ReflectionTestUtils.setField(captchaService, "verifyUrl", "https://www.google.com/recaptcha/api/siteverify");
        ReflectionTestUtils.setField(captchaService, "scoreThreshold", 0.5);

        CaptchaVerifyResponse responseBody = new CaptchaVerifyResponse();
        responseBody.setSuccess(false);

        when(restTemplate.postForObject(eq("https://www.google.com/recaptcha/api/siteverify"), any(HttpEntity.class), eq(CaptchaVerifyResponse.class)))
                .thenReturn(responseBody);

        InvalidCaptchaException ex = assertThrows(InvalidCaptchaException.class,
                () -> captchaService.verifyCaptcha("invalid-token", "127.0.0.1"));
        assertEquals("CAPTCHA verification failed. Please try again.", ex.getMessage());
    }

    @Test
    @DisplayName("Enabled CAPTCHA with low score throws InvalidCaptchaException")
    void verifyCaptcha_Enabled_LowScore_ThrowsException() {
        ReflectionTestUtils.setField(captchaService, "captchaEnabled", true);
        ReflectionTestUtils.setField(captchaService, "captchaSecret", "test-secret");
        ReflectionTestUtils.setField(captchaService, "verifyUrl", "https://www.google.com/recaptcha/api/siteverify");
        ReflectionTestUtils.setField(captchaService, "scoreThreshold", 0.5);

        CaptchaVerifyResponse responseBody = new CaptchaVerifyResponse();
        responseBody.setSuccess(true);
        responseBody.setScore(0.2); // Below 0.5

        when(restTemplate.postForObject(eq("https://www.google.com/recaptcha/api/siteverify"), any(HttpEntity.class), eq(CaptchaVerifyResponse.class)))
                .thenReturn(responseBody);

        InvalidCaptchaException ex = assertThrows(InvalidCaptchaException.class,
                () -> captchaService.verifyCaptcha("low-score-token", "127.0.0.1"));
        assertEquals("CAPTCHA verification failed due to low score. Please try again.", ex.getMessage());
    }

    @Test
    @DisplayName("Provider network error throws InvalidCaptchaException fails safely without crashing")
    void verifyCaptcha_Enabled_NetworkError_ThrowsExceptionSafely() {
        ReflectionTestUtils.setField(captchaService, "captchaEnabled", true);
        ReflectionTestUtils.setField(captchaService, "captchaSecret", "test-secret");
        ReflectionTestUtils.setField(captchaService, "verifyUrl", "https://www.google.com/recaptcha/api/siteverify");
        ReflectionTestUtils.setField(captchaService, "scoreThreshold", 0.5);

        when(restTemplate.postForObject(eq("https://www.google.com/recaptcha/api/siteverify"), any(HttpEntity.class), eq(CaptchaVerifyResponse.class)))
                .thenThrow(new RestClientException("Connection timed out"));

        InvalidCaptchaException ex = assertThrows(InvalidCaptchaException.class,
                () -> captchaService.verifyCaptcha("network-timeout-token", "127.0.0.1"));
        assertEquals("CAPTCHA verification service is temporarily unavailable. Please try again later.", ex.getMessage());
    }
}
