import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { useAuth } from '../context/AuthContext';

export default function LoginPage() {
  const navigate = useNavigate();
  const { saveAuth, user } = useAuth();

  // If already logged in, redirect to dashboard
  useEffect(() => {
    if (user) {
      navigate('/dashboard');
    }
  }, [user, navigate]);

  // Form state
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  // 2FA state
  const [isOtpStep, setIsOtpStep] = useState(false);
  const [challengeId, setChallengeId] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [cooldownSeconds, setCooldownSeconds] = useState(0);

  // Status state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [infoMessage, setInfoMessage] = useState('');

  // reCAPTCHA v3 configuration
  const recaptchaSiteKey = import.meta.env.VITE_RECAPTCHA_SITE_KEY;
  const isCaptchaConfigured = Boolean(
    recaptchaSiteKey &&
    recaptchaSiteKey !== 'YOUR_RECAPTCHA_SITE_KEY' &&
    recaptchaSiteKey.trim() !== ''
  );

  // Load Google reCAPTCHA v3 script dynamically
  useEffect(() => {
    if (!isCaptchaConfigured) return;

    const scriptId = 'google-recaptcha-v3-script';
    let script = document.getElementById(scriptId);

    if (!script) {
      script = document.createElement('script');
      script.id = scriptId;
      script.src = `https://www.google.com/recaptcha/api.js?render=${encodeURIComponent(recaptchaSiteKey)}`;
      script.async = true;
      script.defer = true;
      document.body.appendChild(script);
    }

    // Toggle badge visibility based on login vs OTP step
    const badge = document.querySelector('.grecaptcha-badge');
    if (badge) {
      badge.style.visibility = isOtpStep ? 'hidden' : 'visible';
    }

    return () => {
      const b = document.querySelector('.grecaptcha-badge');
      if (b) {
        b.style.visibility = 'hidden';
      }
    };
  }, [isCaptchaConfigured, isOtpStep, recaptchaSiteKey]);

  // Execute reCAPTCHA v3 on user action (e.g. login)
  const executeRecaptcha = (action = 'login') => {
    return new Promise((resolve) => {
      if (!isCaptchaConfigured || !window.grecaptcha) {
        resolve(null);
        return;
      }
      try {
        window.grecaptcha.ready(() => {
          window.grecaptcha
            .execute(recaptchaSiteKey, { action })
            .then((token) => resolve(token))
            .catch((err) => {
              console.warn('reCAPTCHA v3 execution warning:', err);
              resolve(null);
            });
        });
      } catch (err) {
        console.warn('reCAPTCHA v3 ready call error:', err);
        resolve(null);
      }
    });
  };

  // Cooldown countdown timer
  useEffect(() => {
    let timer;
    if (cooldownSeconds > 0) {
      timer = setInterval(() => {
        setCooldownSeconds((prev) => Math.max(0, prev - 1));
      }, 1000);
    }
    return () => clearInterval(timer);
  }, [cooldownSeconds]);

  // Step 1: Submit Credentials
  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setInfoMessage('');
    setLoading(true);

    // Generate fresh reCAPTCHA v3 token for the 'login' action
    let token = null;
    if (isCaptchaConfigured) {
      token = await executeRecaptcha('login');
    }

    try {
      const response = await api.login(
        username.trim(),
        password,
        token
      );

      if (response.otpRequired) {
        setIsOtpStep(true);
        setChallengeId(response.challengeId);
        setInfoMessage(response.message || 'OTP verification code sent to your registered email address.');
        setCooldownSeconds(60); // 60-second initial cooldown
      } else {
        // Direct session creation (when 2FA is disabled)
        saveAuth(response.sessionToken, {
          username: response.username,
          role: response.role,
        });
        const profile = await api.getCurrentUser().catch(() => ({
          username: response.username,
          role: response.role,
        }));
        saveAuth(response.sessionToken, profile);
        navigate('/dashboard');
      }
    } catch (err) {
      setError(err.message || 'Login failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  // Step 2: Verify OTP Code
  const handleOtpSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setInfoMessage('');
    setLoading(true);

    try {
      const response = await api.verifyOtp(challengeId, otpCode.trim());

      saveAuth(response.sessionToken, {
        username: response.username,
        role: response.role,
      });

      const profile = await api.getCurrentUser().catch(() => ({
        username: response.username,
        role: response.role,
      }));

      saveAuth(response.sessionToken, profile);
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || 'Invalid or expired OTP code.');
    } finally {
      setLoading(false);
    }
  };

  // Resend OTP Code
  const handleResendOtp = async () => {
    if (cooldownSeconds > 0) return;
    setError('');
    setInfoMessage('');
    setLoading(true);

    try {
      const res = await api.resendOtp(challengeId);
      setInfoMessage(res.message || 'A new verification code has been sent to your email.');
      setCooldownSeconds(60);
    } catch (err) {
      setError(err.message || 'Failed to resend verification code.');
    } finally {
      setLoading(false);
    }
  };

  const handleBackToLogin = () => {
    setIsOtpStep(false);
    setOtpCode('');
    setChallengeId('');
    setError('');
    setInfoMessage('');
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-header">
          <div className="auth-logo">🛡️</div>
          <h2>{isOtpStep ? 'Two-Factor Authentication' : 'INNSPARK Sign In'}</h2>
          <p className="auth-subtitle">
            {isOtpStep
              ? 'Enter the 6-digit verification code sent to your registered email'
              : 'Sign in to access your security activity monitor'}
          </p>
        </div>

        {error && (
          <div className="alert alert-danger" role="alert">
            <span className="alert-icon">⚠️</span>
            <span>{error}</span>
          </div>
        )}

        {infoMessage && (
          <div className="alert alert-info" role="alert">
            <span className="alert-icon">ℹ️</span>
            <span>{infoMessage}</span>
          </div>
        )}

        {!isOtpStep ? (
          // Step 1: Username & Password
          <form onSubmit={handleLoginSubmit} className="auth-form">
            <div className="form-group">
              <label htmlFor="username">Username</label>
              <input
                id="username"
                type="text"
                className="form-control"
                placeholder="Enter your username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                autoFocus
              />
            </div>

            <div className="form-group">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                className="form-control"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            {isCaptchaConfigured && (
              <div className="recaptcha-v3-notice" style={{ fontSize: '0.78rem', color: '#94a3b8', textAlign: 'center', margin: '8px 0 16px' }}>
                🛡️ Protected by Google reCAPTCHA v3
              </div>
            )}

            <button type="submit" className="btn btn-primary btn-block" disabled={loading}>
              {loading ? 'Authenticating...' : 'Sign In'}
            </button>

            <div className="auth-footer">
              <span>Don't have an account? </span>
              <Link to="/register" className="auth-link">
                Register here
              </Link>
            </div>
          </form>
        ) : (
          // Step 2: 2FA OTP Code Verification
          <form onSubmit={handleOtpSubmit} className="auth-form">
            <div className="form-group">
              <label htmlFor="otpCode">6-Digit Verification Code</label>
              <input
                id="otpCode"
                type="text"
                className="form-control text-center otp-input"
                placeholder="000000"
                maxLength={6}
                pattern="\d{6}"
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ''))}
                required
                autoFocus
              />
              <small className="form-text text-muted">
                Code expires in 5 minutes. Never share this code with anyone.
              </small>
            </div>

            <button
              type="submit"
              className="btn btn-primary btn-block"
              disabled={loading || otpCode.length !== 6}
            >
              {loading ? 'Verifying Code...' : 'Verify & Continue'}
            </button>

            <div className="otp-actions">
              <button
                type="button"
                onClick={handleResendOtp}
                className="btn-resend"
                disabled={loading || cooldownSeconds > 0}
              >
                {cooldownSeconds > 0
                  ? `Resend code in ${cooldownSeconds}s`
                  : 'Resend Verification Code'}
              </button>

              <button
                type="button"
                onClick={handleBackToLogin}
                className="btn-back"
                disabled={loading}
              >
                ← Back to Login
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
