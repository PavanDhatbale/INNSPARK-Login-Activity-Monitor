# Login Activity Monitor for Suspicious Behaviour

> **INNSPARK Technical Evaluation — Backend Development Project**
> Built with Java 21, Spring Boot 3.3.5, Spring Security, Spring Data JPA, and MySQL 8.

---

## 1. Project Overview

The **Login Activity Monitor for Suspicious Behaviour** is a backend security service designed to monitor authentication traffic, detect potential attacks synchronously and via background scanning, maintain persistent database audit records, enforce Role-Based Access Control (RBAC), and protect user accounts with Multi-Factor Authentication (OTP / 2FA).

- **Multi-Factor Authentication (2FA)**: Two-Factor Authentication via email-delivered One-Time Passwords (OTP) for all roles (`USER`, `ADMIN`, `SUPERADMIN`).
- **Database-Backed Session Lifecycle**: 48-byte hex tokens, stored as SHA-256 hashes in MySQL, with a 15-minute sliding inactivity timeout and administrative session revocation.
- **Anomaly Detection & Background Scanner**: Synchronous evaluation on login attempts combined with an automated scheduled scanner for IP-based brute force, username-based brute force, and unusual success following multiple failures.
- **Tenant Isolation & RBAC**: Regular users are isolated strictly to their own login history and metrics (`USER`). Only `ADMIN` and `SUPERADMIN` can view global security metrics, manage active user sessions, and inspect cross-user audit trails and system-wide suspicious activity logs.
- **Security Dashboard**: Responsive frontend visualization (React 19 + Vite + React Router v7) with user dashboards and an administrative security console.

---

## 2. Core Features by Phase

### Phase 1: Project Foundation & Anomaly Detection
- **MySQL Persistence**: Relational schemas for `login_attempts` and `suspicious_activity`.
- **Foundational API Endpoints**:
  - `POST /login`: Log attempt simulation (accepts `username`, `ip_address`, `status`).
  - `GET /login`: Query login attempt history with secure user isolation and filtering.
  - `GET /suspicious`: Query detected suspicious activity records with reasoning (restricted to `ADMIN` and `SUPERADMIN`).
- **Detection Rules Engine**:
  - **Rule 1 (IP Brute Force)**: $\ge 5$ failed login attempts from the same IP address within a 10-minute window (`app.detection.ip-failure-threshold=5`).
  - **Rule 2 (User Brute Force)**: $\ge 5$ failed login attempts for the same username within a 10-minute window (`app.detection.user-failure-threshold=5`).
  - **Rule 3 (Unusual Success)**: A successful login immediately following $\ge 3$ failed attempts for the same username within 10 minutes (`app.detection.unusual-success-failure-threshold=3`).
- **Incident Deduplication**: Query bounded with `timestamp <= :until` preventing future-dated or repeat incident duplicates within the active window.
- **Automated Scheduled Scanner**: Periodic background sweep (`@Scheduled(fixedDelay = 60000)`) for unattended anomaly detection and alerting.

### Phase 2: Authentication, Session Management & RBAC
- **Password Security**: BCrypt password hashing (`strength = 12`) with automatic salt generation.
- **User Roles & Hierarchy**: `USER`, `ADMIN`, `SUPERADMIN`. Public registration defaults strictly to `USER`.
- **Database-Backed Sessions**: 48-byte cryptographically secure random session tokens (`SecureRandom`), stored as SHA-256 hashes in `user_sessions`, featuring a 15-minute sliding inactivity expiration window.
- **In-Memory Rate Limiting**: Sliding 60-second window permitting up to 5 attempts per IP address to mitigate rapid credential stuffing (returns HTTP 429).
- **Stateless Spring Security**: Custom `SessionAuthenticationFilter` extracting tokens from `Authorization: Bearer <token>` or `X-Session-Token: <token>`.
- **Admin User Management**: `GET /admin/users`, `PUT /admin/users/{id}/role`, `PUT /admin/users/{id}/status`, `DELETE /admin/users/{id}` (auditing preserved via `user_id = NULL`).

### Phase 3.1: Email Alerts & CAPTCHA Integration
- **Security Email Notifications**: Delivers security alert notifications to the configured administrator (`app.alerts.email.admin-recipient`) upon IP-based or user-based suspicious activity detection.
- **User Compromise Alerts**: Automatically notifies the user's registered email when their account is targeted by suspicious login failures.
- **Fail-Safe Delivery**: SMTP connection or network timeouts are safely caught and logged without aborting authentication transactions.
- **Google reCAPTCHA v3 Integration**: Backend score verification (`app.captcha.score-threshold=0.5`) triggered after consecutive failed login attempts (`app.captcha.failure-threshold=3`).

### Phase 3.2: Multi-Factor Authentication (OTP / 2FA)
- **Universal 2FA Coverage**: Enforced across all user roles (`USER`, `ADMIN`, `SUPERADMIN`).
- **Two-Step Authentication Pipeline**:
  1. `POST /auth/login`: Validates credentials, checks rate limits and CAPTCHA. If valid, generates a 6-digit numeric OTP, saves its BCrypt hash in `otp_challenges`, and delivers it via SMTP. **No session token is issued at this stage.**
  2. `POST /auth/verify-otp`: Atomically validates the challenge ID and 6-digit code using pessimistic locking (`@Lock(LockModeType.PESSIMISTIC_WRITE)`). Upon success, creates the database session and returns the session token.
- **Strict OTP Controls**: Single-use expiration (5 minutes), attempt limit (5 attempts), and resend cooldown (60 seconds, max 3 resends).

### Phase 3.3: User Activity Dashboard & Admin Security Console
- **User Activity Dashboard**:
  - Personal statistics: Total attempts, successful logins, failed logins, anomaly count, last login timestamps.
  - Paginated personal login history with status filtering (`SUCCESS` / `FAILURE`).
  - Personal anomaly timeline with rule triggers and severity ratings (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Strict tenant isolation: Non-privileged users receive HTTP 403 if querying records belonging to another username.
- **Admin Security Console**:
  - System-wide security analytics: Total registered users, total attempts, success/fail counts, total suspicious incidents.
  - User directory and role management interface.
  - Active session drawer permitting administrators to inspect and terminate active sessions for any user.
- **Frontend Single Page Application (SPA)**:
  - Built with **React 19**, **Vite**, and **React Router v7**.
  - Dark-theme security dashboard styling, live data refreshing, countdown timers, and role-based route guards.

### Phase 4: Admin Active-Session Management
- **View Active Sessions**: `GET /admin/users/{id}/sessions` allows administrators to inspect all non-expired, active sessions for a user, displaying session ID, IP address, user agent, start time, and last activity time.
- **Individual Session Revocation**: `DELETE /admin/users/{userId}/sessions/{sessionId}` terminates a single active session immediately.
- **Global Session Revocation**: `DELETE /admin/users/{userId}/sessions` terminates all active sessions for the target user.

---

## 3. Mandatory Class Requirement

The repository strictly preserves the required assessment class:
```java
// src/main/java/com/innspark/loginmonitor/InnsparkLogin.java
package com.innspark.loginmonitor;

public class InnsparkLogin {
}
```
*Note: This class remains completely empty and unmodified in compliance with the assignment specification.*

---

## 4. Architecture & 2FA Flow

```
                      Step 1: Primary Authentication
+-------------------------------------------------------------------------+
| Client: POST /auth/login { username, password, captchaToken }            |
+-------------------------------------------------------------------------+
                                    │
                                    ▼
                      [Rate Limiter & CAPTCHA Check]
                                    │
                                    ▼
                      [BCrypt Password Verification]
                                    │
                                    ▼
                     [Generate 6-digit SecureRandom OTP]
                                    │
                                    ▼
        [Save BCrypt Hash in otp_challenges (Status: PENDING)]
                                    │
                                    ▼
                 [Send OTP to User Email via SMTP]
                                    │
                                    ▼
+-------------------------------------------------------------------------+
| Return AuthResponse: { otpRequired: true, challengeId: "<UUID>", ... }  |
| (NO session token created yet!)                                         |
+-------------------------------------------------------------------------+

                      Step 2: OTP Verification
+-------------------------------------------------------------------------+
| Client: POST /auth/verify-otp { challengeId: "<UUID>", otp: "<CODE>" }   |
+-------------------------------------------------------------------------+
                                    │
                                    ▼
                [Lock challenge row (PESSIMISTIC_WRITE)]
                                    │
                 Check: Status == PENDING & Not Expired
                 Check: Failed attempts < maxAttempts (5)
                                    │
                                    ▼
                     [BCrypt Match Submitted OTP]
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
               Code Invalid                    Code Valid
                    │                               │
        Increment failedAttempts        Mark status = VERIFIED
        If >= 5, status = FAILED        Create UserSession in DB
        Throw InvalidOtpException       Return AuthResponse with
                                        active sessionToken!
```

---

## 5. Configuration & Environment Variables

Spring Boot resolves configuration properties from system environment variables, command-line arguments, and `application.properties`. For local development, backend environment variables can be exported in your shell (e.g., PowerShell: `$env:VAR="value"` or Bash: `export VAR=value`), configured in your IDE run configuration, or defined in a local `.env` file (processed by the internal `DotenvEnvironmentPostProcessor` SPI).

Frontend variables are managed separately by Vite and loaded from `frontend/.env`.

### Backend Environment Variables (`.env.example`)

| Variable | Description | Default Value | Alias / Legacy Mapping |
| :--- | :--- | :--- | :--- |
| `SERVER_PORT` | HTTP server port | `8080` | — |
| `DB_HOST` | MySQL database host | `localhost` | — |
| `DB_PORT` | MySQL database port | `3306` | — |
| `DB_NAME` | MySQL database name | `login_monitor` | — |
| `DB_USERNAME` | MySQL database username | `root` | — |
| `DB_PASSWORD` | MySQL database password | *(empty)* | — |
| `APP_ALERTS_EMAIL_ENABLED` | Enable security alert emails | `false` | `EMAIL_ALERTS_ENABLED` |
| `APP_ALERTS_EMAIL_TO` | Administrator recipient email for alerts | *(empty)* | `EMAIL_ALERT_RECIPIENT` |
| `MAIL_FROM` | Sender email address (`From:` header) | `noreply@innspark.com` | — |
| `SPRING_MAIL_HOST` | SMTP server host (e.g. `smtp.gmail.com`) | *(empty)* | `MAIL_HOST` |
| `SPRING_MAIL_PORT` | SMTP server port | `587` | `MAIL_PORT` |
| `SPRING_MAIL_USERNAME` | SMTP account username / email address | *(empty)* | `MAIL_USERNAME` |
| `SPRING_MAIL_PASSWORD` | SMTP application-specific password | *(empty)* | `MAIL_PASSWORD` |
| `APP_CAPTCHA_ENABLED` | Enforce CAPTCHA token check on login | `false` | `CAPTCHA_ENABLED` |
| `APP_CAPTCHA_SECRET` | Google reCAPTCHA v3 Secret Key | *(empty)* | `CAPTCHA_SECRET` |
| `APP_CAPTCHA_VERIFY_URL` | Provider siteverify verification URL | `https://www.google.com/recaptcha/api/siteverify` | `CAPTCHA_VERIFY_URL` |
| `APP_CAPTCHA_SCORE_THRESHOLD`| Minimum score for v3 CAPTCHAs | `0.5` | `CAPTCHA_SCORE_THRESHOLD` |
| `APP_CAPTCHA_FAILURE_THRESHOLD`| Failed attempts before CAPTCHA enforcement | `3` | — |
| `APP_OTP_ENABLED` | Enable Two-Factor Authentication (OTP) | `true` | — |
| `APP_OTP_EXPIRATION_MINUTES` | OTP code validity period (minutes) | `5` | — |
| `APP_OTP_MAX_ATTEMPTS` | Maximum allowed failed verification attempts | `5` | — |
| `APP_OTP_RESEND_COOLDOWN_SECONDS` | Minimum seconds between resend requests | `60` | — |
| `APP_OTP_MAX_RESENDS` | Maximum allowed resends per challenge | `3` | — |

### Frontend Environment Variables (`frontend/.env.example`)

| Variable | Description | Default Value |
| :--- | :--- | :--- |
| `VITE_API_BASE_URL` | Spring Boot backend REST API base URL | `http://localhost:8080` |
| `VITE_RECAPTCHA_SITE_KEY` | Google reCAPTCHA v3 public Site Key | `your_recaptcha_v3_public_site_key_here` |

---

## 6. Setup & Execution (Windows / Cross-Platform)

### Prerequisites
- **Java 21 JDK** installed (`java -version`)
- **Maven 3.9+** installed (`mvn -version`)
- **Node.js v18+ & npm** installed (`node -v`, `npm -v`)
- **MySQL 8** server running locally on port 3306

### Step 1: Configure Backend Environment & Database
1. Initialize the MySQL database:
   ```sql
   CREATE DATABASE IF NOT EXISTS login_monitor;
   ```
2. Configure backend environment variables. You can export them in your shell or copy the template:
   ```powershell
   copy .env.example .env
   ```
3. Set your local database password in `.env` (or via shell environment `$env:DB_PASSWORD`):
   ```dotenv
   DB_PASSWORD=your_actual_mysql_password
   ```

### Step 2: Run Backend Tests
```powershell
mvn clean test
```
*Current test suite: **244 automated unit, security, and integration tests passing with 0 failures**.*

### Step 3: Start the Backend Server
```powershell
mvn spring-boot:run
```
The backend API server starts on `http://localhost:8080`.

### Step 4: Configure & Start Frontend Application
In a separate terminal window:
1. Navigate to the frontend directory:
   ```powershell
   cd frontend
   ```
2. (Optional) Configure frontend environment variables if different from defaults:
   ```powershell
   copy .env.example .env
   ```
3. Install dependencies and start the Vite development server:
   ```powershell
   npm install
   npm run dev
   ```
4. Open `http://localhost:5173` in your web browser.

---

## 7. Key API Endpoints & Examples

### 1. User Registration
`POST /auth/register`
```json
{
  "username": "<USERNAME>",
  "email": "<USER_EMAIL>",
  "password": "<STRONG_PASSWORD>"
}
```

### 2. Login (Step 1 of 2FA)
`POST /auth/login`
```json
{
  "username": "<USERNAME>",
  "password": "<PASSWORD>",
  "captchaToken": ""
}
```
**Response (200 OK):**
```json
{
  "otpRequired": true,
  "challengeId": "<CHALLENGE_UUID>",
  "sessionToken": null,
  "tokenType": null,
  "username": "<USERNAME>",
  "role": "USER",
  "expiresAt": "<TIMESTAMP_ISO8601>",
  "message": "OTP verification required. Check registered email."
}
```

### 3. Verify OTP (Step 2 of 2FA)
`POST /auth/verify-otp`
```json
{
  "challengeId": "<CHALLENGE_UUID>",
  "otp": "<6_DIGIT_OTP>"
}
```
**Response (200 OK):**
```json
{
  "otpRequired": false,
  "challengeId": null,
  "sessionToken": "<SESSION_TOKEN_HEX>",
  "tokenType": "Bearer",
  "username": "<USERNAME>",
  "role": "USER",
  "expiresAt": "<TIMESTAMP_ISO8601>",
  "message": null
}
```

### 4. Resend OTP
`POST /auth/resend-otp`
```json
{
  "challengeId": "<CHALLENGE_UUID>"
}
```
**Response (200 OK):**
```json
{
  "challengeId": "<CHALLENGE_UUID>",
  "expiresAt": "<TIMESTAMP_ISO8601>",
  "message": "A new verification code has been sent to your registered email address."
}
```

### 5. Profile & Session Validation
`GET /auth/me`  
**Header:** `Authorization: Bearer <SESSION_TOKEN_HEX>`  
**Response (200 OK):**
```json
{
  "id": 1,
  "username": "<USERNAME>",
  "email": "<USER_EMAIL>",
  "role": "USER",
  "enabled": true,
  "createdAt": "<TIMESTAMP_ISO8601>"
}
```

### 6. Session Termination / Logout
`POST /auth/logout`  
**Header:** `Authorization: Bearer <SESSION_TOKEN_HEX>`  
**Response (200 OK):**
```json
{
  "message": "Logged out successfully"
}
```

### 7. User Activity Dashboard Statistics
`GET /dashboard/stats`  
**Header:** `Authorization: Bearer <SESSION_TOKEN_HEX>`  
**Response (200 OK):**
```json
{
  "username": "<USERNAME>",
  "totalAttempts": 14,
  "successfulLogins": 11,
  "failedAttempts": 3,
  "suspiciousActivities": 1,
  "lastLogin": "<TIMESTAMP_ISO8601>",
  "lastSuccessfulLogin": "<TIMESTAMP_ISO8601>"
}
```

### 8. User Paginated Login History (Isolated)
`GET /dashboard/login-history?page=0&size=10&status=SUCCESS`  
**Header:** `Authorization: Bearer <SESSION_TOKEN_HEX>`  
**Response (200 OK):**
```json
{
  "content": [
    {
      "id": 105,
      "username": "<USERNAME>",
      "status": "SUCCESS",
      "ipAddress": "192.0.2.100",
      "timestamp": "<TIMESTAMP_ISO8601>",
      "userAgent": "Mozilla/5.0..."
    }
  ],
  "page": 0,
  "size": 10,
  "totalElements": 11,
  "totalPages": 2,
  "last": false
}
```

### 9. User Suspicious Activities with Severity (Isolated)
`GET /dashboard/suspicious-activities?page=0&size=10`  
**Header:** `Authorization: Bearer <SESSION_TOKEN_HEX>`  
**Response (200 OK):**
```json
{
  "content": [
    {
      "id": 12,
      "username": "<USERNAME>",
      "ipAddress": "192.0.2.45",
      "reason": "Multiple failed login attempts for the same username within 10 minutes",
      "timestamp": "<TIMESTAMP_ISO8601>",
      "severity": "HIGH"
    }
  ],
  "page": 0,
  "size": 10,
  "totalElements": 1,
  "totalPages": 1,
  "last": true
}
```

### 10. Admin Active-Session Management (Phase 4)
- **View Active Sessions for User:**  
  `GET /admin/users/{userId}/sessions`  
  **Header:** `Authorization: Bearer <ADMIN_SESSION_TOKEN>` *(Requires `ROLE_ADMIN` or `ROLE_SUPERADMIN`)*  
  **Response (200 OK):**
  ```json
  [
    {
      "id": 35,
      "userId": 1,
      "username": "<TARGET_USERNAME>",
      "ipAddress": "127.0.0.1",
      "userAgent": "Mozilla/5.0...",
      "createdAt": "<TIMESTAMP_ISO8601>",
      "lastActivityAt": "<TIMESTAMP_ISO8601>",
      "active": true
    }
  ]
  ```
- **Terminate Individual Session:**  
  `DELETE /admin/users/{userId}/sessions/{sessionId}`  
  **Header:** `Authorization: Bearer <ADMIN_SESSION_TOKEN>`  
  **Response (200 OK):** `{"message": "Session terminated successfully"}`
- **Terminate All Sessions for User:**  
  `DELETE /admin/users/{userId}/sessions`  
  **Header:** `Authorization: Bearer <ADMIN_SESSION_TOKEN>`  
  **Response (200 OK):** `{"message": "All sessions terminated successfully"}`

### 11. Admin Global System Statistics
`GET /admin/dashboard/stats`  
**Header:** `Authorization: Bearer <ADMIN_SESSION_TOKEN>` *(Requires `ROLE_ADMIN` or `ROLE_SUPERADMIN`)*  
**Response (200 OK):**
```json
{
  "totalUsers": 12,
  "totalLoginAttempts": 240,
  "totalSuccessfulLogins": 195,
  "totalFailedLogins": 45,
  "totalSuspiciousActivities": 7,
  "recentSuspiciousActivities": 3
}
```

### 12. Foundational Assignment Endpoints (Phase 1)
- **Simulate/Log Attempt:** `POST /login` with `{ "username": "<USERNAME>", "ip_address": "192.0.2.10", "status": "FAILURE" }` *(Public)*
- **Audit Query:** `GET /login?username=<USERNAME>&status=FAILURE` *(Authenticated; regular users are isolated to their own username; admins can query any username)*
- **Query Suspicious Incidents:** `GET /suspicious` *(Restricted to `ADMIN` and `SUPERADMIN`. Unauthenticated calls return `HTTP 401`; regular `USER` calls return `HTTP 403`)*
