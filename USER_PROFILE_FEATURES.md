# User Profile & Security Features - Implementation Guide

**Version:** 2.1.0
**Status:** Planned
**Last Updated:** 2025-10-12

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Feature List](#feature-list)
3. [Security Analysis](#security-analysis)
4. [Magic Link vs OTP Comparison](#magic-link-vs-otp-comparison)
5. [Security Phrase (Magic Words)](#security-phrase-magic-words)
6. [Implementation Plan](#implementation-plan)
7. [Database Schema Changes](#database-schema-changes)
8. [API Endpoints](#api-endpoints)
9. [Frontend Changes](#frontend-changes)
10. [Security Checklist](#security-checklist)
11. [Testing Requirements](#testing-requirements)

---

## Overview

This document outlines the comprehensive user profile management and security features planned for version 2.1.0. The focus is on enhancing user account management, improving security, and providing better visibility into account activity and URL usage analytics.

### Goals

- ✅ Improve user account security
- ✅ Provide comprehensive usage analytics
- ✅ Enable password management
- ✅ Add activity logging and audit trail
- ✅ Implement anti-phishing measures (security phrases)
- ✅ Enhance user experience with better dashboards

### Non-Goals

- ❌ Email address changes (security risk, low value)
- ❌ 2FA/MFA (planned for v2.2.0)
- ❌ OAuth social login (planned for v2.3.0)

---

## Feature List

### 1. Password Management

**Priority:** High
**Estimated Effort:** 4 hours

#### Features:
- Change password (requires current password)
- Forgot password with magic link
- Password strength validation
- Session invalidation on password change
- Email alerts on password change

#### User Stories:
- As a user, I want to change my password securely
- As a user, I want to reset my password if I forget it
- As a user, I want to be notified if someone changes my password

---

### 2. Security Phrase (Magic Words)

**Priority:** High
**Estimated Effort:** 3 hours

#### Features:
- User-defined security phrase (3-50 characters)
- Phrase appears in all official emails
- Prevents phishing attacks
- Visual banner in emails
- Optional feature (user can choose not to set)

#### User Stories:
- As a user, I want to verify emails are really from the platform
- As a user, I want protection against phishing attempts
- As a user, I want a personalized security measure

#### Example:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔐 Your Security Phrase: Purple Elephant 2025

If this phrase is missing or incorrect, DO NOT click any links.
This email may be a phishing attempt.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

### 3. Activity Logging

**Priority:** Medium
**Estimated Effort:** 5 hours

#### Features:
- Log all user actions (login, logout, URL CRUD, password changes)
- Store activity logs with timestamp, IP, user agent
- Display activity timeline in user profile
- Filter by action type and date range
- Export activity log as JSON/CSV

#### Logged Activities:
- `user_login` - Successful login
- `user_logout` - User logout
- `password_changed` - Password updated
- `security_phrase_set` - Security phrase created/updated
- `url_created` - New short URL created
- `url_updated` - URL modified
- `url_deleted` - URL deleted
- `login_failed` - Failed login attempt (security)

#### Redis Storage:
```
Key: activity:{userID}
Type: List (LPUSH for new entries)
Expiration: 90 days per entry
Max Size: 1000 entries per user
```

#### Data Structure:
```json
{
  "timestamp": "2025-10-12T10:30:00Z",
  "action": "url_created",
  "details": {
    "shortURL": "abc123",
    "originalURL": "https://example.com"
  },
  "ip": "192.168.1.100",
  "userAgent": "Mozilla/5.0...",
  "location": "Tehran, Iran" // Optional: GeoIP lookup
}
```

---

### 4. Enhanced Analytics Dashboard

**Priority:** High
**Estimated Effort:** 8 hours

#### Features:
- Time-series charts for URL clicks (daily/weekly/monthly)
- Click breakdown by device (mobile/desktop/tablet)
- Click breakdown by browser
- Geographic distribution (country/city)
- Referrer analysis (where clicks come from)
- Top performing URLs
- Click heatmap (time of day analysis)
- Export analytics data

#### Charts & Visualizations:
1. **Line Chart**: Clicks over time (7/30/90 days)
2. **Pie Chart**: Device distribution
3. **Bar Chart**: Top 10 URLs by clicks
4. **Map**: Geographic distribution (if GeoIP available)
5. **Heatmap**: Clicks by hour and day of week

#### Technology:
- Frontend: Chart.js (lightweight, 60KB)
- Backend: Aggregate data from `logs:{shortURL}` keys
- Caching: Pre-compute analytics hourly for performance

---

### 5. URL Access Logs Viewer

**Priority:** Medium
**Estimated Effort:** 3 hours

#### Features:
- View access logs for each URL
- Filter by date range
- Search by IP or user agent
- Export logs as JSON/CSV
- Pagination (50 entries per page)

#### Display Information:
- Timestamp
- IP address
- User agent (parsed: browser, OS, device)
- Referrer URL
- Geographic location (if available)

---

### 6. User Profile Settings

**Priority:** High
**Estimated Effort:** 4 hours

#### Features:
- View account information
- Display email (read-only)
- Display registration date
- Display last login time
- Display account status (verified, active)
- Change password form
- Set/update security phrase
- View usage statistics summary

---

## Security Analysis

### Threat Model

#### Threat 1: Email Injection Attacks

**Attack Vector:**
```
User input: "victim@test.com\nBCC: attacker@evil.com"
Result: Email sent to both victim and attacker
```

**Mitigation:**
```go
func ValidateEmail(email string) error {
    // 1. Trim whitespace
    email = strings.TrimSpace(email)

    // 2. Check for injection characters
    if strings.ContainsAny(email, "\n\r\t") {
        return errors.New("invalid email format: contains control characters")
    }

    // 3. Regex validation (RFC 5322 simplified)
    emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    if !emailRegex.MatchString(email) {
        return errors.New("invalid email format")
    }

    // 4. Length check
    if len(email) > 254 {
        return errors.New("email too long")
    }

    return nil
}
```

**Status:** ✅ Already implemented in `handler/user.go:62-66`

---

#### Threat 2: Token Prediction/Brute Force

**Attack Vector:**
```
Attacker tries to guess reset tokens:
- Sequential: token1, token2, token3
- Timestamp-based: predictable patterns
```

**Mitigation:**
```go
// Use UUID v4 (122 bits of entropy)
token := uuid.New().String()

// Entropy: 2^122 = 5.3 × 10^36 combinations
// Brute force time: Longer than universe's age
```

**Rate Limiting:**
```go
// Limit token validation attempts
// Max 10 attempts per IP per hour
rateLimit := "reset_attempts:" + ip
attempts, _ := redis.Incr(ctx, rateLimit).Result()
if attempts == 1 {
    redis.Expire(ctx, rateLimit, time.Hour)
}
if attempts > 10 {
    return errors.New("too many attempts, try again later")
}
```

---

#### Threat 3: Token Interception (Man-in-the-Middle)

**Attack Vector:**
```
User on public WiFi → Requests password reset
↓
Attacker intercepts email traffic (unencrypted SMTP)
↓
Attacker extracts token from email
↓
Attacker uses token to reset victim's password
```

**Mitigation:**

1. **TLS/SSL for SMTP** ✅
```go
emailConfig := &email.Config{
    SMTPHost: "smtp.gmail.com",
    SMTPPort: 587,
    UseTLS:   true, // Force TLS encryption
}
```

2. **HTTPS for all endpoints** ✅
```yaml
# config.yaml
webserver:
  scheme: https # Force HTTPS in production
```

3. **Device/IP Validation (Optional)**
```go
// Log requesting IP and user agent
type ResetToken struct {
    Token       string
    UserID      string
    RequestIP   string
    UserAgent   string
    CreatedAt   time.Time
    ExpiresAt   time.Time
}

// On verification, log the verifying IP
// If different, create security alert
```

**Trade-off:** This can block legitimate users (mobile switching between WiFi/cellular)

**Better Approach:** Log suspicious activity and send alert email

---

#### Threat 4: Token Reuse

**Attack Vector:**
```
1. User clicks reset link → Token: abc123
2. User completes password reset
3. Token not deleted from database
4. Attacker finds old token and reuses it
```

**Mitigation:**
```go
func ResetPassword(token, newPassword string) error {
    // 1. Validate token
    tokenData, err := redis.Get(ctx, "reset_token:" + token).Result()
    if err != nil {
        return errors.New("invalid or expired token")
    }

    // 2. Parse token
    var resetToken ResetToken
    json.Unmarshal([]byte(tokenData), &resetToken)

    // 3. Update password
    updateUserPassword(resetToken.UserID, newPassword)

    // 4. DELETE TOKEN IMMEDIATELY ← Critical!
    redis.Del(ctx, "reset_token:" + token)

    // 5. Invalidate all user sessions (force re-login)
    redis.Del(ctx, "refresh_token:" + resetToken.UserID + ":*")

    // 6. Log activity
    logActivity(resetToken.UserID, "password_reset", getIP(r))

    // 7. Send alert email
    sendPasswordChangeAlert(resetToken.Email, getIP(r), getUserAgent(r))

    return nil
}
```

**Status:** 🔴 **TO BE IMPLEMENTED**

---

#### Threat 5: Email Account Compromise

**Attack Vector:**
```
1. Attacker gains access to victim's email account
2. Attacker requests password reset on platform
3. Attacker receives magic link in compromised email
4. Attacker resets password and takes over account
```

**Reality Check:**
- If attacker has email access, they can reset passwords on ANY service
- Email is the root of trust for most platforms
- This is a fundamental limitation, not specific to our implementation

**Mitigation (Defense in Depth):**

1. **Activity Alerts**
```go
func SendPasswordChangeAlert(email, ip, device string) {
    emailService.Send(email, `
        ⚠️ Security Alert: Your password was changed

        Time: {timestamp}
        IP Address: {ip}
        Device: {device}
        Location: {city, country}

        If this wasn't you, your email account may be compromised.

        Recommended actions:
        1. Change your email password immediately
        2. Enable 2FA on your email account
        3. Contact support: support@yourplatform.com
    `)
}
```

2. **Recovery Codes (Future Feature - v2.2.0)**
```go
// Generate 10 single-use recovery codes on registration
// User must save offline
// Can be used to recover account if email compromised
recoveryCode := generateSecureCode() // "ABCD-1234-EFGH-5678"
```

3. **2FA/MFA (Future Feature - v2.2.0)**
```
Even if attacker has email access, they need:
- Email access + TOTP code from authenticator app
- Email access + SMS code to phone number
- Email access + biometric authentication
```

**Status:** 🟡 **Partial** (alerts implemented, 2FA planned for v2.2.0)

---

#### Threat 6: NoSQL Injection (Redis)

**Attack Vector:**
```go
// VULNERABLE:
token := r.URL.Query().Get("token") // Input: "abc*" or "abc%"
keys := redis.Keys(ctx, "reset_token:" + token) // Wildcard match!
```

**Mitigation:**
```go
func ValidateToken(token string) error {
    // 1. Fixed length (UUID = 36 chars)
    if len(token) != 36 {
        return errors.New("invalid token format")
    }

    // 2. UUID format validation
    uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
    if !uuidRegex.MatchString(token) {
        return errors.New("invalid token format")
    }

    return nil
}

// Usage:
token := r.URL.Query().Get("token")
if err := ValidateToken(token); err != nil {
    return http.StatusBadRequest
}
// Now safe - no wildcards possible
value := redis.Get(ctx, "reset_token:" + token)
```

**Status:** 🔴 **TO BE IMPLEMENTED**

---

#### Threat 7: Header Injection

**Attack Vector:**
```go
// VULNERABLE:
customHeader := r.Header.Get("X-Custom-Header")
// Input: "value\r\nSet-Cookie: session=hacked"
w.Header().Set("X-Response", customHeader)
```

**Mitigation:**
```go
func SanitizeHeader(value string) string {
    // Remove all control characters
    return strings.Map(func(r rune) rune {
        if r == '\r' || r == '\n' || r == '\t' {
            return -1 // Remove character
        }
        return r
    }, value)
}

// Usage:
customHeader := SanitizeHeader(r.Header.Get("X-Custom-Header"))
w.Header().Set("X-Response", customHeader)
```

**Status:** ✅ Not applicable (we don't echo user headers)

---

#### Threat 8: Security Phrase Injection

**Attack Vector:**
```
User sets security phrase: "<script>alert('XSS')</script>"
Email HTML renders: <div>Your phrase: <script>alert('XSS')</script></div>
```

**Mitigation:**
```go
func sanitizeSecurityPhrase(phrase string) string {
    // 1. Remove control characters
    phrase = strings.Map(func(r rune) rune {
        if r == '\r' || r == '\n' || r == '\t' {
            return -1
        }
        return r
    }, phrase)

    // 2. Remove HTML tags
    phrase = regexp.MustCompile(`<[^>]*>`).ReplaceAllString(phrase, "")

    // 3. Escape special characters for HTML
    phrase = html.EscapeString(phrase)

    // 4. Length limit
    if len(phrase) > 50 {
        phrase = phrase[:50]
    }

    return phrase
}
```

**Status:** 🔴 **TO BE IMPLEMENTED**

---

## Magic Link vs OTP Comparison

### Feature Comparison Matrix

| Feature | OTP Code (Current) | Magic Link | Hybrid (Recommended) |
|---------|-------------------|------------|----------------------|
| **User Experience** | ⭐⭐⭐ Copy/type code | ⭐⭐⭐⭐⭐ One-click | ⭐⭐⭐⭐⭐ Best of both |
| **Mobile Friendly** | ⭐⭐ Switch apps | ⭐⭐⭐⭐⭐ Tap link | ⭐⭐⭐⭐⭐ Flexible |
| **Security** | ⭐⭐⭐⭐ 6 digits | ⭐⭐⭐⭐⭐ UUID token | ⭐⭐⭐⭐⭐ Maximum |
| **Implementation** | ⭐⭐⭐⭐⭐ Simple | ⭐⭐⭐ Complex | ⭐⭐⭐ Moderate |
| **Email Parsing** | ⭐⭐⭐ Plain text | ⭐⭐⭐⭐⭐ HTML button | ⭐⭐⭐⭐⭐ Both |
| **Works Offline** | ⭐⭐⭐⭐ View code | ⭐ Must be online | ⭐⭐⭐ OTP fallback |
| **Phishing Risk** | ⭐⭐⭐ Code stealing | ⭐⭐⭐⭐ Domain check | ⭐⭐⭐⭐ Security phrase |

---

### Recommendation by Use Case

#### 1. Registration Verification
**Recommended:** Hybrid (Magic Link + OTP Fallback)

**Email Format:**
```html
Welcome! Please verify your email:

[Verify Email Button] ← Click this (recommended)

Or enter this code: 123456
(Valid for 15 minutes)
```

**Why Hybrid:**
- Most users prefer one-click (better UX)
- OTP fallback for email clients that strip links
- Accessibility: Works for all users

---

#### 2. Password Reset
**Recommended:** Magic Link Only

**Why:**
- Industry standard (GitHub, Slack, Vercel)
- Better security (single-use token)
- No typing errors
- Clear user flow

**Email Format:**
```html
Reset your password:

[Reset Password Button]

This link expires in 30 minutes and can only be used once.
```

---

#### 3. Login from New Device (Future Feature)
**Recommended:** Magic Link

**Why:**
- Security: Requires email access to approve
- UX: One-click approval
- Similar to "magic link login" services

---

### Implementation Phases

#### Phase 1 (v2.1.0): Keep Current OTP System ✅
- Registration: OTP code (already working)
- Status: No changes needed

#### Phase 2 (v2.1.0): Add Password Reset with Magic Link 🚀
- Forgot password: Magic link only
- New feature, industry standard

#### Phase 3 (v2.2.0): Enhance Registration with Hybrid
- Registration: Magic link (primary) + OTP (fallback)
- Improves UX while maintaining compatibility

#### Phase 4 (v3.0.0): Passwordless Login
- Optional: Magic link login (no password needed)
- Premium feature for enterprise users

---

## Security Phrase (Magic Words)

### Overview

A user-chosen security phrase that appears in all official emails from the platform. This helps users verify email authenticity and prevents phishing attacks.

### Benefits

1. **Anti-Phishing Protection**
   - Users can instantly recognize genuine emails
   - Phishing emails won't have the correct phrase

2. **User Trust**
   - Personalized security measure
   - Increases confidence in email legitimacy

3. **Low Complexity**
   - Easy to understand for non-technical users
   - No additional apps or devices required

4. **Zero Cost**
   - No external services needed
   - Simple implementation

---

### How It Works

#### Step 1: User Setup

User navigates to Profile Settings → Security → Set Security Phrase

```
Examples:
- "Purple Elephant 2025"
- "CoffeeLover#42"
- "MySecretPhrase123"
- "Tokyo-Berlin-Paris"
```

**Validation Rules:**
- Length: 3-50 characters
- Allowed: Letters, numbers, spaces, hyphens, underscores
- Not allowed: HTML tags, control characters
- Case-sensitive (preserves user's capitalization)

---

#### Step 2: Storage

```go
// model/user.go
type User struct {
    ID              string `json:"id"`
    Email           string `json:"email"`
    PasswordHash    string `json:"passwordHash"`
    SecurityPhrase  string `json:"securityPhrase"` // ← NEW
    Verified        bool   `json:"verified"`
    // ... other fields
}
```

**Redis Storage:**
```
Key: user:{userID}
Value: JSON with securityPhrase field
```

---

#### Step 3: Email Integration

All emails sent to user include security phrase in a prominent banner:

```html
<div style="background: #f0f9ff; border: 2px solid #0ea5e9; padding: 15px; margin: 20px 0;">
    🔐 <strong>Your Security Phrase:</strong>
    <div style="color: #0369a1; font-weight: bold; font-size: 18px;">
        Purple Elephant 2025
    </div>
    <small style="color: #64748b;">
        If this phrase is missing or incorrect, this is a phishing attempt.
        Do NOT click any links.
    </small>
</div>
```

---

#### Step 4: User Verification

When user receives email:

✅ **Legitimate Email:**
```
🔐 Your Security Phrase: Purple Elephant 2025
[Correct phrase → Safe to click links]
```

❌ **Phishing Email:**
```
[No security phrase, or wrong phrase → DO NOT CLICK]
```

---

### Email Templates

#### Password Reset Email

```html
<!DOCTYPE html>
<html>
<head>
    <style>
        .security-banner {
            background: #f0f9ff;
            border: 2px solid #0ea5e9;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
        }
        .security-phrase {
            color: #0369a1;
            font-weight: bold;
            font-size: 18px;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <h2>Reset Your Password</h2>

    <p>Hi there,</p>

    <div class="security-banner">
        🔐 <strong>Your Security Phrase:</strong>
        <div class="security-phrase">{{.SecurityPhrase}}</div>
        <small style="color: #64748b;">
            This phrase proves this email is from us. If missing or incorrect,
            this is a phishing attempt.
        </small>
    </div>

    <p>We received a request to reset your password.</p>

    <a href="{{.ResetLink}}" style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px;">
        Reset Password
    </a>

    <p style="color: #94a3b8; margin-top: 20px;">
        This link expires in 30 minutes.<br>
        If you didn't request this, ignore this email.
    </p>
</body>
</html>
```

---

#### Welcome Email

```html
<div class="security-banner">
    🔐 <strong>Your Security Phrase:</strong>
    <div class="security-phrase">{{.SecurityPhrase}}</div>
</div>

<h2>Welcome to Short URL Generator!</h2>

<p>Your account has been successfully verified.</p>

<p>
    <strong>Security Tip:</strong> All future emails from us will include your
    security phrase. If it's missing, the email is not from us.
</p>
```

---

### Implementation Details

#### Backend Endpoint

```go
// POST /api/user/security-phrase
type SetSecurityPhraseRequest struct {
    SecurityPhrase string `json:"securityPhrase"`
}

func (uh *UserHandler) SetSecurityPhrase(w http.ResponseWriter, r *http.Request) {
    // 1. Get authenticated user
    userID := r.Context().Value("userID").(string)

    // 2. Parse request
    var req SetSecurityPhraseRequest
    json.NewDecoder(r.Body).Decode(&req)

    // 3. Validate phrase
    phrase := strings.TrimSpace(req.SecurityPhrase)
    if len(phrase) < 3 || len(phrase) > 50 {
        SendJSONError(w, http.StatusBadRequest,
            errors.New("invalid length"),
            "Security phrase must be 3-50 characters")
        return
    }

    // 4. Sanitize (prevent injection)
    phrase = sanitizeSecurityPhrase(phrase)

    // 5. Update user
    user := getUserFromRedis(userID)
    user.SecurityPhrase = phrase
    saveUserToRedis(user)

    // 6. Log activity
    logActivity(userID, "security_phrase_set", getIP(r))

    SendJSONSuccess(w, http.StatusOK, map[string]string{
        "message": "Security phrase updated",
    })
}

func sanitizeSecurityPhrase(phrase string) string {
    // Remove control characters
    phrase = strings.Map(func(r rune) rune {
        if r == '\r' || r == '\n' || r == '\t' {
            return -1
        }
        return r
    }, phrase)

    // Remove HTML tags
    phrase = regexp.MustCompile(`<[^>]*>`).ReplaceAllString(phrase, "")

    // Escape for HTML
    phrase = html.EscapeString(phrase)

    return phrase
}
```

---

#### Email Service Integration

```go
// email/email.go

func (es *EmailService) SendPasswordReset(user *model.User, resetLink string) error {
    // Get security phrase
    securityPhrase := user.SecurityPhrase
    if securityPhrase == "" {
        securityPhrase = "(Not set - Please set one in your profile)"
    }

    templateData := struct {
        SecurityPhrase string
        ResetLink      string
        UserEmail      string
    }{
        SecurityPhrase: securityPhrase,
        ResetLink:      resetLink,
        UserEmail:      user.Email,
    }

    // Render template with security phrase
    body := renderTemplate("password_reset.html", templateData)

    return es.send(user.Email, "Reset Your Password", body)
}

// Similar for all other emails
func (es *EmailService) SendOTP(user *model.User, otp string) error {
    securityPhrase := user.SecurityPhrase
    if securityPhrase == "" {
        securityPhrase = "(Not set)"
    }

    // Include phrase in OTP email
    body := fmt.Sprintf(`
        <div class="security-banner">
            🔐 Your Security Phrase: <strong>%s</strong>
        </div>
        <p>Your verification code: <strong>%s</strong></p>
    `, securityPhrase, otp)

    return es.send(user.Email, "Your Verification Code", body)
}
```

---

#### Frontend UI

```html
<!-- Profile Section - Security Phrase -->
<div class="profile-section">
    <h3>Email Security</h3>

    <div class="info-box">
        <p>
            Set a personal phrase that appears in all emails from us.
            This helps you identify genuine emails and avoid phishing attempts.
        </p>
    </div>

    <div class="form-group">
        <label for="securityPhrase">
            Security Phrase
            <span class="optional">(3-50 characters)</span>
        </label>
        <input
            type="text"
            id="securityPhrase"
            placeholder="e.g., My Purple Elephant 2025"
            maxlength="50">
        <small class="help-text">
            Choose something memorable but unique. Examples: "Sunset Beach 42",
            "CoffeeLover2025", "Tokyo2025"
        </small>
    </div>

    <button class="btn btn-primary" onclick="updateSecurityPhrase()">
        Save Security Phrase
    </button>

    <!-- Preview -->
    <div class="example-preview">
        <h4>Preview: How it appears in emails</h4>
        <div class="security-banner-preview">
            🔐 <strong>Your Security Phrase:</strong>
            <div class="phrase-text" id="phrasePreview">My Purple Elephant 2025</div>
            <small>If this phrase is missing or incorrect, the email is fake.</small>
        </div>
    </div>
</div>

<script>
// Real-time preview
document.getElementById('securityPhrase').addEventListener('input', function(e) {
    const preview = document.getElementById('phrasePreview');
    preview.textContent = e.target.value || 'My Purple Elephant 2025';
});

async function updateSecurityPhrase() {
    const phrase = document.getElementById('securityPhrase').value.trim();

    if (phrase.length < 3 || phrase.length > 50) {
        showError('Security phrase must be 3-50 characters');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/user/security-phrase`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${accessToken}`
            },
            body: JSON.stringify({ securityPhrase: phrase })
        });

        if (response.ok) {
            showSuccess('Security phrase saved! It will appear in all future emails.');
        } else {
            const data = await response.json();
            showError(data.error || 'Failed to save');
        }
    } catch (error) {
        showError('Network error');
    }
}
</script>
```

---

### Security Considerations

#### 1. Phrase Storage
- ✅ Stored in plaintext (not sensitive data)
- ✅ No encryption needed (needs to be readable for emails)
- ✅ Per-user isolation (each user has own phrase)

#### 2. Phrase Validation
- ✅ Length limit (3-50 chars)
- ✅ Sanitize HTML tags (prevent XSS)
- ✅ Remove control characters (prevent injection)
- ✅ Escape for HTML display

#### 3. Email Security
- ✅ Always include phrase in visible location
- ✅ Use consistent styling (users recognize it)
- ✅ Add warning text ("if missing, it's phishing")

#### 4. User Education
- ✅ Clear instructions on setup
- ✅ Examples of good phrases
- ✅ Explanation of why it matters
- ✅ Preview of how it looks

---

### Edge Cases

#### Case 1: User Never Sets Phrase
**Solution:** Show default message
```
🔐 Security Phrase: (Not set - Set one in your profile for protection)
```

#### Case 2: Empty Phrase
**Solution:** Require minimum 3 characters on save

#### Case 3: Very Long Phrase
**Solution:** Enforce 50 character maximum

#### Case 4: Special Characters
**Solution:** Allow alphanumeric, spaces, hyphens, underscores only

#### Case 5: HTML/Script Tags
**Solution:** Strip all HTML tags before saving

---

## Implementation Plan

### Phase 1: Password Management (Week 1)

#### Tasks:
1. **Backend - Password Reset Endpoints**
   - [ ] POST `/api/auth/forgot-password` - Send magic link
   - [ ] GET `/api/auth/reset-password?token=xxx` - Validate token
   - [ ] POST `/api/auth/reset-password` - Set new password

2. **Backend - Change Password Endpoint**
   - [ ] POST `/api/user/change-password` - Requires current password

3. **Models**
   - [ ] Add `ResetToken` struct
   - [ ] Add request/response models

4. **Email Templates**
   - [ ] Create password reset email HTML
   - [ ] Create password change alert email

5. **Security**
   - [ ] Token validation (UUID format)
   - [ ] Token expiration (30 minutes)
   - [ ] Single-use tokens (delete after use)
   - [ ] Rate limiting (3 requests per hour per email)
   - [ ] Session invalidation on password change

6. **Testing**
   - [ ] Unit tests for token generation
   - [ ] Integration tests for reset flow
   - [ ] Security tests (expired token, reused token)

**Estimated Effort:** 6 hours

---

### Phase 2: Security Phrase (Week 1)

#### Tasks:
1. **Database Schema**
   - [ ] Add `SecurityPhrase` field to User model
   - [ ] Migration for existing users (default empty string)

2. **Backend Endpoint**
   - [ ] PUT `/api/user/security-phrase` - Set/update phrase

3. **Validation & Sanitization**
   - [ ] Phrase length validation (3-50 chars)
   - [ ] HTML tag removal
   - [ ] Control character removal
   - [ ] HTML escaping for display

4. **Email Service Integration**
   - [ ] Update all email templates to include phrase
   - [ ] Add security banner styling
   - [ ] Handle missing phrase gracefully

5. **Frontend UI**
   - [ ] Security phrase input field in profile
   - [ ] Real-time preview
   - [ ] Save button with validation
   - [ ] Example email preview

6. **Testing**
   - [ ] Sanitization tests (XSS, injection)
   - [ ] Email rendering tests
   - [ ] Edge case tests (empty, too long, HTML tags)

**Estimated Effort:** 4 hours

---

### Phase 3: Activity Logging (Week 2)

#### Tasks:
1. **Data Model**
   - [ ] Create `ActivityLog` struct
   - [ ] Define log entry format (JSON)

2. **Redis Storage**
   - [ ] Implement `activity:{userID}` list storage
   - [ ] Set 90-day expiration per entry
   - [ ] Limit to 1000 entries per user

3. **Logging Functions**
   - [ ] `logActivity(userID, action, details, ip, userAgent)`
   - [ ] Log on all major actions (login, logout, CRUD operations)

4. **Backend Endpoint**
   - [ ] GET `/api/user/activity` - Retrieve user's activity log
   - [ ] Pagination support (50 per page)
   - [ ] Filter by action type
   - [ ] Date range filtering

5. **Integration**
   - [ ] Add logging to login handler
   - [ ] Add logging to URL create/update/delete handlers
   - [ ] Add logging to password change handler

6. **Frontend UI**
   - [ ] Activity timeline display
   - [ ] Filter controls
   - [ ] Load more pagination
   - [ ] Export to CSV/JSON

7. **Testing**
   - [ ] Log storage tests
   - [ ] Retrieval and filtering tests
   - [ ] Performance tests (large log sets)

**Estimated Effort:** 6 hours

---

### Phase 4: Enhanced Analytics Dashboard (Week 2-3)

#### Tasks:
1. **Data Aggregation**
   - [ ] Create analytics aggregation functions
   - [ ] Parse user agents (device, browser, OS)
   - [ ] GeoIP lookup (optional, requires service)
   - [ ] Time-series data processing

2. **Backend Endpoints**
   - [ ] GET `/api/user/analytics` - Overall analytics
   - [ ] GET `/api/user/analytics/url/{shortURL}` - Per-URL analytics
   - [ ] GET `/api/user/url/{shortURL}/logs` - Access logs

3. **Frontend - Chart.js Integration**
   - [ ] Add Chart.js library (CDN or npm)
   - [ ] Create line chart for clicks over time
   - [ ] Create pie chart for device breakdown
   - [ ] Create bar chart for top URLs

4. **Frontend - Analytics Page**
   - [ ] Overall dashboard section
   - [ ] Time range selector (7/30/90 days)
   - [ ] Summary cards (total clicks, avg per URL, etc.)
   - [ ] Charts section
   - [ ] Export data button

5. **Performance Optimization**
   - [ ] Cache aggregated data (hourly refresh)
   - [ ] Pagination for large datasets
   - [ ] Lazy load charts

6. **Testing**
   - [ ] Aggregation accuracy tests
   - [ ] Chart rendering tests
   - [ ] Performance tests with large datasets

**Estimated Effort:** 10 hours

---

### Phase 5: User Profile Page (Week 3)

#### Tasks:
1. **Frontend - Profile Section**
   - [ ] Add "Profile" tab in navigation
   - [ ] Account information display (email, join date, last login)
   - [ ] Change password form
   - [ ] Security phrase form
   - [ ] Usage statistics summary

2. **Navigation Updates**
   - [ ] Add tabs: Dashboard | My URLs | Analytics | Activity | Profile
   - [ ] Active tab highlighting
   - [ ] Mobile-responsive navigation

3. **Styling**
   - [ ] Consistent card layout
   - [ ] Form styling
   - [ ] Dark mode support

4. **Testing**
   - [ ] UI/UX testing
   - [ ] Responsive design testing
   - [ ] Accessibility testing

**Estimated Effort:** 5 hours

---

### Phase 6: Testing & Documentation (Week 4)

#### Tasks:
1. **Unit Tests**
   - [ ] Password reset flow tests
   - [ ] Security phrase tests
   - [ ] Activity logging tests
   - [ ] Analytics calculation tests

2. **Integration Tests**
   - [ ] End-to-end password reset
   - [ ] Email delivery tests
   - [ ] Analytics data flow

3. **Security Tests**
   - [ ] Injection attack tests
   - [ ] Token security tests
   - [ ] Rate limiting tests

4. **Documentation**
   - [ ] Update API documentation (Swagger)
   - [ ] Update CLAUDE.md
   - [ ] Update README.md
   - [ ] Create user guide

5. **Code Review**
   - [ ] Security review
   - [ ] Performance review
   - [ ] Code quality review

**Estimated Effort:** 6 hours

---

## Database Schema Changes

### User Model Updates

```go
// model/user.go

type User struct {
    ID              string    `json:"id"`           // UUID
    Email           string    `json:"email"`        // Unique email
    PasswordHash    string    `json:"passwordHash"` // Bcrypt hash
    SecurityPhrase  string    `json:"securityPhrase"` // ← NEW: User's magic words
    Verified        bool      `json:"verified"`
    CreatedAt       time.Time `json:"createdAt"`
    LastLoginAt     time.Time `json:"lastLoginAt"`
    Active          bool      `json:"active"`
    CustomDomain    string    `json:"customDomain"`
}
```

### New Models

```go
// model/auth.go

// ResetToken represents a password reset token
type ResetToken struct {
    Token       string    `json:"token"`       // UUID v4
    UserID      string    `json:"userID"`      // User to reset
    Email       string    `json:"email"`       // Email address
    RequestIP   string    `json:"requestIP"`   // IP that requested reset
    UserAgent   string    `json:"userAgent"`   // Browser/device
    CreatedAt   time.Time `json:"createdAt"`   // Request timestamp
    ExpiresAt   time.Time `json:"expiresAt"`   // Token expiration (30 min)
    Used        bool      `json:"used"`        // Single-use flag
}

// ForgotPasswordRequest represents forgot password request
type ForgotPasswordRequest struct {
    Email string `json:"email" example:"user@example.com"`
}

// ResetPasswordRequest represents password reset with token
type ResetPasswordRequest struct {
    Token       string `json:"token" example:"550e8400-e29b-41d4-a716-446655440000"`
    NewPassword string `json:"newPassword" example:"NewSecurePassword123"`
}

// ChangePasswordRequest represents password change
type ChangePasswordRequest struct {
    CurrentPassword string `json:"currentPassword" example:"OldPassword123"`
    NewPassword     string `json:"newPassword" example:"NewPassword123"`
}

// SetSecurityPhraseRequest represents security phrase update
type SetSecurityPhraseRequest struct {
    SecurityPhrase string `json:"securityPhrase" example:"Purple Elephant 2025"`
}
```

```go
// model/activity.go

// ActivityLog represents a user action log entry
type ActivityLog struct {
    Timestamp time.Time              `json:"timestamp"`
    Action    string                 `json:"action"` // login, logout, url_created, etc.
    Details   map[string]interface{} `json:"details"`
    IP        string                 `json:"ip"`
    UserAgent string                 `json:"userAgent"`
    Location  string                 `json:"location"` // Optional: City, Country
}

// ActivityType constants
const (
    ActivityUserLogin          = "user_login"
    ActivityUserLogout         = "user_logout"
    ActivityPasswordChanged    = "password_changed"
    ActivitySecurityPhraseSet  = "security_phrase_set"
    ActivityURLCreated         = "url_created"
    ActivityURLUpdated         = "url_updated"
    ActivityURLDeleted         = "url_deleted"
    ActivityLoginFailed        = "login_failed"
)
```

```go
// model/analytics.go

// UserAnalytics represents aggregated user analytics
type UserAnalytics struct {
    TotalURLs       int                   `json:"totalUrls"`
    ActiveURLs      int                   `json:"activeUrls"`
    TotalClicks     int64                 `json:"totalClicks"`
    ClicksByDay     []TimeSeriesPoint     `json:"clicksByDay"`
    DeviceBreakdown map[string]int        `json:"deviceBreakdown"`
    BrowserBreakdown map[string]int       `json:"browserBreakdown"`
    TopURLs         []URLStats            `json:"topUrls"`
    RecentActivity  []ActivityLog         `json:"recentActivity"`
}

// TimeSeriesPoint represents a point in time-series data
type TimeSeriesPoint struct {
    Date  string `json:"date"`  // "2025-10-12"
    Value int64  `json:"value"` // Number of clicks
}

// URLStats represents statistics for a single URL
type URLStats struct {
    ShortURL     string `json:"shortURL"`
    OriginalURL  string `json:"originalURL"`
    Clicks       int    `json:"clicks"`
    LastAccessed string `json:"lastAccessed"`
}
```

---

### Redis Data Structure

#### User Data
```
Key: user:{userID}
Type: String (JSON)
Value: {
    "id": "uuid",
    "email": "user@example.com",
    "passwordHash": "bcrypt_hash",
    "securityPhrase": "Purple Elephant 2025",
    "verified": true,
    "createdAt": "2025-01-01T00:00:00Z",
    "lastLoginAt": "2025-10-12T10:30:00Z",
    "active": true,
    "customDomain": ""
}
Expiration: None (persistent)
```

#### Reset Tokens
```
Key: reset_token:{token}
Type: String (JSON)
Value: {
    "token": "550e8400-e29b-41d4-a716-446655440000",
    "userID": "user_uuid",
    "email": "user@example.com",
    "requestIP": "192.168.1.100",
    "userAgent": "Mozilla/5.0...",
    "createdAt": "2025-10-12T10:00:00Z",
    "expiresAt": "2025-10-12T10:30:00Z",
    "used": false
}
Expiration: 30 minutes (auto-delete)
```

#### Activity Logs
```
Key: activity:{userID}
Type: List (LPUSH for newest first)
Value: [
    {
        "timestamp": "2025-10-12T10:30:00Z",
        "action": "url_created",
        "details": {
            "shortURL": "abc123",
            "originalURL": "https://example.com"
        },
        "ip": "192.168.1.100",
        "userAgent": "Mozilla/5.0..."
    },
    { ... }
]
Expiration: 90 days per entry
Max Size: 1000 entries (LTRIM after insert)
```

#### Rate Limiting
```
Key: reset_attempts:{ip}
Type: String (counter)
Value: "3"
Expiration: 1 hour
Purpose: Limit password reset attempts per IP
```

---

## API Endpoints

### Authentication Endpoints

#### 1. Forgot Password
```
POST /api/auth/forgot-password
```

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response (200 OK):**
```json
{
  "message": "If an account exists with this email, a password reset link has been sent."
}
```

**Errors:**
- `400 Bad Request` - Invalid email format
- `429 Too Many Requests` - Rate limit exceeded (max 3 per hour)

**Security Notes:**
- Always return success (don't reveal if email exists)
- Rate limit by IP and email
- Generate UUID v4 token
- Store token in Redis with 30-minute expiration
- Send email with magic link

---

#### 2. Validate Reset Token
```
GET /api/auth/reset-password?token={token}
```

**Query Parameters:**
- `token` (required): UUID v4 reset token

**Response (200 OK):**
```json
{
  "valid": true,
  "email": "user@example.com"
}
```

**Errors:**
- `400 Bad Request` - Invalid token format
- `404 Not Found` - Token not found or expired
- `410 Gone` - Token already used

**Security Notes:**
- Validate UUID format before Redis lookup
- Check expiration timestamp
- Check if already used

---

#### 3. Reset Password
```
POST /api/auth/reset-password
```

**Request:**
```json
{
  "token": "550e8400-e29b-41d4-a716-446655440000",
  "newPassword": "NewSecurePassword123"
}
```

**Response (200 OK):**
```json
{
  "message": "Password reset successful. Please login with your new password."
}
```

**Errors:**
- `400 Bad Request` - Invalid token or weak password
- `404 Not Found` - Token not found or expired
- `410 Gone` - Token already used

**Security Notes:**
- Validate password strength (min 8 chars)
- Hash password with bcrypt
- Delete token immediately after use
- Invalidate all user sessions (force re-login)
- Log activity (password_changed)
- Send alert email to user

---

### User Profile Endpoints

#### 4. Change Password
```
POST /api/user/change-password
```

**Authentication:** Required (Bearer token)

**Request:**
```json
{
  "currentPassword": "OldPassword123",
  "newPassword": "NewPassword123"
}
```

**Response (200 OK):**
```json
{
  "message": "Password changed successfully"
}
```

**Errors:**
- `401 Unauthorized` - Invalid current password
- `400 Bad Request` - Weak new password
- `401 Unauthorized` - Not authenticated

**Security Notes:**
- Verify current password with bcrypt
- Require authentication (can't change without login)
- Hash new password
- Invalidate all sessions except current
- Log activity
- Send alert email

---

#### 5. Set Security Phrase
```
PUT /api/user/security-phrase
```

**Authentication:** Required (Bearer token)

**Request:**
```json
{
  "securityPhrase": "Purple Elephant 2025"
}
```

**Response (200 OK):**
```json
{
  "message": "Security phrase updated successfully",
  "phrase": "Purple Elephant 2025"
}
```

**Errors:**
- `400 Bad Request` - Invalid phrase (too short/long, contains HTML)
- `401 Unauthorized` - Not authenticated

**Security Notes:**
- Validate length (3-50 chars)
- Sanitize HTML tags
- Remove control characters
- Escape for HTML display
- Log activity

---

#### 6. Get User Profile
```
GET /api/user/profile
```

**Authentication:** Required (Bearer token)

**Response (200 OK):**
```json
{
  "id": "user_uuid",
  "email": "user@example.com",
  "verified": true,
  "createdAt": "2025-01-01T00:00:00Z",
  "lastLoginAt": "2025-10-12T10:30:00Z",
  "active": true,
  "customDomain": "",
  "securityPhrase": "Purple Elephant 2025",
  "stats": {
    "totalUrls": 42,
    "totalClicks": 1337
  }
}
```

**Errors:**
- `401 Unauthorized` - Not authenticated

---

### Activity & Analytics Endpoints

#### 7. Get Activity Log
```
GET /api/user/activity?page=1&limit=50&action=url_created&from=2025-10-01&to=2025-10-31
```

**Authentication:** Required (Bearer token)

**Query Parameters:**
- `page` (optional, default: 1): Page number
- `limit` (optional, default: 50, max: 100): Entries per page
- `action` (optional): Filter by action type
- `from` (optional): Start date (ISO 8601)
- `to` (optional): End date (ISO 8601)

**Response (200 OK):**
```json
{
  "page": 1,
  "limit": 50,
  "total": 237,
  "activities": [
    {
      "timestamp": "2025-10-12T10:30:00Z",
      "action": "url_created",
      "details": {
        "shortURL": "abc123",
        "originalURL": "https://example.com"
      },
      "ip": "192.168.1.100",
      "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
      "location": "Tehran, Iran"
    }
  ]
}
```

**Errors:**
- `401 Unauthorized` - Not authenticated
- `400 Bad Request` - Invalid parameters

---

#### 8. Get User Analytics
```
GET /api/user/analytics?range=30
```

**Authentication:** Required (Bearer token)

**Query Parameters:**
- `range` (optional, default: 30): Time range in days (7, 30, 90)

**Response (200 OK):**
```json
{
  "totalUrls": 42,
  "activeUrls": 38,
  "totalClicks": 1337,
  "clicksByDay": [
    {"date": "2025-10-12", "value": 45},
    {"date": "2025-10-11", "value": 52}
  ],
  "deviceBreakdown": {
    "mobile": 540,
    "desktop": 720,
    "tablet": 77
  },
  "browserBreakdown": {
    "Chrome": 800,
    "Safari": 300,
    "Firefox": 200,
    "Other": 37
  },
  "topUrls": [
    {
      "shortURL": "abc123",
      "originalURL": "https://example.com",
      "clicks": 234,
      "lastAccessed": "2025-10-12T10:30:00Z"
    }
  ]
}
```

**Errors:**
- `401 Unauthorized` - Not authenticated

---

#### 9. Get URL Access Logs
```
GET /api/user/url/{shortURL}/logs?page=1&limit=50
```

**Authentication:** Required (Bearer token)

**Path Parameters:**
- `shortURL` (required): Short URL identifier

**Query Parameters:**
- `page` (optional, default: 1): Page number
- `limit` (optional, default: 50, max: 100): Entries per page

**Response (200 OK):**
```json
{
  "shortURL": "abc123",
  "page": 1,
  "limit": 50,
  "total": 234,
  "logs": [
    {
      "timestamp": "2025-10-12T10:30:00Z",
      "ip": "192.168.1.100",
      "userAgent": "Mozilla/5.0...",
      "referer": "https://google.com",
      "device": "Desktop",
      "browser": "Chrome",
      "os": "Windows 10",
      "location": "Tehran, Iran"
    }
  ]
}
```

**Errors:**
- `401 Unauthorized` - Not authenticated
- `403 Forbidden` - URL doesn't belong to user
- `404 Not Found` - URL not found

---

## Frontend Changes

### Navigation Structure

```html
<!-- User Panel Navigation -->
<div class="user-panel">
    <nav class="tabs">
        <a href="#" onclick="showSection('dashboard')" class="tab active">
            📊 Dashboard
        </a>
        <a href="#" onclick="showSection('urls')" class="tab">
            🔗 My URLs
        </a>
        <a href="#" onclick="showSection('analytics')" class="tab">
            📈 Analytics
        </a>
        <a href="#" onclick="showSection('activity')" class="tab">
            📋 Activity
        </a>
        <a href="#" onclick="showSection('profile')" class="tab">
            👤 Profile
        </a>
    </nav>

    <div id="dashboardSection" class="section active">
        <!-- Dashboard content -->
    </div>

    <div id="urlsSection" class="section hidden">
        <!-- URLs list (existing) -->
    </div>

    <div id="analyticsSection" class="section hidden">
        <!-- Analytics charts -->
    </div>

    <div id="activitySection" class="section hidden">
        <!-- Activity timeline -->
    </div>

    <div id="profileSection" class="section hidden">
        <!-- Profile settings -->
    </div>
</div>
```

---

### Profile Section

```html
<div id="profileSection" class="section">
    <h2>Profile Settings</h2>

    <!-- Account Information -->
    <div class="profile-card">
        <h3>Account Information</h3>
        <div class="info-row">
            <label>Email:</label>
            <span id="profileEmail">user@example.com</span>
        </div>
        <div class="info-row">
            <label>Member Since:</label>
            <span id="profileJoinDate">January 1, 2025</span>
        </div>
        <div class="info-row">
            <label>Last Login:</label>
            <span id="profileLastLogin">October 12, 2025 10:30 AM</span>
        </div>
        <div class="info-row">
            <label>Account Status:</label>
            <span class="status-verified">✅ Verified</span>
        </div>
    </div>

    <!-- Password Management -->
    <div class="profile-card">
        <h3>Change Password</h3>
        <div id="changePasswordError" class="error-message hidden"></div>
        <form id="changePasswordForm">
            <div class="form-group">
                <label for="currentPassword">Current Password</label>
                <input type="password" id="currentPassword" required>
            </div>
            <div class="form-group">
                <label for="newPassword">New Password</label>
                <input type="password" id="newPassword" minlength="8" required>
            </div>
            <div class="form-group">
                <label for="confirmNewPassword">Confirm New Password</label>
                <input type="password" id="confirmNewPassword" required>
            </div>
            <button type="submit" class="btn btn-primary">Change Password</button>
        </form>
    </div>

    <!-- Security Phrase -->
    <div class="profile-card">
        <h3>Email Security</h3>
        <p class="help-text">
            Set a personal phrase that appears in all emails from us.
            This helps you verify our emails are genuine and not phishing attempts.
        </p>

        <div class="form-group">
            <label for="securityPhrase">Security Phrase (3-50 characters)</label>
            <input
                type="text"
                id="securityPhrase"
                placeholder="e.g., My Purple Elephant 2025"
                maxlength="50">
            <small class="help-text">
                Choose something memorable but unique.
            </small>
        </div>

        <button class="btn btn-primary" onclick="updateSecurityPhrase()">
            Save Security Phrase
        </button>

        <!-- Preview -->
        <div class="example-preview">
            <h4>Preview: How it appears in emails</h4>
            <div class="security-banner-preview">
                🔐 <strong>Your Security Phrase:</strong>
                <div class="phrase-text" id="phrasePreview">Purple Elephant 2025</div>
            </div>
        </div>
    </div>

    <!-- Usage Statistics -->
    <div class="profile-card">
        <h3>Usage Statistics</h3>
        <div class="stats-row">
            <div class="stat-item">
                <div class="stat-label">Total URLs</div>
                <div class="stat-value" id="profileTotalUrls">42</div>
            </div>
            <div class="stat-item">
                <div class="stat-label">Total Clicks</div>
                <div class="stat-value" id="profileTotalClicks">1,337</div>
            </div>
            <div class="stat-item">
                <div class="stat-label">Avg Clicks/URL</div>
                <div class="stat-value" id="profileAvgClicks">32</div>
            </div>
        </div>
    </div>
</div>
```

---

### Analytics Section

```html
<div id="analyticsSection" class="section">
    <h2>Analytics Dashboard</h2>

    <!-- Time Range Selector -->
    <div class="controls">
        <label>Time Range:</label>
        <select id="analyticsRange" onchange="loadAnalytics()">
            <option value="7">Last 7 Days</option>
            <option value="30" selected>Last 30 Days</option>
            <option value="90">Last 90 Days</option>
        </select>
        <button class="btn btn-secondary" onclick="exportAnalytics()">
            Export Data
        </button>
    </div>

    <!-- Summary Cards -->
    <div class="analytics-summary">
        <div class="summary-card">
            <h4>Total Clicks</h4>
            <div class="value" id="analyticsClicks">1,337</div>
            <div class="change">+12% from last period</div>
        </div>
        <div class="summary-card">
            <h4>Active URLs</h4>
            <div class="value" id="analyticsActiveUrls">38</div>
        </div>
        <div class="summary-card">
            <h4>Avg Daily Clicks</h4>
            <div class="value" id="analyticsAvgDaily">45</div>
        </div>
    </div>

    <!-- Charts -->
    <div class="charts-grid">
        <div class="chart-container">
            <h3>Clicks Over Time</h3>
            <canvas id="clicksChart"></canvas>
        </div>

        <div class="chart-container">
            <h3>Device Breakdown</h3>
            <canvas id="deviceChart"></canvas>
        </div>

        <div class="chart-container">
            <h3>Browser Breakdown</h3>
            <canvas id="browserChart"></canvas>
        </div>

        <div class="chart-container">
            <h3>Top 10 URLs</h3>
            <canvas id="topUrlsChart"></canvas>
        </div>
    </div>
</div>
```

---

### Activity Section

```html
<div id="activitySection" class="section">
    <h2>Activity Log</h2>

    <!-- Filters -->
    <div class="controls">
        <select id="activityFilter" onchange="filterActivity()">
            <option value="">All Activities</option>
            <option value="user_login">Logins</option>
            <option value="password_changed">Password Changes</option>
            <option value="url_created">URL Created</option>
            <option value="url_updated">URL Updated</option>
            <option value="url_deleted">URL Deleted</option>
        </select>
        <button class="btn btn-secondary" onclick="exportActivity()">
            Export CSV
        </button>
    </div>

    <!-- Activity Timeline -->
    <div id="activityTimeline" class="timeline">
        <!-- Activity entries populated via JavaScript -->
    </div>

    <button class="btn btn-secondary" onclick="loadMoreActivity()">
        Load More
    </button>
</div>
```

---

### JavaScript Functions

```javascript
// Profile management
async function loadProfile() {
    const response = await fetch(`${API_BASE}/api/user/profile`, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    const data = await response.json();

    document.getElementById('profileEmail').textContent = data.email;
    document.getElementById('profileJoinDate').textContent =
        new Date(data.createdAt).toLocaleDateString();
    document.getElementById('securityPhrase').value = data.securityPhrase || '';
}

// Change password
async function changePassword(e) {
    e.preventDefault();

    const current = document.getElementById('currentPassword').value;
    const newPass = document.getElementById('newPassword').value;
    const confirm = document.getElementById('confirmNewPassword').value;

    if (newPass !== confirm) {
        showError('changePasswordError', 'Passwords do not match');
        return;
    }

    const response = await fetch(`${API_BASE}/api/user/change-password`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`
        },
        body: JSON.stringify({
            currentPassword: current,
            newPassword: newPass
        })
    });

    if (response.ok) {
        alert('Password changed successfully!');
        document.getElementById('changePasswordForm').reset();
    } else {
        const data = await response.json();
        showError('changePasswordError', data.error);
    }
}

// Update security phrase
async function updateSecurityPhrase() {
    const phrase = document.getElementById('securityPhrase').value.trim();

    if (phrase.length < 3 || phrase.length > 50) {
        alert('Security phrase must be 3-50 characters');
        return;
    }

    const response = await fetch(`${API_BASE}/api/user/security-phrase`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`
        },
        body: JSON.stringify({ securityPhrase: phrase })
    });

    if (response.ok) {
        alert('Security phrase saved!');
    }
}

// Load analytics
async function loadAnalytics() {
    const range = document.getElementById('analyticsRange').value;

    const response = await fetch(`${API_BASE}/api/user/analytics?range=${range}`, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    const data = await response.json();

    // Update charts
    updateClicksChart(data.clicksByDay);
    updateDeviceChart(data.deviceBreakdown);
    updateBrowserChart(data.browserBreakdown);
    updateTopUrlsChart(data.topUrls);
}

// Load activity
async function loadActivity() {
    const response = await fetch(`${API_BASE}/api/user/activity?limit=50`, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    const data = await response.json();

    renderActivityTimeline(data.activities);
}

function renderActivityTimeline(activities) {
    const timeline = document.getElementById('activityTimeline');
    timeline.innerHTML = activities.map(activity => `
        <div class="timeline-item">
            <div class="timeline-icon">${getActivityIcon(activity.action)}</div>
            <div class="timeline-content">
                <div class="timeline-header">
                    <strong>${formatActivityTitle(activity.action)}</strong>
                    <span class="timeline-time">${formatTimestamp(activity.timestamp)}</span>
                </div>
                <div class="timeline-details">
                    ${formatActivityDetails(activity)}
                </div>
            </div>
        </div>
    `).join('');
}
```

---

## Security Checklist

### Input Validation
- [ ] Email format validation (regex)
- [ ] Password strength validation (min 8 chars, complexity)
- [ ] Security phrase validation (length, no HTML)
- [ ] Token format validation (UUID)
- [ ] URL parameter sanitization

### Authentication & Authorization
- [ ] JWT token validation on all protected endpoints
- [ ] Token expiration checks
- [ ] Refresh token rotation
- [ ] Session invalidation on password change
- [ ] User ownership verification (URLs, activity logs)

### Password Security
- [ ] Bcrypt hashing (cost factor 10+)
- [ ] Current password verification on change
- [ ] Password reset tokens expire in 30 minutes
- [ ] Single-use reset tokens
- [ ] Rate limiting on password reset requests

### Token Security
- [ ] UUID v4 for reset tokens (122-bit entropy)
- [ ] Tokens stored with expiration in Redis
- [ ] Token deleted immediately after use
- [ ] Token format validation before lookup
- [ ] Rate limiting on token validation attempts

### Email Security
- [ ] TLS/SSL for SMTP connections
- [ ] Email injection prevention (control character removal)
- [ ] Security phrase sanitization (HTML removal)
- [ ] SPF, DKIM, DMARC configuration
- [ ] Alert emails on sensitive operations

### Rate Limiting
- [ ] Password reset requests: 3 per hour per email
- [ ] Token validation attempts: 10 per hour per IP
- [ ] Login attempts: 5 per 15 minutes per email
- [ ] API calls: Existing rate limiter (10 req/s per IP)

### Logging & Monitoring
- [ ] Log all authentication attempts
- [ ] Log all password changes
- [ ] Log all security phrase changes
- [ ] Log all URL operations
- [ ] Activity logs stored securely with 90-day retention

### Data Protection
- [ ] Passwords hashed with bcrypt
- [ ] Security phrases sanitized
- [ ] Activity logs contain no sensitive data
- [ ] User agents and IPs logged for security
- [ ] Redis data encrypted at rest (infrastructure level)

### HTTPS/TLS
- [ ] Force HTTPS in production
- [ ] Secure cookie flags (HttpOnly, Secure, SameSite)
- [ ] HSTS headers
- [ ] TLS 1.2+ only

### Error Handling
- [ ] Generic error messages (don't reveal if email exists)
- [ ] No stack traces in production
- [ ] Structured error logging
- [ ] User-friendly error messages

### Injection Prevention
- [ ] Email injection prevention
- [ ] NoSQL injection prevention (Redis)
- [ ] XSS prevention (HTML escaping)
- [ ] Header injection prevention

---

## Testing Requirements

### Unit Tests

#### Password Reset
- [ ] Token generation (UUID format)
- [ ] Token expiration (30 minutes)
- [ ] Token validation (format, existence, expiration)
- [ ] Single-use enforcement
- [ ] Email format validation
- [ ] Password strength validation

#### Security Phrase
- [ ] Length validation (3-50 chars)
- [ ] HTML tag removal
- [ ] Control character removal
- [ ] XSS prevention (script tags)
- [ ] SQL/NoSQL injection characters

#### Activity Logging
- [ ] Log entry creation
- [ ] Timestamp accuracy
- [ ] IP and user agent capture
- [ ] Activity type validation
- [ ] Storage in Redis list
- [ ] Pagination logic

#### Analytics
- [ ] Data aggregation accuracy
- [ ] Time-series calculation
- [ ] Device/browser parsing
- [ ] Top URLs sorting
- [ ] Date range filtering

---

### Integration Tests

#### Password Reset Flow
```go
func TestPasswordResetFlow(t *testing.T) {
    // 1. Request password reset
    resp := POST("/api/auth/forgot-password", {"email": "test@example.com"})
    assert.Equal(t, 200, resp.StatusCode)

    // 2. Get token from Redis
    token := getResetTokenFromRedis("test@example.com")
    assert.NotEmpty(t, token)

    // 3. Validate token
    resp = GET("/api/auth/reset-password?token=" + token)
    assert.Equal(t, 200, resp.StatusCode)

    // 4. Reset password
    resp = POST("/api/auth/reset-password", {
        "token": token,
        "newPassword": "NewPassword123"
    })
    assert.Equal(t, 200, resp.StatusCode)

    // 5. Verify token deleted
    tokenExists := checkTokenInRedis(token)
    assert.False(t, tokenExists)

    // 6. Verify can login with new password
    resp = POST("/api/auth/login", {
        "email": "test@example.com",
        "password": "NewPassword123"
    })
    assert.Equal(t, 200, resp.StatusCode)
}
```

#### Security Phrase Flow
```go
func TestSecurityPhraseFlow(t *testing.T) {
    // 1. Login
    token := loginAsTestUser()

    // 2. Set security phrase
    resp := PUT("/api/user/security-phrase", {
        "securityPhrase": "Test Phrase 123"
    }, headers{"Authorization": "Bearer " + token})
    assert.Equal(t, 200, resp.StatusCode)

    // 3. Verify stored in user data
    user := getUserFromRedis("test_user_id")
    assert.Equal(t, "Test Phrase 123", user.SecurityPhrase)

    // 4. Request password reset
    POST("/api/auth/forgot-password", {"email": "test@example.com"})

    // 5. Verify email contains security phrase
    email := getLastSentEmail("test@example.com")
    assert.Contains(t, email.Body, "Test Phrase 123")
}
```

---

### Security Tests

#### Token Security
```go
func TestTokenSecurity(t *testing.T) {
    // Test 1: Expired token rejected
    expiredToken := createExpiredResetToken()
    resp := GET("/api/auth/reset-password?token=" + expiredToken)
    assert.Equal(t, 404, resp.StatusCode)

    // Test 2: Used token rejected
    token := createResetToken()
    resetPasswordWithToken(token)
    resp = GET("/api/auth/reset-password?token=" + token)
    assert.Equal(t, 410, resp.StatusCode) // Gone

    // Test 3: Invalid format rejected
    resp = GET("/api/auth/reset-password?token=invalid")
    assert.Equal(t, 400, resp.StatusCode)

    // Test 4: NoSQL injection prevented
    resp = GET("/api/auth/reset-password?token=abc*")
    assert.Equal(t, 400, resp.StatusCode)
}
```

#### Rate Limiting
```go
func TestPasswordResetRateLimit(t *testing.T) {
    email := "test@example.com"

    // Send 3 requests (allowed)
    for i := 0; i < 3; i++ {
        resp := POST("/api/auth/forgot-password", {"email": email})
        assert.Equal(t, 200, resp.StatusCode)
    }

    // 4th request should be rate limited
    resp := POST("/api/auth/forgot-password", {"email": email})
    assert.Equal(t, 429, resp.StatusCode) // Too Many Requests
}
```

#### Injection Prevention
```go
func TestEmailInjection(t *testing.T) {
    // Test 1: Newline injection
    resp := POST("/api/auth/forgot-password", {
        "email": "test@example.com\nBCC: attacker@evil.com"
    })
    assert.Equal(t, 400, resp.StatusCode)

    // Test 2: Security phrase XSS
    token := loginAsTestUser()
    resp = PUT("/api/user/security-phrase", {
        "securityPhrase": "<script>alert('XSS')</script>"
    }, authHeader(token))
    assert.Equal(t, 200, resp.StatusCode)

    // Verify HTML tags removed
    user := getUserFromRedis("test_user_id")
    assert.NotContains(t, user.SecurityPhrase, "<script>")
}
```

---

### Performance Tests

#### Analytics Aggregation
```go
func BenchmarkAnalyticsAggregation(b *testing.B) {
    // Create test data: 1000 URLs with 100 clicks each
    setupTestData(1000, 100)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        getAnalytics("test_user_id", 30)
    }
}

// Expected: < 500ms for 100k log entries
```

#### Activity Log Retrieval
```go
func BenchmarkActivityLogRetrieval(b *testing.B) {
    // Create 1000 activity entries
    setupActivityLogs("test_user_id", 1000)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        getActivityLog("test_user_id", 1, 50)
    }
}

// Expected: < 50ms for pagination query
```

---

### UI/UX Tests

#### Profile Page
- [ ] Profile information displays correctly
- [ ] Change password form validates input
- [ ] Security phrase updates successfully
- [ ] Error messages display correctly
- [ ] Dark mode styling applies correctly

#### Analytics Page
- [ ] Charts render correctly
- [ ] Time range selector works
- [ ] Data updates on range change
- [ ] Export function generates CSV
- [ ] Responsive design on mobile

#### Activity Page
- [ ] Timeline renders correctly
- [ ] Filters work as expected
- [ ] Pagination loads more entries
- [ ] Activity icons display correctly
- [ ] Timestamps formatted correctly

---

## Migration Plan

### For Existing Users

#### 1. Database Migration
```go
// Migration script: add SecurityPhrase field to existing users
func MigrateExistingUsers(ctx context.Context, rdb *redis.Client) error {
    // Get all user keys
    keys, err := rdb.Keys(ctx, "user:*").Result()
    if err != nil {
        return err
    }

    for _, key := range keys {
        // Skip non-user keys
        if strings.Contains(key, "email") {
            continue
        }

        // Get user data
        userData, err := rdb.Get(ctx, key).Result()
        if err != nil {
            continue
        }

        var user model.User
        json.Unmarshal([]byte(userData), &user)

        // Add empty security phrase if not set
        if user.SecurityPhrase == "" {
            user.SecurityPhrase = ""
            updatedData, _ := json.Marshal(user)
            rdb.Set(ctx, key, updatedData, 0)
        }
    }

    log.Info().Msgf("Migrated %d users", len(keys))
    return nil
}
```

#### 2. Email Templates Update
- Update all email templates to include security phrase
- Handle empty phrase gracefully (show "Not set" message)
- Encourage users to set phrase via email notification

#### 3. Feature Rollout
1. Deploy backend changes (backwards compatible)
2. Run database migration script
3. Update frontend with new profile section
4. Send announcement email to all users
5. Monitor for issues

---

## Conclusion

This document provides a comprehensive implementation guide for enhancing user profile management and security features in the Short URL Generator platform. The planned features focus on:

1. **Security**: Password reset with magic links, security phrases, activity logging
2. **User Experience**: Enhanced analytics, profile management, activity visibility
3. **Best Practices**: Industry-standard authentication flows, anti-phishing measures

**Total Estimated Effort:** 37 hours (≈5 working days)

**Recommended Implementation Order:**
1. Password Management (Week 1)
2. Security Phrase (Week 1)
3. Activity Logging (Week 2)
4. Enhanced Analytics (Week 2-3)
5. User Profile Page (Week 3)
6. Testing & Documentation (Week 4)

**Next Steps:**
- Review and approve this implementation plan
- Assign developers and set timeline
- Begin Phase 1 implementation
- Set up testing environment
- Create project tracking (GitHub issues/project board)

---

**Document Status:** ✅ Complete
**Ready for Implementation:** Yes
**Approval Required:** Yes
