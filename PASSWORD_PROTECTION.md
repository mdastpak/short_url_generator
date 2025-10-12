# Password Protection for Short URLs

## Overview

The URL shortening service supports optional password protection for short URLs. When a URL is password-protected, users must enter the correct password before being redirected to the destination.

## Features

### Core Functionality
- **Optional Protection**: URLs can be created with or without password protection
- **Secure Storage**: Passwords are hashed using bcrypt (cost factor 10)
- **Password Prompt**: Beautiful, responsive password prompt page shown before redirect
- **Session-based Access**: Correct password grants 24-hour access via session cookie
- **User Management**: URL owners can set, update, or remove password protection
- **Anonymous Support**: Both authenticated and anonymous users can create password-protected URLs

### Security Features
- **Bcrypt Hashing**: Passwords never stored in plain text
- **Rate Limiting**: Password verification attempts limited to prevent brute force
- **Session Cookies**: HTTP-only, secure cookies (when HTTPS enabled)
- **No Password Leakage**: Passwords never returned in API responses
- **Constant-time Comparison**: Uses bcrypt.CompareHashAndPassword

### User Experience
- **Single Password Entry**: Once verified, access granted for 24 hours via cookie
- **Responsive Design**: Password prompt works on mobile and desktop
- **Clear Error Messages**: Invalid password feedback without revealing security details
- **Show/Hide Password**: Toggle visibility for easier entry

## API Endpoints

### 1. Create Password-Protected URL

**Endpoint**: `POST /shorten`

**Request Body**:
```json
{
  "originalURL": "https://example.com/secret-page",
  "password": "MySecurePassword123",
  "expiry": "2024-12-31T23:59:59Z",
  "maxUsage": 100
}
```

**Response** (201 Created):
```json
{
  "success": true,
  "message": "Short URL created successfully",
  "data": {
    "originalURL": "https://example.com/secret-page",
    "shortURL": "abc123xyz",
    "fullURL": "http://localhost:8080/abc123xyz",
    "managementID": "550e8400-e29b-41d4-a716-446655440000",
    "createdAt": "2024-01-15T10:30:00Z",
    "expiry": "2024-12-31T23:59:59Z",
    "maxUsage": 100,
    "currentUsage": 0,
    "isProtected": true
  }
}
```

**Notes**:
- `password` field is optional
- Password is hashed with bcrypt before storage
- Response includes `isProtected: true` but never returns the password hash
- Minimum password length: 6 characters
- Maximum password length: 72 characters (bcrypt limitation)

### 2. Access Password-Protected URL

**Flow**:
1. User accesses `GET /{shortURL}`
2. If password-protected and no valid session → redirect to `/password/{shortURL}`
3. User enters password on prompt page
4. Submit to `POST /verify-password/{shortURL}`
5. If correct → set session cookie → redirect to original URL
6. If incorrect → show error message

**Endpoint**: `GET /{shortURL}`

**Responses**:
- **No password**: 301 redirect to original URL
- **Password required**: 302 redirect to `/password/{shortURL}`
- **Valid session**: 301 redirect to original URL (cookie check)
- **Not found**: 404
- **Expired**: 410
- **Usage limit exceeded**: 403

### 3. Verify Password

**Endpoint**: `POST /verify-password/{shortURL}`

**Request Body**:
```json
{
  "password": "MySecurePassword123"
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "Password verified successfully",
  "data": {
    "redirectURL": "https://example.com/secret-page"
  }
}
```

**Response** (401 Unauthorized):
```json
{
  "success": false,
  "error": "Invalid password"
}
```

**Rate Limiting**:
- Maximum 5 attempts per IP per short URL per 15 minutes
- After 5 failed attempts, IP is temporarily blocked for that URL

**Security**:
- Sets HTTP-only session cookie `url_access_{shortURL}` with 24-hour expiration
- Cookie is secure when HTTPS is enabled
- Constant-time password comparison via bcrypt

### 4. Set/Update Password (Authenticated)

**Endpoint**: `PUT /api/user/url/{shortURL}/password`

**Headers**:
```
Authorization: Bearer {access_token}
```

**Request Body**:
```json
{
  "password": "NewSecurePassword456"
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "Password protection enabled",
  "data": {
    "shortURL": "abc123xyz",
    "isProtected": true
  }
}
```

**Validation**:
- User must be authenticated
- User must own the URL (UserID match)
- Password length: 6-72 characters
- Password is hashed before storage

### 5. Remove Password (Authenticated)

**Endpoint**: `DELETE /api/user/url/{shortURL}/password`

**Headers**:
```
Authorization: Bearer {access_token}
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "Password protection removed",
  "data": {
    "shortURL": "abc123xyz",
    "isProtected": false
  }
}
```

**Validation**:
- User must be authenticated
- User must own the URL (UserID match)
- Removes password hash and clears all session cookies

## Data Model

### URL Struct (model/url.go)

```go
type URL struct {
    ManagementID   string    `json:"managementID"`
    OriginalURL    string    `json:"originalURL"`
    ShortURL       string    `json:"shortURL"`
    CreatedAt      time.Time `json:"createdAt"`
    Expiry         time.Time `json:"expiry"`
    MaxUsage       int       `json:"maxUsage"`
    CurrentUsage   int       `json:"currentUsage"`
    UserID         string    `json:"userID"`
    CustomDomain   string    `json:"customDomain"`
    PasswordHash   string    `json:"passwordHash"`   // Bcrypt hash (empty if not protected)
    ScheduledStart time.Time `json:"scheduledStart"`
    ScheduledEnd   time.Time `json:"scheduledEnd"`
    Aliases        []string  `json:"aliases"`
    Active         bool      `json:"active"`
}
```

### Redis Data Model

**URL Storage**:
- Key: `{shortURL}`
- Value: JSON-marshaled URL struct with `passwordHash` field
- `passwordHash` is empty string if URL is not password-protected

**Session Storage**:
- Key: `password_session:{shortURL}:{sessionID}`
- Value: Timestamp of verification
- TTL: 24 hours
- Format: ISO 8601 timestamp string

**Rate Limiting**:
- Key: `password_attempts:{shortURL}:{ip}`
- Value: Counter (incremented on failed attempts)
- TTL: 15 minutes
- Max value: 5 (then blocked)

## Implementation Details

### Password Hashing

```go
import "golang.org/x/crypto/bcrypt"

// Hash password with bcrypt (cost factor 10)
hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

// Verify password (constant-time comparison)
err := bcrypt.CompareHashAndPassword([]byte(url.PasswordHash), []byte(password))
```

**Security Properties**:
- Bcrypt cost factor: 10 (default)
- Salt automatically generated and included in hash
- Constant-time comparison prevents timing attacks
- Hash length: 60 characters

### Session Management

**Session Cookie**:
```
Name: url_access_{shortURL}
Value: {sessionID} (UUID v4)
MaxAge: 86400 (24 hours)
HttpOnly: true
Secure: true (if HTTPS)
SameSite: Lax
Path: /
```

**Session Validation**:
1. Extract cookie from request
2. Look up session in Redis: `password_session:{shortURL}:{sessionID}`
3. If exists and not expired → grant access
4. If missing or expired → require password

### Rate Limiting

**Algorithm**:
1. On password verification attempt, check `password_attempts:{shortURL}:{ip}`
2. If counter >= 5 → return 429 Too Many Requests
3. If counter < 5 → proceed with verification
4. On failure → increment counter (set 15-minute TTL if first attempt)
5. On success → delete counter

**IP Extraction**:
- Check `X-Forwarded-For` header (reverse proxy)
- Fallback to `X-Real-IP` header
- Fallback to `RemoteAddr`

## Password Prompt Page

### Features
- Clean, centered design
- Responsive layout (mobile-friendly)
- Show/hide password toggle
- Clear error messages
- Loading state during verification
- Keyboard support (Enter to submit)

### HTML Structure (handler/password_prompt.html)
```html
<!DOCTYPE html>
<html>
<head>
    <title>Password Required</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        /* Responsive CSS with modern design */
    </style>
</head>
<body>
    <div class="container">
        <div class="lock-icon">🔒</div>
        <h1>Password Required</h1>
        <p>This short URL is password-protected. Please enter the password to continue.</p>

        <form id="passwordForm">
            <div class="input-group">
                <input type="password" id="passwordInput" placeholder="Enter password" required>
                <button type="button" id="togglePassword">👁️</button>
            </div>
            <button type="submit" id="submitButton">Unlock</button>
            <div id="error" class="error"></div>
        </form>
    </div>

    <script>
        // JavaScript for form submission and validation
    </script>
</body>
</html>
```

## Use Cases

### 1. Private Document Sharing
```bash
# Create password-protected link for confidential document
curl -X POST http://localhost:8080/shorten \
  -H "Content-Type: application/json" \
  -d '{
    "originalURL": "https://docs.company.com/confidential-report.pdf",
    "password": "Team2024!",
    "expiry": "2024-12-31T23:59:59Z"
  }'

# Share link: http://localhost:8080/abc123
# Recipients need password "Team2024!" to access
```

### 2. Limited-Time Event Access
```bash
# Create password-protected event link with expiry
curl -X POST http://localhost:8080/shorten \
  -H "Content-Type: application/json" \
  -d '{
    "originalURL": "https://zoom.us/j/123456789",
    "password": "EventPass2024",
    "expiry": "2024-06-30T18:00:00Z",
    "maxUsage": 50
  }'

# Link expires after date or 50 accesses
```

### 3. User-Managed Protection
```bash
# User creates URL without password initially
curl -X POST http://localhost:8080/shorten \
  -H "Authorization: Bearer {token}" \
  -d '{"originalURL": "https://example.com/page"}'

# Later, user adds password protection
curl -X PUT http://localhost:8080/api/user/url/abc123/password \
  -H "Authorization: Bearer {token}" \
  -d '{"password": "SecureNow123"}'

# Even later, user removes password
curl -X DELETE http://localhost:8080/api/user/url/abc123/password \
  -H "Authorization: Bearer {token}"
```

## Security Considerations

### Threat Model

**Protected Against**:
- ✅ Brute force attacks (rate limiting: 5 attempts per 15 minutes)
- ✅ Timing attacks (bcrypt constant-time comparison)
- ✅ Password storage compromise (bcrypt hashing)
- ✅ Session hijacking (HTTP-only cookies)
- ✅ MITM attacks (secure cookies when HTTPS enabled)

**Not Protected Against**:
- ❌ Password sharing (if user shares password, anyone can access)
- ❌ Session token theft (if cookie stolen, attacker has 24h access)
- ❌ Social engineering (attacker tricks user into revealing password)
- ❌ Weak passwords (users can still choose "123456")

### Best Practices

**For Users**:
1. Use strong passwords (minimum 12 characters, mix of upper/lower/numbers/symbols)
2. Don't share passwords via insecure channels (SMS, plain email)
3. Use unique passwords for each protected URL
4. Set expiry dates for temporary content
5. Monitor access logs for suspicious activity

**For Administrators**:
1. Enable HTTPS to secure cookie transmission
2. Monitor rate limiting logs for brute force attempts
3. Consider password strength requirements in UI
4. Implement IP blocking for persistent attackers
5. Log password verification attempts for audit

## Testing

### Manual Testing

**Test 1: Create Password-Protected URL**
```bash
curl -X POST http://localhost:8080/shorten \
  -H "Content-Type: application/json" \
  -d '{
    "originalURL": "https://example.com",
    "password": "TestPassword123"
  }'

# Expected: 201 Created with isProtected: true
```

**Test 2: Access Without Password**
```bash
curl -i http://localhost:8080/abc123

# Expected: 302 redirect to /password/abc123
```

**Test 3: Verify Password (Correct)**
```bash
curl -X POST http://localhost:8080/verify-password/abc123 \
  -H "Content-Type: application/json" \
  -d '{"password": "TestPassword123"}' \
  -c cookies.txt

# Expected: 200 OK with redirectURL
# Cookie saved to cookies.txt
```

**Test 4: Access With Valid Session**
```bash
curl -i http://localhost:8080/abc123 -b cookies.txt

# Expected: 301 redirect to https://example.com
```

**Test 5: Verify Password (Incorrect)**
```bash
curl -X POST http://localhost:8080/verify-password/abc123 \
  -H "Content-Type: application/json" \
  -d '{"password": "WrongPassword"}'

# Expected: 401 Unauthorized
```

**Test 6: Rate Limiting**
```bash
# Make 6 failed attempts rapidly
for i in {1..6}; do
  curl -X POST http://localhost:8080/verify-password/abc123 \
    -H "Content-Type: application/json" \
    -d '{"password": "Wrong"}'
done

# Expected: First 5 return 401, 6th returns 429 (rate limited)
```

**Test 7: Set Password (Authenticated User)**
```bash
curl -X PUT http://localhost:8080/api/user/url/abc123/password \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{"password": "NewPassword456"}'

# Expected: 200 OK with isProtected: true
```

**Test 8: Remove Password (Authenticated User)**
```bash
curl -X DELETE http://localhost:8080/api/user/url/abc123/password \
  -H "Authorization: Bearer {token}"

# Expected: 200 OK with isProtected: false
```

### Automated Testing

```go
// Test password hashing
func TestPasswordHashing(t *testing.T) {
    password := "TestPassword123"
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    assert.NoError(t, err)

    // Correct password should match
    err = bcrypt.CompareHashAndPassword(hash, []byte(password))
    assert.NoError(t, err)

    // Wrong password should not match
    err = bcrypt.CompareHashAndPassword(hash, []byte("WrongPassword"))
    assert.Error(t, err)
}

// Test rate limiting
func TestPasswordRateLimiting(t *testing.T) {
    // Simulate 5 failed attempts
    for i := 0; i < 5; i++ {
        resp := verifyPassword("abc123", "WrongPassword", "192.168.1.1")
        assert.Equal(t, 401, resp.StatusCode)
    }

    // 6th attempt should be rate limited
    resp := verifyPassword("abc123", "WrongPassword", "192.168.1.1")
    assert.Equal(t, 429, resp.StatusCode)
}
```

## Performance Considerations

### Bcrypt Performance
- Hashing time: ~50-100ms (cost factor 10)
- Verification time: ~50-100ms
- Impact: Negligible for URL creation, acceptable for verification
- Recommendation: Keep cost factor at 10 for balance of security and performance

### Session Storage
- Redis lookup: ~1-2ms
- Impact: Minimal (faster than password verification)
- Cache-friendly: Session checks are fast path

### Rate Limiting
- Redis INCR: <1ms
- Impact: Negligible
- Protects against brute force without performance degradation

## Future Enhancements

### Potential Features
1. **Password Strength Indicator**: Real-time feedback on password strength
2. **2FA Support**: Optional two-factor authentication for high-security URLs
3. **Password Expiry**: Force password change after X days
4. **Access Logs**: Detailed logs of password verification attempts
5. **Passwordless Options**: Magic links, OTP via email/SMS
6. **Password Recovery**: Allow URL owners to reset password via email
7. **Shared Passwords**: Multiple passwords for same URL (team access)
8. **IP Whitelisting**: Bypass password for trusted IPs

### Analytics Integration
- Track password verification success/failure rates
- Monitor brute force attempt patterns
- Alert on suspicious activity (many failed attempts)
- Dashboard showing password-protected URL usage

## Summary

Password protection adds an essential security layer to the URL shortening service, allowing users to control access to sensitive content. The implementation balances security (bcrypt hashing, rate limiting, session management) with user experience (24-hour sessions, responsive prompt page) to provide a robust yet user-friendly feature.

**Key Benefits**:
- ✅ Secure password storage (bcrypt)
- ✅ Brute force protection (rate limiting)
- ✅ Easy user experience (session cookies)
- ✅ Flexible management (set/update/remove)
- ✅ Full API support (programmatic access)
