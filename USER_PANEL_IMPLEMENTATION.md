# User Panel Implementation Plan

## Overview
This document outlines the implementation plan for adding a complete user authentication system and user panel with advanced URL management features.

## Features to Implement

### 1. User Authentication System
- ✅ User model created (model/user.go)
- ✅ JWT authentication utilities (auth/jwt.go)
- ✅ Authentication middleware (middleware/auth.go)
- ✅ Email service for OTP delivery (email/email.go)
- ⏳ User registration endpoint
- ⏳ OTP verification endpoint
- ⏳ Login endpoint
- ⏳ Token refresh endpoint
- ⏳ Logout endpoint

### 2. User Panel Dashboard
- ⏳ User dashboard HTML UI
- ⏳ My URLs page (list, search, filter)
- ⏳ Create URL form with all features
- ⏳ URL details/edit page
- ⏳ User profile/settings page
- ⏳ Dark mode toggle

### 3. Advanced URL Features
- ✅ URL model updated with new fields
- ⏳ Custom domains support
  - Domain verification
  - DNS setup instructions
  - Domain-specific routing
- ⏳ Password-protected URLs
  - Password unlock page
  - Bcrypt hashing
  - Password validation
- ⏳ Scheduled activation/deactivation
  - Start/end date fields
  - Background job for activation
  - Manual activation toggle
- ⏳ URL aliases
  - Multiple short codes → same URL
  - Alias management UI
  - Redirect routing

### 4. Configuration Updates
- ⏳ Add email configuration (SMTP settings)
- ⏳ Add JWT secret and token durations
- ⏳ Add user features flags

### 5. Database Schema (Redis)
**Users:**
- Key: `user:{userID}` → JSON of User struct
- Key: `user:email:{email}` → userID (for email lookup)
- Key: `otp:{email}` → JSON of OTP struct

**User URLs:**
- Key: `user:urls:{userID}` → Set of shortURL codes
- Existing URL keys remain the same, just add UserID field

**Custom Domains:**
- Key: `domain:{domain}` → userID (domain ownership)
- Key: `domain:verified:{domain}` → boolean

**URL Aliases:**
- Key: `alias:{aliasCode}` → original shortURL

## Implementation Steps

### Phase 1: Core Authentication (Current)
1. ✅ Create user model
2. ✅ Create JWT utilities
3. ✅ Create email service
4. ✅ Create auth middleware
5. Create user handler with registration/login/verify endpoints
6. Update config.yaml with email and JWT settings
7. Wire up auth routes in main.go

### Phase 2: User Panel UI
1. Create user dashboard HTML (similar to admin panel)
2. Add login/register pages
3. Add my URLs list page
4. Add create URL form
5. Add dark mode CSS and toggle

### Phase 3: Advanced Features
1. Implement password-protected URLs
2. Implement scheduled activation
3. Implement URL aliases
4. Implement custom domains

### Phase 4: Testing & Documentation
1. Test all auth flows
2. Test all URL features
3. Update README.md
4. Update Swagger docs
5. Create user guide

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register with email
- `POST /api/auth/verify-otp` - Verify OTP code
- `POST /api/auth/login` - Login with email/password
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout (invalidate tokens)

### User URLs
- `GET /api/user/urls` - List user's URLs
- `POST /api/user/urls` - Create URL (authenticated)
- `GET /api/user/urls/{id}` - Get URL details
- `PUT /api/user/urls/{id}` - Update URL
- `DELETE /api/user/urls/{id}` - Delete URL
- `POST /api/user/urls/{id}/aliases` - Add alias
- `DELETE /api/user/urls/{id}/aliases/{alias}` - Remove alias

### User Profile
- `GET /api/user/profile` - Get user profile
- `PUT /api/user/profile` - Update profile
- `PUT /api/user/password` - Change password

### Custom Domains
- `POST /api/user/domains` - Add custom domain
- `POST /api/user/domains/{domain}/verify` - Verify domain
- `DELETE /api/user/domains/{domain}` - Remove domain

### User Panel
- `GET /user/dashboard` - User dashboard UI
- `GET /user/login` - Login page
- `GET /user/register` - Registration page

## Configuration Example

```yaml
# Email configuration
email:
  enabled: false  # Set to true in production
  smtp_host: "smtp.gmail.com"
  smtp_port: "587"
  smtp_username: "your-email@gmail.com"
  smtp_password: "your-app-password"
  from_email: "noreply@yourdomain.com"
  from_name: "Short URL Generator"

# JWT configuration
jwt:
  secret_key: "your-very-long-secret-key-change-this"  # CHANGE IN PRODUCTION!
  access_token_duration: 15m  # 15 minutes
  refresh_token_duration: 7d  # 7 days

# User features
user_features:
  registration_enabled: true
  custom_domains_enabled: true
  password_protected_urls_enabled: true
  scheduled_urls_enabled: true
  url_aliases_enabled: true
  max_urls_per_user: 1000
  max_aliases_per_url: 10
```

## Progress Tracking

**Completed:**
- User model structure
- JWT authentication system
- Email service with OTP
- Auth middleware
- Updated URL model

**Next Steps:**
1. Create user handler (register, login, verify)
2. Create config updates
3. Wire up routes
4. Build user panel UI
5. Implement advanced features

**Estimated Time:**
- Phase 1 (Auth): ~4-6 hours
- Phase 2 (UI): ~6-8 hours
- Phase 3 (Features): ~8-10 hours
- Phase 4 (Testing): ~2-4 hours
**Total: ~20-28 hours**

This is a significant feature addition that will transform the application from a simple URL shortener into a full-featured SaaS platform.
