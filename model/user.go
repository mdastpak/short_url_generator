package model

import "time"

// User represents a registered user (for internal storage)
type User struct {
	ID             string    `json:"id"`             // UUID
	Email          string    `json:"email"`          // Email address (unique)
	PasswordHash   string    `json:"passwordHash"`   // Bcrypt password hash (stored but not exposed in API)
	SecurityPhrase string    `json:"securityPhrase"` // User's security phrase for email verification (anti-phishing)
	Verified       bool      `json:"verified"`       // Email verification status
	CreatedAt      time.Time `json:"createdAt"`      // Registration timestamp
	LastLoginAt    time.Time `json:"lastLoginAt"`    // Last login timestamp
	Active         bool      `json:"active"`         // Account status (can be disabled by admin)
	CustomDomain   string    `json:"customDomain"`   // Optional custom domain for this user
}

// UserResponse represents user data for API responses (excludes sensitive fields)
type UserResponse struct {
	ID             string    `json:"id"`
	Email          string    `json:"email"`
	SecurityPhrase string    `json:"securityPhrase"` // User's security phrase (safe to expose)
	Verified       bool      `json:"verified"`
	CreatedAt      time.Time `json:"createdAt"`
	LastLoginAt    time.Time `json:"lastLoginAt"`
	Active         bool      `json:"active"`
	CustomDomain   string    `json:"customDomain"`
}

// ToResponse converts User to UserResponse (removes sensitive data)
func (u *User) ToResponse() UserResponse {
	return UserResponse{
		ID:             u.ID,
		Email:          u.Email,
		SecurityPhrase: u.SecurityPhrase,
		Verified:       u.Verified,
		CreatedAt:      u.CreatedAt,
		LastLoginAt:    u.LastLoginAt,
		Active:         u.Active,
		CustomDomain:   u.CustomDomain,
	}
}

// GetEmail returns the user's email (for email service)
func (u *User) GetEmail() string {
	return u.Email
}

// GetSecurityPhrase returns the user's security phrase (for email service)
func (u *User) GetSecurityPhrase() string {
	return u.SecurityPhrase
}

// RegisterRequest represents user registration data
type RegisterRequest struct {
	Email    string `json:"email" example:"user@example.com"`
	Password string `json:"password" example:"SecurePassword123"`
}

// VerifyOTPRequest represents OTP verification data
type VerifyOTPRequest struct {
	Email string `json:"email" example:"user@example.com"`
	OTP   string `json:"otp" example:"123456"`
}

// LoginRequest represents login credentials
type LoginRequest struct {
	Email    string `json:"email" example:"user@example.com"`
	Password string `json:"password" example:"SecurePassword123"`
}

// LoginResponse represents successful login response
type LoginResponse struct {
	AccessToken  string       `json:"accessToken"`
	RefreshToken string       `json:"refreshToken"`
	User         UserResponse `json:"user"`
}

// RefreshTokenRequest represents token refresh request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// OTP represents a one-time password for email verification
type OTP struct {
	Email     string    `json:"email"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expiresAt"`
	Attempts  int       `json:"attempts"` // Track failed attempts
}
