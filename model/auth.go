package model

import "time"

// ResetToken represents a password reset token
type ResetToken struct {
	Token      string    `json:"token"`      // UUID v4
	UserID     string    `json:"userID"`     // User to reset password for
	Email      string    `json:"email"`      // Email address
	RequestIP  string    `json:"requestIP"`  // IP that requested reset
	UserAgent  string    `json:"userAgent"`  // Browser/device that requested reset
	CreatedAt  time.Time `json:"createdAt"`  // Request timestamp
	ExpiresAt  time.Time `json:"expiresAt"`  // Token expiration (typically 30 minutes)
	Used       bool      `json:"used"`       // Single-use flag
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

// ChangePasswordRequest represents password change (requires current password)
type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword" example:"OldPassword123"`
	NewPassword     string `json:"newPassword" example:"NewPassword123"`
}

// SetSecurityPhraseRequest represents security phrase update
type SetSecurityPhraseRequest struct {
	SecurityPhrase string `json:"securityPhrase" example:"Purple Elephant 2025"`
}

// VerifyPasswordRequest represents password verification for protected URLs
type VerifyPasswordRequest struct {
	Password string `json:"password" example:"MySecurePassword123"`
}

// SetPasswordRequest represents setting password protection on a URL
type SetPasswordRequest struct {
	Password string `json:"password" example:"MySecurePassword123"`
}
