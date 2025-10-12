package utils

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"short-url-generator/config"
)

// ValidatePassword validates a password against the provided rules
func ValidatePassword(password string, rules config.PasswordRulesConfig) error {
	// Check length
	if len(password) < rules.MinLength {
		return fmt.Errorf("password must be at least %d characters long", rules.MinLength)
	}
	if len(password) > rules.MaxLength {
		return fmt.Errorf("password must not exceed %d characters", rules.MaxLength)
	}

	// Check uppercase requirement
	if rules.RequireUppercase && !containsUppercase(password) {
		return errors.New("password must contain at least one uppercase letter")
	}

	// Check lowercase requirement
	if rules.RequireLowercase && !containsLowercase(password) {
		return errors.New("password must contain at least one lowercase letter")
	}

	// Check digit requirement
	if rules.RequireDigit && !containsDigit(password) {
		return errors.New("password must contain at least one digit")
	}

	// Check special character requirement
	if rules.RequireSpecial && !containsSpecial(password) {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

// ValidateUserPassword validates a user account password
func ValidateUserPassword(password string, cfg config.Config) error {
	return ValidatePassword(password, cfg.Password.User)
}

// ValidateURLPassword validates a URL protection password
func ValidateURLPassword(password string, cfg config.Config) error {
	return ValidatePassword(password, cfg.Password.URL)
}

// GetPasswordRequirements returns a human-readable string of password requirements
func GetPasswordRequirements(rules config.PasswordRulesConfig) string {
	var requirements []string

	requirements = append(requirements, fmt.Sprintf("%d-%d characters", rules.MinLength, rules.MaxLength))

	if rules.RequireUppercase {
		requirements = append(requirements, "at least one uppercase letter")
	}
	if rules.RequireLowercase {
		requirements = append(requirements, "at least one lowercase letter")
	}
	if rules.RequireDigit {
		requirements = append(requirements, "at least one digit")
	}
	if rules.RequireSpecial {
		requirements = append(requirements, "at least one special character")
	}

	return strings.Join(requirements, ", ")
}

// Helper functions
func containsUppercase(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func containsLowercase(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

func containsDigit(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func containsSpecial(s string) bool {
	for _, r := range s {
		if unicode.IsPunct(r) || unicode.IsSymbol(r) {
			return true
		}
	}
	return false
}
