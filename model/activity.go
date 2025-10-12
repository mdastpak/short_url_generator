package model

import "time"

// ActivityLog represents a user action log entry
type ActivityLog struct {
	Timestamp time.Time              `json:"timestamp"` // When the action occurred
	Action    string                 `json:"action"`    // Type of action (see ActivityType constants)
	Details   map[string]interface{} `json:"details"`   // Additional action-specific details
	IP        string                 `json:"ip"`        // IP address of the user
	UserAgent string                 `json:"userAgent"` // Browser/device user agent
	Location  string                 `json:"location"`  // Optional: City, Country (from GeoIP)
}

// ActivityType constants for common user actions
const (
	ActivityUserLogin         = "user_login"          // Successful login
	ActivityUserLogout        = "user_logout"         // User logout
	ActivityPasswordChanged   = "password_changed"    // Password updated
	ActivitySecurityPhraseSet = "security_phrase_set" // Security phrase created/updated
	ActivityURLCreated        = "url_created"         // New short URL created
	ActivityURLUpdated        = "url_updated"         // URL modified
	ActivityURLDeleted        = "url_deleted"         // URL deleted
	ActivityLoginFailed       = "login_failed"        // Failed login attempt (security)
)

// ActivityListResponse represents paginated activity log response
type ActivityListResponse struct {
	Page       int           `json:"page"`       // Current page number
	Limit      int           `json:"limit"`      // Entries per page
	Total      int           `json:"total"`      // Total number of entries
	Activities []ActivityLog `json:"activities"` // Activity log entries
}
