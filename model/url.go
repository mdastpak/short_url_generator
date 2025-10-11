package model

import "time"

type URL struct {
	ManagementID   string    // UUID v4 for update/delete operations
	OriginalURL    string
	ShortURL       string
	CreatedAt      time.Time
	Expiry         time.Time
	MaxUsage       int
	CurrentUsage   int
	UserID         string    // Owner user ID (empty for anonymous URLs)
	CustomDomain   string    // Optional custom domain (e.g., "go.company.com")
	PasswordHash   string    // Bcrypt hash for password-protected URLs (empty if not protected)
	ScheduledStart time.Time // URL becomes active at this time (zero value = active immediately)
	ScheduledEnd   time.Time // URL becomes inactive at this time (zero value = no end)
	Aliases        []string  // Additional short codes pointing to same URL
	Active         bool      // Manual activation status (for scheduled URLs)
}

type URLLog struct {
	ShortURL   string
	AccessedAt time.Time
	IP         string
	UserAgent  string
	Referer    string
}
