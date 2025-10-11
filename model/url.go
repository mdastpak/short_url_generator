package model

import "time"

type URL struct {
	ManagementID   string    `json:"managementID"`   // UUID v4 for update/delete operations
	OriginalURL    string    `json:"originalURL"`
	ShortURL       string    `json:"shortURL"`
	CreatedAt      time.Time `json:"createdAt"`
	Expiry         time.Time `json:"expiry"`
	MaxUsage       int       `json:"maxUsage"`
	CurrentUsage   int       `json:"currentUsage"`
	UserID         string    `json:"userID"`         // Owner user ID (empty for anonymous URLs)
	CustomDomain   string    `json:"customDomain"`   // Optional custom domain (e.g., "go.company.com")
	PasswordHash   string    `json:"passwordHash"`   // Bcrypt hash for password-protected URLs (empty if not protected)
	ScheduledStart time.Time `json:"scheduledStart"` // URL becomes active at this time (zero value = active immediately)
	ScheduledEnd   time.Time `json:"scheduledEnd"`   // URL becomes inactive at this time (zero value = no end)
	Aliases        []string  `json:"aliases"`        // Additional short codes pointing to same URL
	Active         bool      `json:"active"`         // Manual activation status (for scheduled URLs)
}

type URLLog struct {
	ShortURL   string
	AccessedAt time.Time
	IP         string
	UserAgent  string
	Referer    string
}
