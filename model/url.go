package model

import "time"

type URL struct {
	ManagementID string    // UUID v4 for update/delete operations
	OriginalURL  string
	ShortURL     string
	CreatedAt    time.Time
	Expiry       time.Time
	MaxUsage     int
	CurrentUsage int
}

type URLLog struct {
	ShortURL   string
	AccessedAt time.Time
	IP         string
	UserAgent  string
	Referer    string
}
