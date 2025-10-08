package model

import "time"

// CreateRequest represents the request body for creating a short URL
// @Description Request body for creating a new short URL. Expiry time must be in RFC3339 format with timezone (e.g., 2024-12-31T23:59:59+03:30 for Iran time, or use Z for UTC)
type CreateRequest struct {
	OriginalURL string    `json:"originalURL" example:"https://example.com" binding:"required"`
	Expiry      time.Time `json:"expiry,omitempty" example:"2024-12-31T23:59:59+03:30"`
	MaxUsage    int       `json:"maxUsage,omitempty" example:"100"`
	CustomSlug  string    `json:"customSlug,omitempty" example:"my-link"`
}

// CreateResponse represents the response after creating a short URL
// @Description Response after successfully creating a short URL
type CreateResponse struct {
	ManagementID string    `json:"managementID" example:"550e8400-e29b-41d4-a716-446655440000"`
	OriginalURL  string    `json:"originalURL" example:"https://example.com"`
	ShortURL     string    `json:"shortURL" example:"abc123xy"`
	FullURL      string    `json:"fullURL" example:"http://localhost:8080/abc123xy"`
	CreatedAt    time.Time `json:"createdAt" example:"2024-01-15T10:30:00+03:30"`
	Expiry       time.Time `json:"expiry,omitempty" example:"2024-12-31T23:59:59+03:30"`
	MaxUsage     int       `json:"maxUsage,omitempty" example:"100"`
	QRCodeURL    string    `json:"qrCodeURL" example:"http://localhost:8080/qr/abc123xy"`
}

// UpdateRequest represents the request body for updating a URL
// @Description Request body for updating the destination of a short URL
type UpdateRequest struct {
	OriginalURL    string `json:"originalURL" example:"https://example.com" binding:"required"`
	ShortURL       string `json:"shortURL" example:"abc123xy" binding:"required"`
	NewOriginalURL string `json:"newOriginalURL" example:"https://newexample.com" binding:"required"`
}

// UpdateResponse represents the response after updating a URL
// @Description Response after successfully updating a short URL
type UpdateResponse struct {
	Message        string    `json:"message" example:"URL updated successfully"`
	ManagementID   string    `json:"managementID" example:"550e8400-e29b-41d4-a716-446655440000"`
	ShortURL       string    `json:"shortURL" example:"abc123xy"`
	OldOriginalURL string    `json:"oldOriginalURL" example:"https://example.com"`
	NewOriginalURL string    `json:"newOriginalURL" example:"https://newexample.com"`
	UpdatedAt      time.Time `json:"updatedAt" example:"2024-01-15T11:00:00+03:30"`
}

// DeleteRequest represents the request body for deleting a URL
// @Description Request body for deleting a short URL
type DeleteRequest struct {
	OriginalURL string `json:"originalURL" example:"https://example.com" binding:"required"`
	ShortURL    string `json:"shortURL" example:"abc123xy" binding:"required"`
}

// HealthResponse represents the health check response
// @Description Health check response showing service status
type HealthResponse struct {
	Status string `json:"status" example:"ok"`
	Redis  string `json:"redis" example:"connected"`
}

// CacheMetricsResponse represents cache performance metrics
// @Description Cache performance metrics including hit rate and evictions
type CacheMetricsResponse struct {
	Enabled   bool    `json:"enabled" example:"true"`
	Hits      uint64  `json:"hits" example:"1234"`
	Misses    uint64  `json:"misses" example:"56"`
	HitRatio  float64 `json:"hitRatio" example:"0.957"`
	Evictions uint64  `json:"evictions" example:"12"`
	KeysAdded uint64  `json:"keysAdded" example:"1290"`
}

// ErrorResponse represents an error response
// @Description Standard error response
type ErrorResponse struct {
	Error string `json:"error" example:"Invalid URL format"`
}

// SuccessResponse represents a generic success response
// @Description Generic success message response
type SuccessResponse struct {
	Message string `json:"message" example:"Operation completed successfully"`
}

// SlugSuggestion represents a custom slug suggestion
// @Description Suggested alternative slug when requested slug is taken
type SlugSuggestion struct {
	Slug      string `json:"slug" example:"my-link-2"`
	Available bool   `json:"available" example:"true"`
}

// SlugConflictResponse represents response when custom slug is taken
// @Description Response when requested custom slug is already in use
type SlugConflictResponse struct {
	Error       string           `json:"error" example:"Custom slug already exists"`
	Suggestions []SlugSuggestion `json:"suggestions"`
}
