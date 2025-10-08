package handler

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/log"
)

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Error       string   `json:"error"`
	Message     string   `json:"message,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"` // Alternative slug suggestions (for conflicts)
}

// SuccessResponse represents a successful URL shortening response
type SuccessResponse struct {
	OriginalURL  string `json:"originalURL"`
	ShortURL     string `json:"shortURL"`
	ManagementID string `json:"managementID,omitempty"` // UUID for update/delete operations
	Slug         string `json:"slug,omitempty"`         // The slug part of the short URL
	IsCustomSlug bool   `json:"isCustomSlug,omitempty"` // Whether this was a user-provided custom slug
	QRCodeURL    string `json:"qrCodeURL,omitempty"`    // URL to generate QR code for this short URL
}

// SendJSONError sends a JSON error response
func SendJSONError(w http.ResponseWriter, statusCode int, err error, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := ErrorResponse{
		Error:   err.Error(),
		Message: message,
	}

	if encodeErr := json.NewEncoder(w).Encode(response); encodeErr != nil {
		log.Error().Err(encodeErr).Msg("Failed to encode error response")
	}
}

// SendJSONErrorWithSuggestions sends a JSON error response with alternative suggestions
func SendJSONErrorWithSuggestions(w http.ResponseWriter, statusCode int, err error, message string, suggestions []string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := ErrorResponse{
		Error:       err.Error(),
		Message:     message,
		Suggestions: suggestions,
	}

	if encodeErr := json.NewEncoder(w).Encode(response); encodeErr != nil {
		log.Error().Err(encodeErr).Msg("Failed to encode error response")
	}
}

// SendJSONSuccess sends a JSON success response
func SendJSONSuccess(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Error().Err(err).Msg("Failed to encode success response")
	}
}
