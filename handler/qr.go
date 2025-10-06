package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"github.com/skip2/go-qrcode"
)

// GenerateQR handles GET /{shortURL}/qr - generates QR code for short URL
func (h *URLHandler) GenerateQR(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.Redis.OperationTimeout)*time.Second)
	defer cancel()

	vars := mux.Vars(r)
	shortURL := vars["shortURL"]

	// Verify shortURL exists in Redis
	exists, err := h.redis.Exists(ctx, shortURL).Result()
	if err != nil {
		log.Error().Err(err).Str("short_url", shortURL).Msg("Failed to check URL existence for QR")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to verify URL")
		return
	}

	if exists == 0 {
		log.Warn().Str("short_url", shortURL).Msg("URL not found for QR generation")
		SendJSONError(w, http.StatusNotFound, errors.New("URL not found"), "Short URL does not exist")
		return
	}

	// Parse query parameters
	query := r.URL.Query()

	// Get size parameter (default: 256, min: 128, max: 1024)
	size := 256
	if sizeStr := query.Get("size"); sizeStr != "" {
		parsedSize, err := strconv.Atoi(sizeStr)
		if err != nil {
			SendJSONError(w, http.StatusBadRequest, errors.New("invalid size parameter"), "Size must be a number")
			return
		}
		if parsedSize < 128 || parsedSize > 1024 {
			SendJSONError(w, http.StatusBadRequest, errors.New("size out of range"), "Size must be between 128 and 1024")
			return
		}
		size = parsedSize
	}

	// Get error correction level (default: medium)
	level := qrcode.Medium
	if levelStr := query.Get("level"); levelStr != "" {
		switch levelStr {
		case "low":
			level = qrcode.Low
		case "medium":
			level = qrcode.Medium
		case "high":
			level = qrcode.High
		case "highest":
			level = qrcode.Highest
		default:
			SendJSONError(w, http.StatusBadRequest, errors.New("invalid level parameter"), "Level must be: low, medium, high, or highest")
			return
		}
	}

	// Construct full URL for QR code
	fullURL := fmt.Sprintf("%s/%s", h.baseURL, shortURL)

	// Generate QR code
	qrCode, err := qrcode.Encode(fullURL, level, size)
	if err != nil {
		log.Error().Err(err).Str("url", fullURL).Msg("Failed to generate QR code")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to generate QR code")
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
	w.Header().Set("Content-Length", strconv.Itoa(len(qrCode)))

	// Write QR code image
	if _, err := w.Write(qrCode); err != nil {
		log.Error().Err(err).Msg("Failed to write QR code response")
		return
	}

	log.Info().
		Str("short_url", shortURL).
		Str("full_url", fullURL).
		Int("size", size).
		Str("level", levelStr(level)).
		Msg("QR code generated successfully")
}

// levelStr converts qrcode.RecoveryLevel to string for logging
func levelStr(level qrcode.RecoveryLevel) string {
	switch level {
	case qrcode.Low:
		return "low"
	case qrcode.Medium:
		return "medium"
	case qrcode.High:
		return "high"
	case qrcode.Highest:
		return "highest"
	default:
		return "unknown"
	}
}
