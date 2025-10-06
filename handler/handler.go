package handler

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"short-url-generator/config"
	"short-url-generator/model"
	"short-url-generator/utils"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

const (
	shortURLMinLength = 8
	shortURLMaxLength = 10
	maxRetries        = 5
	charset           = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
	urlIndexKey       = "url_index" // Redis hash key for URL deduplication index
)

var (
	ErrMaxRetriesExceeded = errors.New("failed to generate unique short URL after maximum retries")
)

// URLHandler handles URL shortening operations
type URLHandler struct {
	redis   *redis.Client
	config  config.Config
	baseURL string
}

// NewURLHandler creates a new URL handler
func NewURLHandler(redisClient *redis.Client, cfg config.Config) *URLHandler {
	baseURL := fmt.Sprintf("%s://%s:%s", cfg.WebServer.Scheme, cfg.WebServer.IP, cfg.WebServer.Port)
	return &URLHandler{
		redis:   redisClient,
		config:  cfg,
		baseURL: baseURL,
	}
}

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) (string, error) {
	result := make([]byte, length)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[num.Int64()]
	}
	return string(result), nil
}

// generateUniqueShortURL generates a unique short URL with collision detection
func (h *URLHandler) generateUniqueShortURL(ctx context.Context) (string, error) {
	for attempt := 0; attempt < maxRetries; attempt++ {
		// Generate random length between min and max
		lengthRange := shortURLMaxLength - shortURLMinLength + 1
		randomOffset, err := rand.Int(rand.Reader, big.NewInt(int64(lengthRange)))
		if err != nil {
			return "", err
		}
		length := shortURLMinLength + int(randomOffset.Int64())

		shortURL, err := generateRandomString(length)
		if err != nil {
			return "", err
		}

		// Check if it already exists
		exists, err := h.redis.Exists(ctx, shortURL).Result()
		if err != nil {
			return "", err
		}

		if exists == 0 {
			return shortURL, nil
		}

		log.Warn().
			Str("short_url", shortURL).
			Int("attempt", attempt+1).
			Msg("Collision detected, retrying")
	}

	return "", ErrMaxRetriesExceeded
}

// findExistingShortURL checks if the original URL already has a short URL
// Returns the existing short URL if found and compatible, empty string otherwise
func (h *URLHandler) findExistingShortURL(ctx context.Context, originalURL string, requestedExpiry time.Time, requestedMaxUsage int) (string, error) {
	// Generate hash of the original URL
	urlHash := utils.HashURL(originalURL)

	// Check if this URL hash exists in our index
	shortURL, err := h.redis.HGet(ctx, urlIndexKey, urlHash).Result()
	if err == redis.Nil {
		// No existing short URL found
		return "", nil
	} else if err != nil {
		// Redis error
		return "", err
	}

	// Found an existing short URL, now check if it's still valid and compatible
	urlData, err := h.redis.Get(ctx, shortURL).Bytes()
	if err == redis.Nil {
		// Short URL no longer exists (expired/deleted), remove from index
		h.redis.HDel(ctx, urlIndexKey, urlHash)
		return "", nil
	} else if err != nil {
		return "", err
	}

	// Unmarshal existing URL data
	var existingURL model.URL
	if err := json.Unmarshal(urlData, &existingURL); err != nil {
		return "", err
	}

	// Check compatibility: expiry and maxUsage must match (or be unset)
	expiryMatches := (requestedExpiry.IsZero() && existingURL.Expiry.IsZero()) ||
		(!requestedExpiry.IsZero() && !existingURL.Expiry.IsZero() && requestedExpiry.Equal(existingURL.Expiry))

	maxUsageMatches := requestedMaxUsage == existingURL.MaxUsage

	if expiryMatches && maxUsageMatches {
		// Compatible! Return existing short URL
		log.Info().
			Str("original_url", originalURL).
			Str("short_url", shortURL).
			Msg("Returning existing short URL (deduplication)")
		return shortURL, nil
	}

	// Incompatible settings, need to create a new short URL
	log.Debug().
		Str("original_url", originalURL).
		Bool("expiry_matches", expiryMatches).
		Bool("max_usage_matches", maxUsageMatches).
		Msg("Existing short URL found but incompatible, creating new one")

	return "", nil
}

// CreateShortURL handles POST /shorten
func (h *URLHandler) CreateShortURL(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.Redis.OperationTimeout)*time.Second)
	defer cancel()

	// Parse JSON request
	var input struct {
		OriginalURL string `json:"originalURL"`
		Expiry      string `json:"expiry"`
		MaxUsage    string `json:"maxUsage"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		log.Error().Err(err).Msg("Failed to decode request body")
		SendJSONError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Validate URL
	if err := utils.ValidateURL(input.OriginalURL); err != nil {
		log.Warn().Err(err).Str("url", input.OriginalURL).Msg("Invalid URL")
		SendJSONError(w, http.StatusBadRequest, err, "")
		return
	}

	// Build URL model
	url := model.URL{
		OriginalURL: input.OriginalURL,
		CreatedAt:   time.Now(),
	}

	// Parse expiry if provided
	if input.Expiry != "" {
		expiry, err := time.Parse(time.RFC3339, input.Expiry)
		if err != nil {
			log.Error().Err(err).Str("expiry", input.Expiry).Msg("Invalid expiry format")
			SendJSONError(w, http.StatusBadRequest, err, "Invalid expiry time format (use RFC3339)")
			return
		}
		url.Expiry = expiry
	}

	// Parse max usage if provided
	if input.MaxUsage != "" {
		maxUsage, err := strconv.Atoi(input.MaxUsage)
		if err != nil {
			log.Error().Err(err).Str("max_usage", input.MaxUsage).Msg("Invalid max usage")
			SendJSONError(w, http.StatusBadRequest, err, "Invalid max usage (must be a number)")
			return
		}
		url.MaxUsage = maxUsage
	}

	// Check for duplicate URL if deduplication is enabled
	var shortURL string
	if h.config.Features.DeduplicationEnabled {
		existingShortURL, err := h.findExistingShortURL(ctx, input.OriginalURL, url.Expiry, url.MaxUsage)
		if err != nil {
			log.Error().Err(err).Msg("Error checking for duplicate URL")
			// Don't fail the request, just log and continue to create new
		} else if existingShortURL != "" {
			// Found compatible existing short URL
			fullShortURL := fmt.Sprintf("%s/%s", h.baseURL, existingShortURL)
			log.Info().
				Str("short_url", fullShortURL).
				Str("original_url", url.OriginalURL).
				Msg("Returning existing short URL (duplicate)")

			SendJSONSuccess(w, http.StatusOK, SuccessResponse{
				OriginalURL: url.OriginalURL,
				ShortURL:    fullShortURL,
			})
			return
		}
	}

	// Generate unique short URL with collision detection
	shortURL, err := h.generateUniqueShortURL(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate unique short URL")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to generate short URL")
		return
	}
	url.ShortURL = shortURL

	// Marshal URL data
	urlData, err := json.Marshal(url)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal URL data")
		SendJSONError(w, http.StatusInternalServerError, err, "Internal server error")
		return
	}

	// Store in Redis
	if err := h.redis.Set(ctx, shortURL, urlData, 0).Err(); err != nil {
		log.Error().Err(err).Str("short_url", shortURL).Msg("Failed to store URL in Redis")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to store URL")
		return
	}

	// Add to deduplication index if enabled
	if h.config.Features.DeduplicationEnabled {
		urlHash := utils.HashURL(input.OriginalURL)
		if err := h.redis.HSet(ctx, urlIndexKey, urlHash, shortURL).Err(); err != nil {
			log.Error().Err(err).Msg("Failed to add URL to deduplication index")
			// Don't fail the request, URL is already stored
		}
	}

	fullShortURL := fmt.Sprintf("%s/%s", h.baseURL, shortURL)
	log.Info().
		Str("short_url", fullShortURL).
		Str("original_url", url.OriginalURL).
		Msg("Short URL created")

	SendJSONSuccess(w, http.StatusCreated, SuccessResponse{
		OriginalURL: url.OriginalURL,
		ShortURL:    fullShortURL,
	})
}

// RedirectURL handles GET /{shortURL}
func (h *URLHandler) RedirectURL(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.Redis.OperationTimeout)*time.Second)
	defer cancel()

	vars := mux.Vars(r)
	shortURL := vars["shortURL"]

	// Fetch URL data from Redis
	urlData, err := h.redis.Get(ctx, shortURL).Bytes()
	if err == redis.Nil {
		log.Warn().Str("short_url", shortURL).Msg("URL not found")
		SendJSONError(w, http.StatusNotFound, errors.New("URL not found"), "")
		return
	} else if err != nil {
		log.Error().Err(err).Str("short_url", shortURL).Msg("Failed to retrieve URL from Redis")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to retrieve URL")
		return
	}

	// Unmarshal URL data
	var url model.URL
	if err := json.Unmarshal(urlData, &url); err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal URL data")
		SendJSONError(w, http.StatusInternalServerError, err, "Internal server error")
		return
	}

	// Check expiry
	if !url.Expiry.IsZero() && time.Now().After(url.Expiry) {
		log.Info().Str("short_url", shortURL).Msg("URL expired")

		// Move to expired list
		if err := h.redis.RPush(ctx, "expired_urls", shortURL).Err(); err != nil {
			log.Error().Err(err).Msg("Failed to add to expired list")
		}
		if err := h.redis.Del(ctx, shortURL).Err(); err != nil {
			log.Error().Err(err).Msg("Failed to delete expired URL")
		}

		// Remove from deduplication index if enabled
		if h.config.Features.DeduplicationEnabled {
			urlHash := utils.HashURL(url.OriginalURL)
			h.redis.HDel(ctx, urlIndexKey, urlHash)
		}

		SendJSONError(w, http.StatusGone, errors.New("URL has expired"), "")
		return
	}

	// Check usage limit
	if url.MaxUsage > 0 && url.CurrentUsage >= url.MaxUsage {
		log.Info().Str("short_url", shortURL).Msg("URL usage limit exceeded")

		// Move to used up list
		if err := h.redis.RPush(ctx, "usedup_urls", shortURL).Err(); err != nil {
			log.Error().Err(err).Msg("Failed to add to used up list")
		}
		if err := h.redis.Del(ctx, shortURL).Err(); err != nil {
			log.Error().Err(err).Msg("Failed to delete used up URL")
		}

		// Remove from deduplication index if enabled
		if h.config.Features.DeduplicationEnabled {
			urlHash := utils.HashURL(url.OriginalURL)
			h.redis.HDel(ctx, urlIndexKey, urlHash)
		}

		SendJSONError(w, http.StatusForbidden, errors.New("URL usage limit exceeded"), "")
		return
	}

	// Increment usage count
	url.CurrentUsage++
	urlData, err = json.Marshal(url)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal updated URL data")
		SendJSONError(w, http.StatusInternalServerError, err, "Internal server error")
		return
	}

	if err := h.redis.Set(ctx, shortURL, urlData, 0).Err(); err != nil {
		log.Error().Err(err).Msg("Failed to update usage count")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to update usage count")
		return
	}

	// Log access
	logEntry := model.URLLog{
		ShortURL:   shortURL,
		AccessedAt: time.Now(),
		IP:         r.RemoteAddr,
		UserAgent:  r.Header.Get("User-Agent"),
		Referer:    r.Header.Get("Referer"),
	}

	logData, err := json.Marshal(logEntry)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal log entry")
	} else {
		if err := h.redis.RPush(ctx, "logs:"+shortURL, logData).Err(); err != nil {
			log.Error().Err(err).Msg("Failed to log URL access")
		}
	}

	log.Info().
		Str("short_url", shortURL).
		Str("original_url", url.OriginalURL).
		Str("remote_addr", r.RemoteAddr).
		Msg("Redirecting")

	http.Redirect(w, r, url.OriginalURL, http.StatusMovedPermanently)
}

// HealthCheck handles GET /health
func (h *URLHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	// Check Redis connection
	if err := h.redis.Ping(ctx).Err(); err != nil {
		log.Error().Err(err).Msg("Redis health check failed")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "unhealthy",
			"redis":  "unavailable",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"redis":  "connected",
	})
}
