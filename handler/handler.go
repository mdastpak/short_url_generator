package handler

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"short-url-generator/cache"
	"short-url-generator/config"
	"short-url-generator/model"
	"short-url-generator/security"
	"short-url-generator/utils"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

const (
	shortURLMinLength   = 8
	shortURLMaxLength   = 10
	maxRetries          = 5
	charset             = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
	urlIndexKey         = "url_index"        // Redis hash key for URL deduplication index
	managementIndexKey  = "management_index" // Redis hash key for managementID lookup
)

var (
	ErrMaxRetriesExceeded = errors.New("failed to generate unique short URL after maximum retries")
)

// URLHandler handles URL shortening operations
type URLHandler struct {
	redis      *redis.Client
	cache      *cache.Cache
	config     config.Config
	baseURL    string
	urlScanner *security.URLScanner
}

// NewURLHandler creates a new URL handler
func NewURLHandler(redisClient *redis.Client, cacheClient *cache.Cache, cfg config.Config, scanner *security.URLScanner) *URLHandler {
	// Use configured base_url if provided, otherwise construct from scheme, IP, and port
	baseURL := cfg.WebServer.BaseURL
	if baseURL == "" {
		baseURL = fmt.Sprintf("%s://%s:%s", cfg.WebServer.Scheme, cfg.WebServer.IP, cfg.WebServer.Port)
	}
	return &URLHandler{
		redis:      redisClient,
		cache:      cacheClient,
		urlScanner: scanner,
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
// Returns the existing URL data if found and compatible, nil otherwise
func (h *URLHandler) findExistingShortURL(ctx context.Context, originalURL string, requestedExpiry time.Time, requestedMaxUsage int) (*model.URL, error) {
	// Generate hash of the original URL
	urlHash := utils.HashURL(originalURL)

	// Check if this URL hash exists in our index
	shortURL, err := h.redis.HGet(ctx, urlIndexKey, urlHash).Result()
	if err == redis.Nil {
		// No existing short URL found
		return nil, nil
	} else if err != nil {
		// Redis error
		return nil, err
	}

	// Found an existing short URL, now check if it's still valid and compatible
	urlData, err := h.redis.Get(ctx, shortURL).Bytes()
	if err == redis.Nil {
		// Short URL no longer exists (expired/deleted), remove from index
		h.redis.HDel(ctx, urlIndexKey, urlHash)
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	// Unmarshal existing URL data
	var existingURL model.URL
	if err := json.Unmarshal(urlData, &existingURL); err != nil {
		return nil, err
	}

	// Check compatibility: expiry and maxUsage must match (or be unset)
	expiryMatches := (requestedExpiry.IsZero() && existingURL.Expiry.IsZero()) ||
		(!requestedExpiry.IsZero() && !existingURL.Expiry.IsZero() && requestedExpiry.Equal(existingURL.Expiry))

	maxUsageMatches := requestedMaxUsage == existingURL.MaxUsage

	if expiryMatches && maxUsageMatches {
		// Compatible! Return existing URL data
		log.Info().
			Str("original_url", originalURL).
			Str("short_url", shortURL).
			Msg("Returning existing short URL (deduplication)")
		return &existingURL, nil
	}

	// Incompatible settings, need to create a new short URL
	log.Debug().
		Str("original_url", originalURL).
		Bool("expiry_matches", expiryMatches).
		Bool("max_usage_matches", maxUsageMatches).
		Msg("Existing short URL found but incompatible, creating new one")

	return nil, nil
}

// CreateShortURL handles POST /shorten
// @Summary Create a short URL
// @Description Shortens a URL with optional expiry time, usage limits, and custom slug. Expiry must be in RFC3339 format with timezone (e.g., 2024-12-31T23:59:59+03:30 for Iran time, or Z for UTC). Supports URL deduplication.
// @Tags URLs
// @Accept json
// @Produce json
// @Param request body model.CreateRequest true "URL shortening request"
// @Success 201 {object} model.CreateResponse "Successfully created short URL"
// @Success 200 {object} model.CreateResponse "Returned existing short URL (deduplication)"
// @Failure 400 {object} model.ErrorResponse "Invalid request (bad URL, invalid expiry, etc.)"
// @Failure 409 {object} model.SlugConflictResponse "Custom slug already taken (includes suggestions)"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /shorten [post]
func (h *URLHandler) CreateShortURL(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.Redis.OperationTimeout)*time.Second)
	defer cancel()

	// Parse JSON request
	var input struct {
		OriginalURL string `json:"originalURL"`
		CustomSlug  string `json:"customSlug"` // Optional custom slug
		Expiry      string `json:"expiry"`
		MaxUsage    int    `json:"maxUsage"`
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

	// Scan URL for malware/phishing if scanner is available
	if h.urlScanner != nil && h.config.Security.URLScanningEnabled {
		scanResult, err := h.urlScanner.ScanURL(ctx, input.OriginalURL)
		if err != nil {
			log.Error().Err(err).Str("url", input.OriginalURL).Msg("URL scanning failed")
			// Don't fail the request if scanning fails, just log it
		} else if !scanResult.Safe {
			log.Warn().
				Str("url", input.OriginalURL).
				Interface("threats", scanResult.Threats).
				Str("source", scanResult.Source).
				Msg("Malicious URL detected")

			SendJSONError(w, http.StatusForbidden,
				errors.New("URL flagged as potentially malicious"),
				fmt.Sprintf("This URL has been flagged for: %v. Source: %s", scanResult.Threats, scanResult.Source))
			return
		}
	}

	// Validate custom slug if provided and feature is enabled
	var isCustomSlug bool
	if input.CustomSlug != "" {
		if !h.config.Features.CustomSlugsEnabled {
			SendJSONError(w, http.StatusBadRequest, errors.New("custom slugs are disabled"), "Custom slugs feature is not enabled")
			return
		}

		// Validate slug format
		if err := utils.ValidateSlug(input.CustomSlug, h.config.Features.MinSlugLength, h.config.Features.MaxSlugLength); err != nil {
			log.Warn().Err(err).Str("slug", input.CustomSlug).Msg("Invalid custom slug")
			SendJSONError(w, http.StatusBadRequest, err, "")
			return
		}

		// Check if slug is already taken (case-insensitive)
		slugLower := strings.ToLower(input.CustomSlug)
		exists, err := h.redis.Exists(ctx, slugLower).Result()
		if err != nil {
			log.Error().Err(err).Msg("Failed to check slug availability")
			SendJSONError(w, http.StatusInternalServerError, err, "Failed to check slug availability")
			return
		}
		if exists > 0 {
			// Generate alternative slug suggestions
			suggestions := utils.GenerateSlugSuggestions(ctx, h.redis, input.CustomSlug, h.config.Features.SlugSuggestionsCount)
			SendJSONErrorWithSuggestions(w, http.StatusConflict, errors.New("custom slug already taken"),
				fmt.Sprintf("The slug '%s' is already in use. Try a different slug or leave blank for auto-generation.", input.CustomSlug),
				suggestions)
			return
		}

		isCustomSlug = true
	}

	// Build URL model
	url := model.URL{
		ManagementID: uuid.New().String(), // Generate UUID v4 for management operations
		OriginalURL:  input.OriginalURL,
		CreatedAt:    time.Now(),
	}

	// Parse expiry if provided
	if input.Expiry != "" {
		expiry, err := time.Parse(time.RFC3339, input.Expiry)
		if err != nil {
			log.Error().Err(err).Str("expiry", input.Expiry).Msg("Invalid expiry format")
			SendJSONError(w, http.StatusBadRequest, err, "Invalid expiry time format (use RFC3339)")
			return
		}
		// Validate expiry is in the future
		if expiry.Before(time.Now()) {
			log.Warn().Time("expiry", expiry).Msg("Expiry date is in the past")
			SendJSONError(w, http.StatusBadRequest, errors.New("expiry date must be in the future"), "Use RFC3339 format with timezone (e.g., 2024-12-31T23:59:59+03:30 for Iran time, or Z for UTC)")
			return
		}
		url.Expiry = expiry
	}

	// Parse max usage if provided
	if input.MaxUsage > 0 {
		url.MaxUsage = input.MaxUsage
	}

	// Determine short URL
	var shortURL string
	if isCustomSlug {
		// Use custom slug (store as lowercase for case-insensitive lookups)
		shortURL = strings.ToLower(input.CustomSlug)
		log.Info().
			Str("custom_slug", input.CustomSlug).
			Str("short_url", shortURL).
			Msg("Using custom slug")
	} else {
		// Check for duplicate URL if deduplication is enabled
		if h.config.Features.DeduplicationEnabled {
			existingURL, err := h.findExistingShortURL(ctx, input.OriginalURL, url.Expiry, url.MaxUsage)
			if err != nil {
				log.Error().Err(err).Msg("Error checking for duplicate URL")
				// Don't fail the request, just log and continue to create new
			} else if existingURL != nil {
				// Found compatible existing short URL
				fullShortURL := fmt.Sprintf("%s/%s", h.baseURL, existingURL.ShortURL)
				qrCodeURL := fmt.Sprintf("%s/qr/%s", h.baseURL, existingURL.ShortURL)
				previewURL := fmt.Sprintf("%s/preview/%s", h.baseURL, existingURL.ShortURL)

				log.Info().
					Str("short_url", fullShortURL).
					Str("original_url", existingURL.OriginalURL).
					Msg("Returning existing short URL (duplicate)")

				SendJSONSuccess(w, http.StatusOK, SuccessResponse{
					OriginalURL:  existingURL.OriginalURL,
					ShortURL:     fullShortURL,
					ManagementID: existingURL.ManagementID,
					Slug:         existingURL.ShortURL,
					QRCodeURL:    qrCodeURL,
					PreviewURL:   previewURL,
				})
				return
			}
		}

		// Generate unique short URL with collision detection
		var err error
		shortURL, err = h.generateUniqueShortURL(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Failed to generate unique short URL")
			SendJSONError(w, http.StatusInternalServerError, err, "Failed to generate short URL")
			return
		}
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

	// Add to management index for update/delete operations
	if err := h.redis.HSet(ctx, managementIndexKey, url.ManagementID, shortURL).Err(); err != nil {
		log.Error().Err(err).Msg("Failed to add URL to management index")
		// Don't fail the request, URL is already stored
	}

	fullShortURL := fmt.Sprintf("%s/%s", h.baseURL, shortURL)
	qrCodeURL := fmt.Sprintf("%s/qr/%s", h.baseURL, shortURL)
	previewURL := fmt.Sprintf("%s/preview/%s", h.baseURL, shortURL)
	log.Info().
		Str("short_url", fullShortURL).
		Str("original_url", url.OriginalURL).
		Str("management_id", url.ManagementID).
		Bool("is_custom_slug", isCustomSlug).
		Msg("Short URL created")

	SendJSONSuccess(w, http.StatusCreated, SuccessResponse{
		OriginalURL:  url.OriginalURL,
		ShortURL:     fullShortURL,
		ManagementID: url.ManagementID,
		Slug:         shortURL,
		IsCustomSlug: isCustomSlug,
		QRCodeURL:    qrCodeURL,
		PreviewURL:   previewURL,
	})
}

// RedirectURL handles GET /{shortURL}
// @Summary Redirect to original URL
// @Description Redirects to the original URL associated with the short URL. Increments usage counter and logs access. Add ?preview=1 to show preview page instead.
// @Tags URLs
// @Produce json
// @Param shortURL path string true "Short URL code" example("abc123xy")
// @Param preview query int false "Show preview page (1=yes, 0=no)" default(0)
// @Success 301 "Redirect to original URL"
// @Success 302 "Redirect to preview page (if preview=1)"
// @Failure 404 {object} model.ErrorResponse "Short URL not found"
// @Failure 410 {object} model.ErrorResponse "URL has expired"
// @Failure 403 {object} model.ErrorResponse "Usage limit exceeded"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /{shortURL} [get]
func (h *URLHandler) RedirectURL(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.Redis.OperationTimeout)*time.Second)
	defer cancel()

	vars := mux.Vars(r)
	shortURL := vars["shortURL"]

	// Check if preview mode is requested
	if r.URL.Query().Get("preview") == "1" {
		http.Redirect(w, r, "/preview/"+shortURL, http.StatusFound)
		return
	}

	var url model.URL
	cacheHit := false

	// Try cache first if enabled
	if h.config.Cache.Enabled && h.cache != nil {
		if cachedData, found := h.cache.Get(shortURL); found {
			if cachedURL, ok := cachedData.(model.URL); ok {
				url = cachedURL
				cacheHit = true
				log.Debug().Str("short_url", shortURL).Msg("Cache hit")
			}
		}
	}

	// On cache miss, fetch from Redis
	if !cacheHit {
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
		if err := json.Unmarshal(urlData, &url); err != nil {
			log.Error().Err(err).Msg("Failed to unmarshal URL data")
			SendJSONError(w, http.StatusInternalServerError, err, "Internal server error")
			return
		}

		// Populate cache for future requests (if enabled)
		if h.config.Cache.Enabled && h.cache != nil {
			// Cost = approximate size of URL struct (estimate 1KB per entry)
			h.cache.Set(shortURL, url, 1024)
			log.Debug().Str("short_url", shortURL).Msg("Cached URL data")
		}
	}

	// Check expiry
	if !url.Expiry.IsZero() && time.Now().After(url.Expiry) {
		log.Info().
			Str("short_url", shortURL).
			Time("expiry", url.Expiry).
			Time("now", time.Now()).
			Msg("URL expired")

		// Invalidate cache
		if h.config.Cache.Enabled && h.cache != nil {
			h.cache.Delete(shortURL)
		}

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

		// Invalidate cache
		if h.config.Cache.Enabled && h.cache != nil {
			h.cache.Delete(shortURL)
		}

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
	urlData, err := json.Marshal(url)
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

	// Update cache with incremented usage count
	if h.config.Cache.Enabled && h.cache != nil {
		h.cache.Set(shortURL, url, 1024)
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
// @Summary Health check
// @Description Returns service health status and Redis connectivity
// @Tags System
// @Produce json
// @Success 200 {object} model.HealthResponse "Service is healthy"
// @Failure 503 {object} model.HealthResponse "Service is unhealthy"
// @Router /health [get]
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

// CacheMetrics handles GET /cache/metrics
// @Summary Cache performance metrics
// @Description Returns cache performance metrics including hit rate, misses, and evictions
// @Tags System
// @Produce json
// @Success 200 {object} model.CacheMetricsResponse "Cache metrics"
// @Failure 503 {object} model.ErrorResponse "Cache is disabled"
// @Router /cache/metrics [get]
func (h *URLHandler) CacheMetrics(w http.ResponseWriter, r *http.Request) {
	if !h.config.Cache.Enabled || h.cache == nil {
		SendJSONError(w, http.StatusServiceUnavailable, errors.New("cache is disabled"), "")
		return
	}

	metrics := h.cache.GetMetricsSnapshot()
	SendJSONSuccess(w, http.StatusOK, metrics)
}
