package handler

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"short-url-generator/model"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

//go:embed preview.html
var previewTemplateFS embed.FS

// PreviewData holds data for the preview template
type PreviewData struct {
	OriginalURL      string
	ShortURL         string
	CreatedAt        string
	Expiry           string
	UsageInfo        string
	IsSecure         bool
	AutoRedirect     bool
	CountdownSeconds int
}

// ShowPreview handles GET /preview/{shortURL}
// @Summary Show URL preview page
// @Description Displays a preview page showing the destination URL before redirecting (anti-phishing protection)
// @Tags URLs
// @Produce html
// @Param shortURL path string true "Short URL code" example("abc123xy")
// @Param autoredirect query int false "Auto-redirect countdown in seconds (0 to disable)" default(0)
// @Success 200 {string} html "Preview page HTML"
// @Failure 404 {object} model.ErrorResponse "Short URL not found"
// @Failure 410 {object} model.ErrorResponse "URL has expired"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /preview/{shortURL} [get]
func (h *URLHandler) ShowPreview(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.Redis.OperationTimeout)*time.Second)
	defer cancel()

	vars := mux.Vars(r)
	shortURL := vars["shortURL"]

	// Parse auto-redirect query parameter
	autoRedirectSeconds := 0
	if autoStr := r.URL.Query().Get("autoredirect"); autoStr != "" {
		if seconds, err := time.ParseDuration(autoStr + "s"); err == nil && seconds > 0 {
			autoRedirectSeconds = int(seconds.Seconds())
			// Limit to max 30 seconds
			if autoRedirectSeconds > 30 {
				autoRedirectSeconds = 30
			}
		}
	}

	var url model.URL
	cacheHit := false

	// Try cache first if enabled
	if h.config.Cache.Enabled && h.cache != nil {
		if cachedData, found := h.cache.Get(shortURL); found {
			if cachedURL, ok := cachedData.(model.URL); ok {
				url = cachedURL
				cacheHit = true
				log.Debug().Str("short_url", shortURL).Msg("Cache hit for preview")
			}
		}
	}

	// On cache miss, fetch from Redis
	if !cacheHit {
		urlData, err := h.redis.Get(ctx, shortURL).Bytes()
		if err == redis.Nil {
			log.Warn().Str("short_url", shortURL).Msg("URL not found for preview")
			SendJSONError(w, http.StatusNotFound, errors.New("URL not found"), "")
			return
		} else if err != nil {
			log.Error().Err(err).Str("short_url", shortURL).Msg("Failed to retrieve URL from Redis for preview")
			SendJSONError(w, http.StatusInternalServerError, err, "Failed to retrieve URL")
			return
		}

		// Unmarshal URL data
		if err := json.Unmarshal(urlData, &url); err != nil {
			log.Error().Err(err).Msg("Failed to unmarshal URL data for preview")
			SendJSONError(w, http.StatusInternalServerError, err, "Internal server error")
			return
		}

		// Populate cache for future requests (if enabled)
		if h.config.Cache.Enabled && h.cache != nil {
			h.cache.Set(shortURL, url, 1024)
			log.Debug().Str("short_url", shortURL).Msg("Cached URL data for preview")
		}
	}

	// Check expiry
	if !url.Expiry.IsZero() && time.Now().After(url.Expiry) {
		log.Info().Str("short_url", shortURL).Msg("URL expired (preview)")
		SendJSONError(w, http.StatusGone, errors.New("URL has expired"), "This short URL has expired and is no longer available")
		return
	}

	// Prepare template data
	data := PreviewData{
		OriginalURL:      url.OriginalURL,
		ShortURL:         shortURL,
		CreatedAt:        url.CreatedAt.Format("Jan 2, 2006 15:04"),
		IsSecure:         strings.HasPrefix(url.OriginalURL, "https://"),
		AutoRedirect:     autoRedirectSeconds > 0,
		CountdownSeconds: autoRedirectSeconds,
	}

	// Add expiry info if set
	if !url.Expiry.IsZero() {
		data.Expiry = url.Expiry.Format("Jan 2, 2006 15:04")
	}

	// Add usage info if max usage is set
	if url.MaxUsage > 0 {
		data.UsageInfo = fmt.Sprintf("%d / %d uses", url.CurrentUsage, url.MaxUsage)
	} else if url.CurrentUsage > 0 {
		data.UsageInfo = fmt.Sprintf("%d uses", url.CurrentUsage)
	}

	// Parse and execute template
	tmpl, err := template.ParseFS(previewTemplateFS, "preview.html")
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse preview template")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to load preview page")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	if err := tmpl.Execute(w, data); err != nil {
		log.Error().Err(err).Msg("Failed to execute preview template")
		return
	}

	log.Info().
		Str("short_url", shortURL).
		Str("original_url", url.OriginalURL).
		Bool("auto_redirect", autoRedirectSeconds > 0).
		Msg("Preview page displayed")
}
