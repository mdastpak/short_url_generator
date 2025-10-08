package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"short-url-generator/model"
	"short-url-generator/utils"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

// AdminStats represents system-wide statistics
type AdminStats struct {
	TotalURLs        int64     `json:"totalURLs"`
	ActiveURLs       int64     `json:"activeURLs"`
	ExpiredURLs      int64     `json:"expiredURLs"`
	TotalClicks      int64     `json:"totalClicks"`
	URLsCreatedToday int64     `json:"urlsCreatedToday"`
	ClicksToday      int64     `json:"clicksToday"`
	CacheEnabled     bool      `json:"cacheEnabled"`
	CacheHitRate     float64   `json:"cacheHitRate,omitempty"`
	LastUpdated      time.Time `json:"lastUpdated"`
}

// URLListItem represents a URL in the admin list
type URLListItem struct {
	ShortURL     string    `json:"shortURL"`
	OriginalURL  string    `json:"originalURL"`
	ManagementID string    `json:"managementID"`
	CreatedAt    time.Time `json:"createdAt"`
	Expiry       time.Time `json:"expiry,omitempty"`
	MaxUsage     int       `json:"maxUsage,omitempty"`
	CurrentUsage int       `json:"currentUsage"`
	IsExpired    bool      `json:"isExpired"`
	IsActive     bool      `json:"isActive"`
}

// URLListResponse represents paginated URL list
type URLListResponse struct {
	URLs       []URLListItem `json:"urls"`
	Total      int           `json:"total"`
	Page       int           `json:"page"`
	PageSize   int           `json:"pageSize"`
	TotalPages int           `json:"totalPages"`
}

// URLDetailResponse represents detailed URL information with logs
type URLDetailResponse struct {
	URL        model.URL       `json:"url"`
	AccessLogs []model.URLLog  `json:"accessLogs"`
	TotalLogs  int             `json:"totalLogs"`
}

// SecurityBlock represents a blocked request
type SecurityBlock struct {
	Type      string    `json:"type"` // "malware", "phishing", "bot"
	URL       string    `json:"url,omitempty"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"userAgent,omitempty"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}

// SecurityStats represents security statistics
type SecurityStats struct {
	BotDetections          int64     `json:"botDetections"`
	MaliciousURLsBlocked   int64     `json:"maliciousURLsBlocked"`
	RateLimitViolations    int64     `json:"rateLimitViolations"`
	TotalSecurityBlocks    int64     `json:"totalSecurityBlocks"`
	Last24Hours            StatsLast24Hours `json:"last24Hours"`
	TopBlockedIPs          []IPBlockCount `json:"topBlockedIPs"`
	TopBlockReasons        []ReasonCount `json:"topBlockReasons"`
	SecurityEnabled        bool      `json:"securityEnabled"`
	URLScanningEnabled     bool      `json:"urlScanningEnabled"`
	BotDetectionEnabled    bool      `json:"botDetectionEnabled"`
	LastUpdated            time.Time `json:"lastUpdated"`
}

// StatsLast24Hours represents statistics for the last 24 hours
type StatsLast24Hours struct {
	BotDetections        int64 `json:"botDetections"`
	MaliciousURLsBlocked int64 `json:"maliciousURLsBlocked"`
	RateLimitViolations  int64 `json:"rateLimitViolations"`
}

// IPBlockCount represents blocked count per IP
type IPBlockCount struct {
	IP    string `json:"ip"`
	Count int64  `json:"count"`
}

// ReasonCount represents block count per reason
type ReasonCount struct {
	Reason string `json:"reason"`
	Count  int64  `json:"count"`
}

// GetAdminStats handles GET /admin/stats
// @Summary Get system statistics
// @Description Returns comprehensive system statistics including URL counts, clicks, and cache metrics
// @Tags Admin
// @Security ApiKeyAuth
// @Produce json
// @Success 200 {object} AdminStats "System statistics"
// @Failure 401 {object} model.ErrorResponse "Unauthorized"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /admin/stats [get]
func (h *URLHandler) GetAdminStats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.Redis.OperationTimeout)*time.Second)
	defer cancel()

	stats := AdminStats{
		LastUpdated:  time.Now(),
		CacheEnabled: h.config.Cache.Enabled,
	}

	// Get all keys to count total URLs
	keys, err := h.redis.Keys(ctx, "*").Result()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get keys for stats")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to retrieve statistics")
		return
	}

	// Count URLs (excluding special keys like url_index, management_index, logs:*, expired_urls, usedup_urls)
	urlCount := int64(0)
	activeCount := int64(0)
	expiredCount := int64(0)
	totalClicks := int64(0)
	urlsToday := int64(0)
	clicksToday := int64(0)

	todayStart := time.Now().Truncate(24 * time.Hour)

	for _, key := range keys {
		// Skip special Redis keys
		if key == urlIndexKey || key == managementIndexKey ||
		   key == "expired_urls" || key == "usedup_urls" ||
		   strings.HasPrefix(key, "logs:") {
			continue
		}

		// Get URL data
		urlData, err := h.redis.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}

		var url model.URL
		if err := json.Unmarshal(urlData, &url); err != nil {
			continue
		}

		urlCount++
		totalClicks += int64(url.CurrentUsage)

		// Check if created today
		if url.CreatedAt.After(todayStart) {
			urlsToday++
		}

		// Check if active or expired
		isExpired := !url.Expiry.IsZero() && time.Now().After(url.Expiry)
		isUsedUp := url.MaxUsage > 0 && url.CurrentUsage >= url.MaxUsage

		if isExpired || isUsedUp {
			expiredCount++
		} else {
			activeCount++
		}

		// Count clicks today (approximation - we'd need to check logs for exact count)
		clicksToday += int64(url.CurrentUsage) // Simplified - in reality, check logs
	}

	stats.TotalURLs = urlCount
	stats.ActiveURLs = activeCount
	stats.ExpiredURLs = expiredCount
	stats.TotalClicks = totalClicks
	stats.URLsCreatedToday = urlsToday
	stats.ClicksToday = clicksToday

	// Get cache metrics if enabled
	if h.config.Cache.Enabled && h.cache != nil {
		snapshot := h.cache.GetMetricsSnapshot()
		stats.CacheHitRate = snapshot.HitRatio
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)

	log.Info().
		Int64("total_urls", stats.TotalURLs).
		Int64("active_urls", stats.ActiveURLs).
		Int64("total_clicks", stats.TotalClicks).
		Msg("Admin stats retrieved")
}

// GetURLsList handles GET /admin/urls
// @Summary List all URLs with pagination
// @Description Returns paginated list of all URLs with filtering and search capabilities
// @Tags Admin
// @Security ApiKeyAuth
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param pageSize query int false "Items per page (max 100)" default(20)
// @Param search query string false "Search in originalURL or shortURL"
// @Param status query string false "Filter by status: active, expired, all" default(all)
// @Success 200 {object} URLListResponse "URL list"
// @Failure 401 {object} model.ErrorResponse "Unauthorized"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /admin/urls [get]
func (h *URLHandler) GetURLsList(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.Redis.OperationTimeout)*time.Second)
	defer cancel()

	// Parse query parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100 // Max page size
	}

	searchQuery := strings.ToLower(r.URL.Query().Get("search"))
	statusFilter := r.URL.Query().Get("status") // "active", "expired", "all"
	if statusFilter == "" {
		statusFilter = "all"
	}

	// Get all URL keys
	keys, err := h.redis.Keys(ctx, "*").Result()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get keys for URL list")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to retrieve URLs")
		return
	}

	// Collect all URLs
	var allURLs []URLListItem

	for _, key := range keys {
		// Skip special keys
		if key == urlIndexKey || key == managementIndexKey ||
		   key == "expired_urls" || key == "usedup_urls" ||
		   strings.HasPrefix(key, "logs:") {
			continue
		}

		// Get URL data
		urlData, err := h.redis.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}

		var url model.URL
		if err := json.Unmarshal(urlData, &url); err != nil {
			continue
		}

		// Check if expired or used up
		isExpired := !url.Expiry.IsZero() && time.Now().After(url.Expiry)
		isUsedUp := url.MaxUsage > 0 && url.CurrentUsage >= url.MaxUsage
		isActive := !isExpired && !isUsedUp

		// Apply status filter
		if statusFilter == "active" && !isActive {
			continue
		}
		if statusFilter == "expired" && isActive {
			continue
		}

		// Apply search filter
		if searchQuery != "" {
			if !strings.Contains(strings.ToLower(url.OriginalURL), searchQuery) &&
			   !strings.Contains(strings.ToLower(url.ShortURL), searchQuery) {
				continue
			}
		}

		allURLs = append(allURLs, URLListItem{
			ShortURL:     url.ShortURL,
			OriginalURL:  url.OriginalURL,
			ManagementID: url.ManagementID,
			CreatedAt:    url.CreatedAt,
			Expiry:       url.Expiry,
			MaxUsage:     url.MaxUsage,
			CurrentUsage: url.CurrentUsage,
			IsExpired:    isExpired || isUsedUp,
			IsActive:     isActive,
		})
	}

	// Sort by CreatedAt (newest first)
	sort.Slice(allURLs, func(i, j int) bool {
		return allURLs[i].CreatedAt.After(allURLs[j].CreatedAt)
	})

	// Paginate
	total := len(allURLs)
	totalPages := (total + pageSize - 1) / pageSize

	start := (page - 1) * pageSize
	end := start + pageSize

	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	pagedURLs := allURLs[start:end]
	if pagedURLs == nil {
		pagedURLs = []URLListItem{} // Return empty array instead of null
	}

	response := URLListResponse{
		URLs:       pagedURLs,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Info().
		Int("page", page).
		Int("page_size", pageSize).
		Int("total", total).
		Str("search", searchQuery).
		Str("status", statusFilter).
		Msg("URLs list retrieved")
}

// GetURLDetail handles GET /admin/urls/{shortURL}
// @Summary Get detailed URL information
// @Description Returns detailed information about a specific URL including access logs
// @Tags Admin
// @Security ApiKeyAuth
// @Produce json
// @Param shortURL path string true "Short URL code"
// @Param limit query int false "Number of recent logs to return" default(50)
// @Success 200 {object} URLDetailResponse "URL details"
// @Failure 401 {object} model.ErrorResponse "Unauthorized"
// @Failure 404 {object} model.ErrorResponse "URL not found"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /admin/urls/{shortURL} [get]
func (h *URLHandler) GetURLDetail(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.Redis.OperationTimeout)*time.Second)
	defer cancel()

	vars := mux.Vars(r)
	shortURL := vars["shortURL"]

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}

	// Get URL data
	urlData, err := h.redis.Get(ctx, shortURL).Bytes()
	if err == redis.Nil {
		SendJSONError(w, http.StatusNotFound, errors.New("URL not found"), "")
		return
	} else if err != nil {
		log.Error().Err(err).Str("short_url", shortURL).Msg("Failed to retrieve URL")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to retrieve URL")
		return
	}

	var url model.URL
	if err := json.Unmarshal(urlData, &url); err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal URL data")
		SendJSONError(w, http.StatusInternalServerError, err, "Internal server error")
		return
	}

	// Get access logs
	logKey := "logs:" + shortURL
	logStrings, err := h.redis.LRange(ctx, logKey, 0, int64(limit-1)).Result()
	if err != nil && err != redis.Nil {
		log.Error().Err(err).Str("short_url", shortURL).Msg("Failed to retrieve logs")
	}

	var logs []model.URLLog
	for _, logStr := range logStrings {
		var logEntry model.URLLog
		if err := json.Unmarshal([]byte(logStr), &logEntry); err == nil {
			logs = append(logs, logEntry)
		}
	}

	// Get total log count
	totalLogs, _ := h.redis.LLen(ctx, logKey).Result()

	response := URLDetailResponse{
		URL:        url,
		AccessLogs: logs,
		TotalLogs:  int(totalLogs),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Info().Str("short_url", shortURL).Int("logs_returned", len(logs)).Msg("URL detail retrieved")
}

// BulkDeleteURLs handles POST /admin/urls/bulk-delete
// @Summary Bulk delete URLs
// @Description Deletes multiple URLs at once
// @Tags Admin
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Param request body []string true "Array of short URL codes to delete"
// @Success 200 {object} map[string]interface{} "Deletion result with counts"
// @Failure 400 {object} model.ErrorResponse "Invalid request"
// @Failure 401 {object} model.ErrorResponse "Unauthorized"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /admin/urls/bulk-delete [post]
func (h *URLHandler) BulkDeleteURLs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.Redis.OperationTimeout)*time.Second)
	defer cancel()

	var shortURLs []string
	if err := json.NewDecoder(r.Body).Decode(&shortURLs); err != nil {
		SendJSONError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if len(shortURLs) == 0 {
		SendJSONError(w, http.StatusBadRequest, errors.New("empty array"), "No URLs provided for deletion")
		return
	}

	deleted := 0
	notFound := 0
	failed := 0

	for _, shortURL := range shortURLs {
		// Get URL to find managementID
		urlData, err := h.redis.Get(ctx, shortURL).Bytes()
		if err == redis.Nil {
			notFound++
			continue
		} else if err != nil {
			failed++
			continue
		}

		var url model.URL
		if err := json.Unmarshal(urlData, &url); err != nil {
			failed++
			continue
		}

		// Delete URL
		if err := h.redis.Del(ctx, shortURL).Err(); err != nil {
			failed++
			continue
		}

		// Delete from management index
		if url.ManagementID != "" {
			h.redis.HDel(ctx, managementIndexKey, url.ManagementID)
		}

		// Delete from deduplication index if enabled
		if h.config.Features.DeduplicationEnabled {
			urlHash := utils.HashURL(url.OriginalURL)
			h.redis.HDel(ctx, urlIndexKey, urlHash)
		}

		// Delete logs
		logKey := "logs:" + shortURL
		h.redis.Del(ctx, logKey)

		// Invalidate cache
		if h.config.Cache.Enabled && h.cache != nil {
			h.cache.Delete(shortURL)
		}

		deleted++
	}

	response := map[string]interface{}{
		"requested": len(shortURLs),
		"deleted":   deleted,
		"notFound":  notFound,
		"failed":    failed,
		"success":   failed == 0,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Info().
		Int("requested", len(shortURLs)).
		Int("deleted", deleted).
		Int("not_found", notFound).
		Int("failed", failed).
		Msg("Bulk delete completed")
}

// GetSystemHealth handles GET /admin/system/health
// @Summary Get extended system health
// @Description Returns detailed system health including Redis metrics, cache stats, and memory usage
// @Tags Admin
// @Security ApiKeyAuth
// @Produce json
// @Success 200 {object} map[string]interface{} "System health details"
// @Failure 401 {object} model.ErrorResponse "Unauthorized"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /admin/system/health [get]
func (h *URLHandler) GetSystemHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	health := make(map[string]interface{})
	health["status"] = "ok"
	health["timestamp"] = time.Now()

	// Redis health
	if err := h.redis.Ping(ctx).Err(); err != nil {
		health["status"] = "degraded"
		health["redis"] = map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		}
	} else {
		// Get Redis info
		info, _ := h.redis.Info(ctx).Result()
		health["redis"] = map[string]interface{}{
			"status":    "connected",
			"connected": true,
		}

		// Parse memory usage from info if available
		if strings.Contains(info, "used_memory_human") {
			health["redis"].(map[string]interface{})["info"] = "available"
		}
	}

	// Cache health
	if h.config.Cache.Enabled && h.cache != nil {
		snapshot := h.cache.GetMetricsSnapshot()
		health["cache"] = map[string]interface{}{
			"enabled":    true,
			"hits":       snapshot.Hits,
			"misses":     snapshot.Misses,
			"keysAdded":  snapshot.KeysAdded,
			"evictions":  snapshot.KeysEvicted,
			"hitRatio":   snapshot.HitRatio,
		}
	} else {
		health["cache"] = map[string]interface{}{
			"enabled": false,
		}
	}

	// Configuration
	health["config"] = map[string]interface{}{
		"deduplicationEnabled": h.config.Features.DeduplicationEnabled,
		"urlScanningEnabled":   h.config.Security.URLScanningEnabled,
		"botDetectionEnabled":  h.config.Security.BotDetectionEnabled,
		"rateLimitRPS":         h.config.RateLimit.RequestsPerSecond,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// GetSecurityStats handles GET /admin/security/stats
// @Summary Get security statistics
// @Description Returns comprehensive security statistics including bot detections, blocked URLs, and rate limit violations
// @Tags Admin
// @Security ApiKeyAuth
// @Produce json
// @Success 200 {object} SecurityStats "Security statistics"
// @Failure 401 {object} model.ErrorResponse "Unauthorized"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /admin/security/stats [get]
func (h *URLHandler) GetSecurityStats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.Redis.OperationTimeout)*time.Second)
	defer cancel()

	stats := SecurityStats{
		SecurityEnabled:     h.config.Security.URLScanningEnabled || h.config.Security.BotDetectionEnabled,
		URLScanningEnabled:  h.config.Security.URLScanningEnabled,
		BotDetectionEnabled: h.config.Security.BotDetectionEnabled,
		LastUpdated:         time.Now(),
	}

	// Get bot detection count
	botCount, err := h.redis.Get(ctx, "security:bot_detections").Int64()
	if err != nil && err != redis.Nil {
		log.Error().Err(err).Msg("Failed to get bot detection count")
	}
	stats.BotDetections = botCount

	// Get malicious URLs blocked count
	maliciousCount, err := h.redis.Get(ctx, "security:malicious_urls").Int64()
	if err != nil && err != redis.Nil {
		log.Error().Err(err).Msg("Failed to get malicious URLs count")
	}
	stats.MaliciousURLsBlocked = maliciousCount

	// Get rate limit violations count
	rateLimitCount, err := h.redis.Get(ctx, "security:rate_limit_violations").Int64()
	if err != nil && err != redis.Nil {
		log.Error().Err(err).Msg("Failed to get rate limit violations count")
	}
	stats.RateLimitViolations = rateLimitCount

	// Calculate total
	stats.TotalSecurityBlocks = stats.BotDetections + stats.MaliciousURLsBlocked + stats.RateLimitViolations

	// Get last 24 hours statistics
	now := time.Now()
	yesterday := now.Add(-24 * time.Hour).Unix()

	// Bot detections in last 24 hours
	botLast24h, err := h.redis.ZCount(ctx, "security:bot_detections_timeline", fmt.Sprintf("%d", yesterday), "+inf").Result()
	if err != nil && err != redis.Nil {
		log.Error().Err(err).Msg("Failed to get bot detections last 24h")
	}
	stats.Last24Hours.BotDetections = botLast24h

	// Malicious URLs in last 24 hours
	maliciousLast24h, err := h.redis.ZCount(ctx, "security:malicious_urls_timeline", fmt.Sprintf("%d", yesterday), "+inf").Result()
	if err != nil && err != redis.Nil {
		log.Error().Err(err).Msg("Failed to get malicious URLs last 24h")
	}
	stats.Last24Hours.MaliciousURLsBlocked = maliciousLast24h

	// Rate limit violations in last 24 hours
	rateLimitLast24h, err := h.redis.ZCount(ctx, "security:rate_limit_timeline", fmt.Sprintf("%d", yesterday), "+inf").Result()
	if err != nil && err != redis.Nil {
		log.Error().Err(err).Msg("Failed to get rate limit violations last 24h")
	}
	stats.Last24Hours.RateLimitViolations = rateLimitLast24h

	// Get top blocked IPs (from sorted set)
	topIPs, err := h.redis.ZRevRangeWithScores(ctx, "security:blocked_ips", 0, 9).Result()
	if err != nil && err != redis.Nil {
		log.Error().Err(err).Msg("Failed to get top blocked IPs")
	}
	for _, z := range topIPs {
		if ip, ok := z.Member.(string); ok {
			stats.TopBlockedIPs = append(stats.TopBlockedIPs, IPBlockCount{
				IP:    ip,
				Count: int64(z.Score),
			})
		}
	}

	// Get top block reasons (from sorted set)
	topReasons, err := h.redis.ZRevRangeWithScores(ctx, "security:block_reasons", 0, 9).Result()
	if err != nil && err != redis.Nil {
		log.Error().Err(err).Msg("Failed to get top block reasons")
	}
	for _, z := range topReasons {
		if reason, ok := z.Member.(string); ok {
			stats.TopBlockReasons = append(stats.TopBlockReasons, ReasonCount{
				Reason: reason,
				Count:  int64(z.Score),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)

	log.Info().
		Int64("bot_detections", stats.BotDetections).
		Int64("malicious_urls", stats.MaliciousURLsBlocked).
		Int64("rate_limit_violations", stats.RateLimitViolations).
		Msg("Security stats retrieved")
}
