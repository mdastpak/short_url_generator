package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"short-url-generator/model"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
)

// GetUserAnalytics handles GET /api/user/analytics
// @Summary Get user analytics
// @Description Get comprehensive analytics for authenticated user including click trends, device breakdown, and top URLs
// @Tags User
// @Security BearerAuth
// @Produce json
// @Success 200 {object} model.UserAnalytics "User analytics data"
// @Failure 401 {object} model.ErrorResponse "Not authenticated"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /api/user/analytics [get]
func (uh *UserHandler) GetUserAnalytics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get authenticated user ID
	userID, ok := r.Context().Value("userID").(string)
	if !ok {
		SendJSONError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"), "Authentication required")
		return
	}

	// Get all URL keys from Redis
	keys, err := uh.redis.Keys(ctx, "*").Result()
	if err != nil {
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to fetch analytics")
		return
	}

	// Initialize analytics data
	analytics := model.UserAnalytics{
		TotalURLs:        0,
		ActiveURLs:       0,
		TotalClicks:      0,
		ClicksByDay:      make([]model.TimeSeriesPoint, 0),
		DeviceBreakdown:  make(map[string]int),
		BrowserBreakdown: make(map[string]int),
		TopURLs:          make([]model.URLStats, 0),
		RecentActivity:   make([]model.ActivityLog, 0),
	}

	// Track clicks by date
	clicksByDate := make(map[string]int64)
	urlStatsList := make([]model.URLStats, 0)

	// Process all user URLs
	for _, key := range keys {
		// Skip non-URL keys
		if strings.HasPrefix(key, "otp:") || strings.HasPrefix(key, "user:") ||
			strings.HasPrefix(key, "logs:") || strings.HasPrefix(key, "url_index") ||
			strings.HasPrefix(key, "management_index") || strings.HasPrefix(key, "security:") ||
			strings.HasPrefix(key, "reset_token:") || strings.HasPrefix(key, "reset_attempts:") ||
			strings.HasPrefix(key, "activity:") || key == "admin_api_key" ||
			key == "malicious_urls" || key == "blocked_ips" || strings.HasSuffix(key, "_urls") {
			continue
		}

		// Get URL data
		urlData, err := uh.redis.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}

		var urlObj model.URL
		if err := json.Unmarshal(urlData, &urlObj); err != nil {
			continue
		}

		// Check if URL belongs to this user
		if urlObj.UserID != userID {
			continue
		}

		// Count totals
		analytics.TotalURLs++
		if urlObj.Active {
			analytics.ActiveURLs++
		}
		analytics.TotalClicks += int64(urlObj.CurrentUsage)

		// Get access logs for this URL to find last accessed time
		logsKey := "logs:" + urlObj.ShortURL
		logs, err := uh.redis.LRange(ctx, logsKey, 0, -1).Result()

		lastAccessed := ""
		var lastAccessTime time.Time

		if err == nil {
			for _, logStr := range logs {
				var log model.URLLog
				if err := json.Unmarshal([]byte(logStr), &log); err != nil {
					continue
				}

				// Track last accessed time (most recent)
				if log.AccessedAt.After(lastAccessTime) {
					lastAccessTime = log.AccessedAt
					lastAccessed = log.AccessedAt.Format(time.RFC3339)
				}

				// Track clicks by day
				date := log.AccessedAt.Format("2006-01-02")
				clicksByDate[date]++

				// Track device breakdown
				device := parseDeviceType(log.UserAgent)
				analytics.DeviceBreakdown[device]++

				// Track browser breakdown
				browser := parseBrowserType(log.UserAgent)
				analytics.BrowserBreakdown[browser]++
			}
		}

		// Add to URL stats list
		urlStatsList = append(urlStatsList, model.URLStats{
			ShortURL:     urlObj.ShortURL,
			OriginalURL:  urlObj.OriginalURL,
			Clicks:       urlObj.CurrentUsage,
			LastAccessed: lastAccessed,
		})
	}

	// Sort URL stats by clicks (top 10)
	sortURLStats(urlStatsList)
	if len(urlStatsList) > 10 {
		analytics.TopURLs = urlStatsList[:10]
	} else {
		analytics.TopURLs = urlStatsList
	}

	// Convert clicks by date to time series (last 30 days)
	now := time.Now()
	for i := 29; i >= 0; i-- {
		date := now.AddDate(0, 0, -i).Format("2006-01-02")
		clicks := clicksByDate[date]
		analytics.ClicksByDay = append(analytics.ClicksByDay, model.TimeSeriesPoint{
			Date:  date,
			Value: clicks,
		})
	}

	// Get recent activity (last 10)
	recentActivity, err := uh.GetRecentActivity(ctx, userID, 10)
	if err == nil {
		analytics.RecentActivity = recentActivity
	}

	SendJSONSuccess(w, http.StatusOK, analytics)
}

// GetURLAccessLogs handles GET /api/user/url/{shortURL}/logs
// @Summary Get URL access logs
// @Description Get detailed access logs for a specific short URL
// @Tags User
// @Security BearerAuth
// @Produce json
// @Param shortURL path string true "Short URL"
// @Success 200 {object} map[string]interface{} "Access logs"
// @Failure 401 {object} model.ErrorResponse "Not authenticated"
// @Failure 403 {object} model.ErrorResponse "URL does not belong to user"
// @Failure 404 {object} model.ErrorResponse "URL not found"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /api/user/url/{shortURL}/logs [get]
func (uh *UserHandler) GetURLAccessLogs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get authenticated user ID
	userID, ok := r.Context().Value("userID").(string)
	if !ok {
		SendJSONError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"), "Authentication required")
		return
	}

	// Get short URL from path
	vars := mux.Vars(r)
	shortURL := vars["shortURL"]
	if shortURL == "" {
		SendJSONError(w, http.StatusBadRequest, fmt.Errorf("missing shortURL"), "Short URL is required")
		return
	}

	// Get URL data to verify ownership
	urlData, err := uh.redis.Get(ctx, shortURL).Result()
	if err == redis.Nil {
		SendJSONError(w, http.StatusNotFound, fmt.Errorf("not found"), "URL not found")
		return
	} else if err != nil {
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to retrieve URL")
		return
	}

	var urlObj model.URL
	if err := json.Unmarshal([]byte(urlData), &urlObj); err != nil {
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to parse URL data")
		return
	}

	// Verify ownership
	if urlObj.UserID != userID {
		SendJSONError(w, http.StatusForbidden, fmt.Errorf("forbidden"), "You do not have permission to access this URL's logs")
		return
	}

	// Get access logs
	logsKey := "logs:" + shortURL
	logs, err := uh.redis.LRange(ctx, logsKey, 0, -1).Result()
	if err != nil && err != redis.Nil {
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to retrieve logs")
		return
	}

	// Parse logs
	accessLogs := make([]model.URLLog, 0, len(logs))
	for _, logStr := range logs {
		var log model.URLLog
		if err := json.Unmarshal([]byte(logStr), &log); err != nil {
			continue
		}
		accessLogs = append(accessLogs, log)
	}

	response := map[string]interface{}{
		"shortURL":   shortURL,
		"originalURL": urlObj.OriginalURL,
		"totalLogs":  len(accessLogs),
		"logs":       accessLogs,
	}

	SendJSONSuccess(w, http.StatusOK, response)
}

// Helper functions

// parseDeviceType extracts device type from user agent
func parseDeviceType(userAgent string) string {
	ua := strings.ToLower(userAgent)
	if strings.Contains(ua, "mobile") || strings.Contains(ua, "android") || strings.Contains(ua, "iphone") {
		return "Mobile"
	} else if strings.Contains(ua, "tablet") || strings.Contains(ua, "ipad") {
		return "Tablet"
	} else if strings.Contains(ua, "bot") || strings.Contains(ua, "crawler") || strings.Contains(ua, "spider") {
		return "Bot"
	}
	return "Desktop"
}

// parseBrowserType extracts browser type from user agent
func parseBrowserType(userAgent string) string {
	ua := strings.ToLower(userAgent)
	if strings.Contains(ua, "edg/") || strings.Contains(ua, "edge") {
		return "Edge"
	} else if strings.Contains(ua, "chrome") && !strings.Contains(ua, "edg") {
		return "Chrome"
	} else if strings.Contains(ua, "firefox") {
		return "Firefox"
	} else if strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome") {
		return "Safari"
	} else if strings.Contains(ua, "opera") || strings.Contains(ua, "opr/") {
		return "Opera"
	} else if strings.Contains(ua, "bot") || strings.Contains(ua, "crawler") {
		return "Bot"
	}
	return "Other"
}

// sortURLStats sorts URL stats by clicks (descending)
func sortURLStats(stats []model.URLStats) {
	// Simple bubble sort (sufficient for small lists)
	for i := 0; i < len(stats); i++ {
		for j := i + 1; j < len(stats); j++ {
			if stats[j].Clicks > stats[i].Clicks {
				stats[i], stats[j] = stats[j], stats[i]
			}
		}
	}
}
