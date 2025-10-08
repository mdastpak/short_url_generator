package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"short-url-generator/config"
	"short-url-generator/model"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
)

func TestGetAdminStats_RequiresRedis(t *testing.T) {
	t.Skip("GetAdminStats requires Redis connection - tested in integration test")
}

func TestGetAdminStats_WithRedis(t *testing.T) {
	// Initialize Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})

	// Check if Redis is available
	if err := rdb.Ping(rdb.Context()).Err(); err != nil {
		t.Skip("Redis not available, skipping integration test")
	}

	cfg := &config.Config{
		Redis: config.RedisConfig{OperationTimeout: 5},
		Cache: config.CacheConfig{Enabled: false},
		Features: config.FeaturesConfig{DeduplicationEnabled: false},
	}
	handler := NewURLHandler(rdb, nil, *cfg, nil)

	// Create a test URL
	testURL := model.URL{
		ShortURL:     "teststats" + time.Now().Format("150405"),
		OriginalURL:  "https://example.com/stats-test",
		ManagementID: "test-mgmt-stats",
		CreatedAt:    time.Now(),
		CurrentUsage: 5,
	}
	urlData, _ := json.Marshal(testURL)
	rdb.Set(rdb.Context(), testURL.ShortURL, urlData, 0)

	// Cleanup
	defer rdb.Del(rdb.Context(), testURL.ShortURL)

	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	w := httptest.NewRecorder()

	handler.GetAdminStats(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Response: %s", w.Code, w.Body.String())
	}

	var stats AdminStats
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if stats.TotalURLs < 1 {
		t.Errorf("Expected at least 1 URL, got %d", stats.TotalURLs)
	}

	if stats.TotalClicks < 5 {
		t.Errorf("Expected at least 5 clicks, got %d", stats.TotalClicks)
	}
}

func TestGetURLsList_WithRedis(t *testing.T) {
	// Initialize Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})

	// Check if Redis is available
	if err := rdb.Ping(rdb.Context()).Err(); err != nil {
		t.Skip("Redis not available, skipping integration test")
	}

	cfg := &config.Config{
		Redis: config.RedisConfig{OperationTimeout: 5},
		Cache: config.CacheConfig{Enabled: false},
		Features: config.FeaturesConfig{DeduplicationEnabled: false},
	}
	handler := NewURLHandler(rdb, nil, *cfg, nil)

	// Create test URLs
	testURL1 := model.URL{
		ShortURL:     "testlist1" + time.Now().Format("150405"),
		OriginalURL:  "https://example.com/list-test-1",
		ManagementID: "test-mgmt-list-1",
		CreatedAt:    time.Now(),
	}
	testURL2 := model.URL{
		ShortURL:     "testlist2" + time.Now().Format("150405"),
		OriginalURL:  "https://example.com/list-test-2",
		ManagementID: "test-mgmt-list-2",
		CreatedAt:    time.Now(),
	}

	url1Data, _ := json.Marshal(testURL1)
	url2Data, _ := json.Marshal(testURL2)
	rdb.Set(rdb.Context(), testURL1.ShortURL, url1Data, 0)
	rdb.Set(rdb.Context(), testURL2.ShortURL, url2Data, 0)

	// Cleanup
	defer func() {
		rdb.Del(rdb.Context(), testURL1.ShortURL)
		rdb.Del(rdb.Context(), testURL2.ShortURL)
	}()

	req := httptest.NewRequest(http.MethodGet, "/admin/urls?page=1&pageSize=10", nil)
	w := httptest.NewRecorder()

	handler.GetURLsList(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Response: %s", w.Code, w.Body.String())
	}

	var response URLListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response.Total < 2 {
		t.Errorf("Expected at least 2 URLs, got %d", response.Total)
	}

	if len(response.URLs) == 0 {
		t.Errorf("Expected URLs array to not be empty")
	}
}

func TestGetURLDetail_WithRedis(t *testing.T) {
	// Initialize Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})

	// Check if Redis is available
	if err := rdb.Ping(rdb.Context()).Err(); err != nil {
		t.Skip("Redis not available, skipping integration test")
	}

	cfg := &config.Config{
		Redis: config.RedisConfig{OperationTimeout: 5},
		Cache: config.CacheConfig{Enabled: false},
		Features: config.FeaturesConfig{DeduplicationEnabled: false},
	}
	handler := NewURLHandler(rdb, nil, *cfg, nil)

	// Create test URL
	shortURL := "testdetail" + time.Now().Format("150405")
	testURL := model.URL{
		ShortURL:     shortURL,
		OriginalURL:  "https://example.com/detail-test",
		ManagementID: "test-mgmt-detail",
		CreatedAt:    time.Now(),
		CurrentUsage: 3,
	}

	urlData, _ := json.Marshal(testURL)
	rdb.Set(rdb.Context(), shortURL, urlData, 0)

	// Add test log
	testLog := model.URLLog{
		IP:         "192.0.2.1",
		UserAgent:  "Test Agent",
		AccessedAt: time.Now(),
	}
	logData, _ := json.Marshal(testLog)
	rdb.RPush(rdb.Context(), "logs:"+shortURL, logData)

	// Cleanup
	defer func() {
		rdb.Del(rdb.Context(), shortURL)
		rdb.Del(rdb.Context(), "logs:"+shortURL)
	}()

	req := httptest.NewRequest(http.MethodGet, "/admin/urls/"+shortURL, nil)
	req = mux.SetURLVars(req, map[string]string{"shortURL": shortURL})
	w := httptest.NewRecorder()

	handler.GetURLDetail(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Response: %s", w.Code, w.Body.String())
	}

	var response URLDetailResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response.URL.ShortURL != shortURL {
		t.Errorf("Expected shortURL %s, got %s", shortURL, response.URL.ShortURL)
	}

	if response.TotalLogs < 1 {
		t.Errorf("Expected at least 1 log, got %d", response.TotalLogs)
	}
}

func TestGetURLDetail_NotFound(t *testing.T) {
	// Initialize Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})

	// Check if Redis is available
	if err := rdb.Ping(rdb.Context()).Err(); err != nil {
		t.Skip("Redis not available, skipping integration test")
	}

	cfg := &config.Config{
		Redis: config.RedisConfig{OperationTimeout: 5},
	}
	handler := NewURLHandler(rdb, nil, *cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/urls/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"shortURL": "nonexistent"})
	w := httptest.NewRecorder()

	handler.GetURLDetail(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestGetSystemHealth(t *testing.T) {
	// Initialize Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})

	// Check if Redis is available
	if err := rdb.Ping(rdb.Context()).Err(); err != nil {
		t.Skip("Redis not available, skipping integration test")
	}

	cfg := &config.Config{
		Redis: config.RedisConfig{OperationTimeout: 5},
		Cache: config.CacheConfig{Enabled: false},
		Features: config.FeaturesConfig{DeduplicationEnabled: true},
		Security: config.SecurityConfig{
			URLScanningEnabled:  true,
			BotDetectionEnabled: true,
		},
		RateLimit: config.RateLimitConfig{
			RequestsPerSecond: 10,
		},
	}
	handler := NewURLHandler(rdb, nil, *cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/system/health", nil)
	w := httptest.NewRecorder()

	handler.GetSystemHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Response: %s", w.Code, w.Body.String())
	}

	var health map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &health); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if health["status"] != "ok" {
		t.Errorf("Expected status 'ok', got %v", health["status"])
	}

	if _, ok := health["redis"]; !ok {
		t.Errorf("Expected 'redis' key in health response")
	}

	if _, ok := health["config"]; !ok {
		t.Errorf("Expected 'config' key in health response")
	}
}
