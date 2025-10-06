package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"short-url-generator/config"
	"short-url-generator/model"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
)

func TestUpdateURL_MissingManagementID(t *testing.T) {
	cfg := &config.Config{
		Redis: config.RedisConfig{OperationTimeout: 5},
	}
	handler := NewURLHandler(nil, nil, *cfg)

	reqBody := UpdateURLRequest{
		OriginalURL:    "https://example.com",
		ShortURL:       "abc123",
		NewOriginalURL: "https://newexample.com",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPut, "/shorten/", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	handler.UpdateURL(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestUpdateURL_InvalidJSON(t *testing.T) {
	cfg := &config.Config{
		Redis: config.RedisConfig{OperationTimeout: 5},
	}
	handler := NewURLHandler(nil, nil, *cfg)

	req := httptest.NewRequest(http.MethodPut, "/shorten/test-id", bytes.NewBufferString("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"managementID": "test-id"})
	w := httptest.NewRecorder()

	handler.UpdateURL(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestUpdateURL_MissingRequiredFields(t *testing.T) {
	cfg := &config.Config{
		Redis: config.RedisConfig{OperationTimeout: 5},
	}
	handler := NewURLHandler(nil, nil, *cfg)

	testCases := []struct {
		name  string
		input UpdateURLRequest
	}{
		{
			name: "Missing originalURL",
			input: UpdateURLRequest{
				ShortURL:       "abc123",
				NewOriginalURL: "https://newexample.com",
			},
		},
		{
			name: "Missing shortURL",
			input: UpdateURLRequest{
				OriginalURL:    "https://example.com",
				NewOriginalURL: "https://newexample.com",
			},
		},
		{
			name: "Missing newOriginalURL",
			input: UpdateURLRequest{
				OriginalURL: "https://example.com",
				ShortURL:    "abc123",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.input)
			req := httptest.NewRequest(http.MethodPut, "/shorten/test-id", bytes.NewBuffer(body))
			req = mux.SetURLVars(req, map[string]string{"managementID": "test-id"})
			w := httptest.NewRecorder()

			handler.UpdateURL(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400, got %d", w.Code)
			}
		})
	}
}

func TestUpdateURL_InvalidNewURL(t *testing.T) {
	cfg := &config.Config{
		Redis: config.RedisConfig{OperationTimeout: 5},
	}
	handler := NewURLHandler(nil, nil, *cfg)

	reqBody := UpdateURLRequest{
		OriginalURL:    "https://example.com",
		ShortURL:       "abc123",
		NewOriginalURL: "http://localhost:8080/admin", // Invalid URL (localhost)
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPut, "/shorten/test-id", bytes.NewBuffer(body))
	req = mux.SetURLVars(req, map[string]string{"managementID": "test-id"})
	w := httptest.NewRecorder()

	handler.UpdateURL(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid URL, got %d", w.Code)
	}
}

func TestDeleteURL_MissingManagementID(t *testing.T) {
	cfg := &config.Config{
		Redis: config.RedisConfig{OperationTimeout: 5},
	}
	handler := NewURLHandler(nil, nil, *cfg)

	reqBody := DeleteURLRequest{
		OriginalURL: "https://example.com",
		ShortURL:    "abc123",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodDelete, "/shorten/", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	handler.DeleteURL(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestDeleteURL_InvalidJSON(t *testing.T) {
	cfg := &config.Config{
		Redis: config.RedisConfig{OperationTimeout: 5},
	}
	handler := NewURLHandler(nil, nil, *cfg)

	req := httptest.NewRequest(http.MethodDelete, "/shorten/test-id", bytes.NewBufferString("invalid json"))
	req = mux.SetURLVars(req, map[string]string{"managementID": "test-id"})
	w := httptest.NewRecorder()

	handler.DeleteURL(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestDeleteURL_MissingRequiredFields(t *testing.T) {
	cfg := &config.Config{
		Redis: config.RedisConfig{OperationTimeout: 5},
	}
	handler := NewURLHandler(nil, nil, *cfg)

	testCases := []struct {
		name  string
		input DeleteURLRequest
	}{
		{
			name: "Missing originalURL",
			input: DeleteURLRequest{
				ShortURL: "abc123",
			},
		},
		{
			name: "Missing shortURL",
			input: DeleteURLRequest{
				OriginalURL: "https://example.com",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.input)
			req := httptest.NewRequest(http.MethodDelete, "/shorten/test-id", bytes.NewBuffer(body))
			req = mux.SetURLVars(req, map[string]string{"managementID": "test-id"})
			w := httptest.NewRecorder()

			handler.DeleteURL(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400, got %d", w.Code)
			}
		})
	}
}

// Integration tests (require Redis)
func TestUpdateURL_Success(t *testing.T) {
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
		Redis:    config.RedisConfig{OperationTimeout: 5},
		Features: config.FeaturesConfig{DeduplicationEnabled: false},
	}
	handler := NewURLHandler(rdb, nil, *cfg)

	// Prepare test data
	managementID := "test-mgmt-id-" + time.Now().Format("20060102150405")
	shortURL := "test" + time.Now().Format("150405")
	originalURL := "https://example.com/original"
	newOriginalURL := "https://example.com/updated"

	// Create URL in Redis
	url := model.URL{
		ManagementID: managementID,
		OriginalURL:  originalURL,
		ShortURL:     shortURL,
		CreatedAt:    time.Now(),
	}
	urlData, _ := json.Marshal(url)
	rdb.Set(rdb.Context(), shortURL, urlData, 0)
	rdb.HSet(rdb.Context(), managementIndexKey, managementID, shortURL)

	// Cleanup after test
	defer func() {
		rdb.Del(rdb.Context(), shortURL)
		rdb.HDel(rdb.Context(), managementIndexKey, managementID)
	}()

	// Test update
	reqBody := UpdateURLRequest{
		OriginalURL:    originalURL,
		ShortURL:       shortURL,
		NewOriginalURL: newOriginalURL,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPut, "/shorten/"+managementID, bytes.NewBuffer(body))
	req = mux.SetURLVars(req, map[string]string{"managementID": managementID})
	w := httptest.NewRecorder()

	handler.UpdateURL(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Response: %s", w.Code, w.Body.String())
	}

	// Verify update in Redis
	updatedData, _ := rdb.Get(rdb.Context(), shortURL).Result()
	var updatedURL model.URL
	json.Unmarshal([]byte(updatedData), &updatedURL)

	if updatedURL.OriginalURL != newOriginalURL {
		t.Errorf("Expected originalURL to be %s, got %s", newOriginalURL, updatedURL.OriginalURL)
	}
}

func TestDeleteURL_Success(t *testing.T) {
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
		Redis:    config.RedisConfig{OperationTimeout: 5},
		Features: config.FeaturesConfig{DeduplicationEnabled: false},
	}
	handler := NewURLHandler(rdb, nil, *cfg)

	// Prepare test data
	managementID := "test-mgmt-id-" + time.Now().Format("20060102150405")
	shortURL := "test" + time.Now().Format("150405")
	originalURL := "https://example.com/delete-test"

	// Create URL in Redis
	url := model.URL{
		ManagementID: managementID,
		OriginalURL:  originalURL,
		ShortURL:     shortURL,
		CreatedAt:    time.Now(),
	}
	urlData, _ := json.Marshal(url)
	rdb.Set(rdb.Context(), shortURL, urlData, 0)
	rdb.HSet(rdb.Context(), managementIndexKey, managementID, shortURL)

	// Test delete
	reqBody := DeleteURLRequest{
		OriginalURL: originalURL,
		ShortURL:    shortURL,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodDelete, "/shorten/"+managementID, bytes.NewBuffer(body))
	req = mux.SetURLVars(req, map[string]string{"managementID": managementID})
	w := httptest.NewRecorder()

	handler.DeleteURL(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d. Response: %s", w.Code, w.Body.String())
	}

	// Verify deletion in Redis
	exists := rdb.Exists(rdb.Context(), shortURL).Val()
	if exists != 0 {
		t.Errorf("Expected URL to be deleted from Redis")
	}

	// Verify deletion from management index
	_, err := rdb.HGet(rdb.Context(), managementIndexKey, managementID).Result()
	if err != redis.Nil {
		t.Errorf("Expected management ID to be deleted from index")
	}
}
