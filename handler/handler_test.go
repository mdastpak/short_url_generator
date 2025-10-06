package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"short-url-generator/config"
	"testing"
)

// Note: Full integration tests would require Redis connection
// These are unit tests that test individual functions

func TestGenerateRandomString(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"Length 8", 8},
		{"Length 10", 10},
		{"Length 6", 6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := generateRandomString(tt.length)
			if err != nil {
				t.Errorf("generateRandomString() error = %v", err)
				return
			}
			if len(result) != tt.length {
				t.Errorf("generateRandomString() length = %v, want %v", len(result), tt.length)
			}

			// Check all characters are from charset
			for _, ch := range result {
				found := false
				for _, valid := range charset {
					if ch == valid {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Invalid character %c in generated string", ch)
				}
			}
		})
	}
}

func TestGenerateRandomString_Uniqueness(t *testing.T) {
	// Generate multiple strings and verify they're different
	generated := make(map[string]bool)
	for i := 0; i < 100; i++ {
		str, err := generateRandomString(8)
		if err != nil {
			t.Fatalf("generateRandomString() error = %v", err)
		}
		if generated[str] {
			t.Errorf("Duplicate string generated: %s", str)
		}
		generated[str] = true
	}
}

func TestHealthCheckEndpoint(t *testing.T) {
	// Integration test - requires Redis connection
	t.Skip("Skipping integration test - requires Redis connection")
}

func TestCreateShortURL_InvalidJSON(t *testing.T) {
	cfg := config.Config{
		WebServer: config.WebServerConfig{
			Scheme: "http",
			IP:     "localhost",
			Port:   "8080",
		},
		Redis: config.RedisConfig{
			OperationTimeout: 5,
		},
	}

	// Create handler (Redis will be nil but we won't reach Redis operations)
	handler := &URLHandler{
		redis:   nil,
		config:  cfg,
		baseURL: "http://localhost:8080",
	}

	invalidJSON := []byte(`{"originalURL": invalid}`)
	req := httptest.NewRequest("POST", "/shorten", bytes.NewBuffer(invalidJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShortURL(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status BadRequest, got %v", w.Code)
	}
}

func TestCreateShortURL_InvalidURL(t *testing.T) {
	cfg := config.Config{
		WebServer: config.WebServerConfig{
			Scheme: "http",
			IP:     "localhost",
			Port:   "8080",
		},
		Redis: config.RedisConfig{
			OperationTimeout: 5,
		},
	}

	handler := &URLHandler{
		redis:   nil,
		config:  cfg,
		baseURL: "http://localhost:8080",
	}

	tests := []struct {
		name string
		url  string
	}{
		{"Empty URL", ""},
		{"Invalid scheme", "ftp://example.com"},
		{"Localhost", "http://localhost:8080"},
		{"Private IP", "http://192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody := map[string]string{"originalURL": tt.url}
			jsonBody, _ := json.Marshal(reqBody)

			req := httptest.NewRequest("POST", "/shorten", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.CreateShortURL(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("Expected status BadRequest for %s, got %v", tt.name, w.Code)
			}
		})
	}
}

func TestRedirectURL_NotFound(t *testing.T) {
	// Integration test - requires Redis connection
	t.Skip("Skipping - requires Redis mock implementation")
}
