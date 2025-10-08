package middleware

import (
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

// AdminAuth middleware protects admin endpoints with API key authentication
type AdminAuth struct {
	apiKey  string
	enabled bool
}

// NewAdminAuth creates a new admin authentication middleware
func NewAdminAuth(apiKey string, enabled bool) *AdminAuth {
	if enabled && apiKey == "" {
		log.Warn().Msg("Admin authentication enabled but no API key configured - admin routes will be inaccessible")
	}
	return &AdminAuth{
		apiKey:  apiKey,
		enabled: enabled,
	}
}

// Protect wraps an HTTP handler with admin authentication
func (a *AdminAuth) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication if disabled
		if !a.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Check if API key is configured
		if a.apiKey == "" {
			log.Warn().Str("path", r.URL.Path).Msg("Admin route accessed but no API key configured")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error":"Admin authentication not configured"}`))
			return
		}

		// Get API key from header
		providedKey := r.Header.Get("X-Admin-Key")
		if providedKey == "" {
			// Also check Authorization header (Bearer token format)
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				providedKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		// Validate API key
		if providedKey == "" {
			log.Warn().
				Str("path", r.URL.Path).
				Str("ip", r.RemoteAddr).
				Msg("Admin route accessed without API key")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"Missing admin API key. Provide via X-Admin-Key header or Authorization: Bearer <key>"}`))
			return
		}

		if providedKey != a.apiKey {
			log.Warn().
				Str("path", r.URL.Path).
				Str("ip", r.RemoteAddr).
				Msg("Admin route accessed with invalid API key")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"Invalid admin API key"}`))
			return
		}

		// Authentication successful
		log.Debug().
			Str("path", r.URL.Path).
			Str("ip", r.RemoteAddr).
			Msg("Admin authenticated successfully")

		next.ServeHTTP(w, r)
	})
}
