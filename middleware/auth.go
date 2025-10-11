package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"short-url-generator/auth"

	"github.com/rs/zerolog/log"
)

// UserAuth is a middleware that validates user JWT tokens
type UserAuth struct {
	jwtManager *auth.JWTManager
}

// NewUserAuth creates a new user authentication middleware
func NewUserAuth(jwtManager *auth.JWTManager) *UserAuth {
	return &UserAuth{
		jwtManager: jwtManager,
	}
}

// Protect returns a middleware function that requires authentication
func (ua *UserAuth) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Missing authorization token",
			})
			return
		}

		// Check Bearer prefix
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid authorization header format. Use: Bearer <token>",
			})
			return
		}

		tokenString := parts[1]

		// Validate token
		claims, err := ua.jwtManager.ValidateToken(tokenString)
		if err != nil {
			log.Warn().Err(err).Msg("Invalid token")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid or expired token",
			})
			return
		}

		// Add user info to context
		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		ctx = context.WithValue(ctx, "userEmail", claims.Email)

		// Continue with authenticated request
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Optional returns a middleware that extracts user info if token exists but doesn't require it
func (ua *UserAuth) Optional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			next.ServeHTTP(w, r)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			claims, err := ua.jwtManager.ValidateToken(parts[1])
			if err == nil {
				// Add user info to context
				ctx := context.WithValue(r.Context(), "userID", claims.UserID)
				ctx = context.WithValue(ctx, "userEmail", claims.Email)
				r = r.WithContext(ctx)
			}
		}

		next.ServeHTTP(w, r)
	})
}

// GetUserID extracts user ID from request context
func GetUserID(r *http.Request) string {
	userID, ok := r.Context().Value("userID").(string)
	if !ok {
		return ""
	}
	return userID
}

// GetUserEmail extracts user email from request context
func GetUserEmail(r *http.Request) string {
	email, ok := r.Context().Value("userEmail").(string)
	if !ok {
		return ""
	}
	return email
}
