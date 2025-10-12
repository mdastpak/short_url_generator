package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"short-url-generator/model"
	"short-url-generator/utils"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

// VerifyPassword handles POST /verify-password/{shortURL}
// @Summary Verify password for protected URL
// @Description Verify password for password-protected short URL and set session cookie
// @Tags URLs
// @Accept json
// @Produce json
// @Param shortURL path string true "Short URL"
// @Param request body model.VerifyPasswordRequest true "Password"
// @Success 200 {object} map[string]interface{} "Password verified, redirect URL provided"
// @Failure 400 {object} model.ErrorResponse "Invalid request"
// @Failure 401 {object} model.ErrorResponse "Invalid password"
// @Failure 404 {object} model.ErrorResponse "URL not found"
// @Failure 429 {object} model.ErrorResponse "Too many attempts"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /verify-password/{shortURL} [post]
func (h *URLHandler) VerifyPassword(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get short URL from path
	vars := mux.Vars(r)
	shortURL := vars["shortURL"]
	if shortURL == "" {
		SendJSONError(w, http.StatusBadRequest, errors.New("missing shortURL"), "Short URL is required")
		return
	}

	// Parse request body
	var req model.VerifyPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendJSONError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Validate password
	if req.Password == "" {
		SendJSONError(w, http.StatusBadRequest, errors.New("missing password"), "Password is required")
		return
	}

	// Get IP address for rate limiting
	ip := getIPAddress(r)

	// Check rate limiting (5 attempts per 15 minutes)
	rateLimitKey := fmt.Sprintf("password_attempts:%s:%s", shortURL, ip)
	attempts, err := h.redis.Incr(ctx, rateLimitKey).Result()
	if err == nil {
		if attempts == 1 {
			// Set 15-minute expiration on first attempt
			h.redis.Expire(ctx, rateLimitKey, 15*time.Minute)
		}
		if attempts > 5 {
			SendJSONError(w, http.StatusTooManyRequests, errors.New("rate limited"), "Too many failed attempts. Please try again later.")
			return
		}
	}

	// Get URL from Redis (try cache first if enabled)
	var urlData model.URL
	if h.cache != nil {
		// Try cache first
		cached, found := h.cache.Get(shortURL)
		if found {
			urlData = cached.(model.URL)
		} else {
			// Cache miss, fetch from Redis
			urlJSON, err := h.redis.Get(ctx, shortURL).Result()
			if err == redis.Nil {
				SendJSONError(w, http.StatusNotFound, errors.New("not found"), "URL not found")
				return
			} else if err != nil {
				log.Error().Err(err).Msg("Failed to get URL from Redis")
				SendJSONError(w, http.StatusInternalServerError, err, "Failed to retrieve URL")
				return
			}

			if err := json.Unmarshal([]byte(urlJSON), &urlData); err != nil {
				log.Error().Err(err).Msg("Failed to unmarshal URL")
				SendJSONError(w, http.StatusInternalServerError, err, "Failed to parse URL data")
				return
			}

			// Update cache
			h.cache.Set(shortURL, urlData, 1024)
		}
	} else {
		// No cache, fetch directly from Redis
		urlJSON, err := h.redis.Get(ctx, shortURL).Result()
		if err == redis.Nil {
			SendJSONError(w, http.StatusNotFound, errors.New("not found"), "URL not found")
			return
		} else if err != nil {
			log.Error().Err(err).Msg("Failed to get URL from Redis")
			SendJSONError(w, http.StatusInternalServerError, err, "Failed to retrieve URL")
			return
		}

		if err := json.Unmarshal([]byte(urlJSON), &urlData); err != nil {
			log.Error().Err(err).Msg("Failed to unmarshal URL")
			SendJSONError(w, http.StatusInternalServerError, err, "Failed to parse URL data")
			return
		}
	}

	// Check if URL is password-protected
	if urlData.PasswordHash == "" {
		SendJSONError(w, http.StatusBadRequest, errors.New("not protected"), "This URL is not password-protected")
		return
	}

	// Verify password using bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(urlData.PasswordHash), []byte(req.Password))
	if err != nil {
		// Password incorrect - increment counter already happened via INCR
		log.Info().
			Str("shortURL", shortURL).
			Str("ip", ip).
			Msg("Failed password verification attempt")

		SendJSONError(w, http.StatusUnauthorized, errors.New("invalid password"), "Invalid password")
		return
	}

	// Password correct - delete rate limit counter
	h.redis.Del(ctx, rateLimitKey)

	// Generate session ID
	sessionID := uuid.New().String()

	// Store session in Redis (24-hour expiration)
	sessionKey := fmt.Sprintf("password_session:%s:%s", shortURL, sessionID)
	if err := h.redis.Set(ctx, sessionKey, time.Now().Format(time.RFC3339), 24*time.Hour).Err(); err != nil {
		log.Error().Err(err).Msg("Failed to store session")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to create session")
		return
	}

	// Set session cookie (24-hour expiration)
	cookie := &http.Cookie{
		Name:     fmt.Sprintf("url_access_%s", shortURL),
		Value:    sessionID,
		Path:     "/",
		MaxAge:   86400, // 24 hours
		HttpOnly: true,
		Secure:   h.config.WebServer.Scheme == "https",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	log.Info().
		Str("shortURL", shortURL).
		Str("ip", ip).
		Msg("Password verified successfully")

	// Return success with redirect URL
	SendJSONSuccess(w, http.StatusOK, map[string]interface{}{
		"message":     "Password verified successfully",
		"redirectURL": urlData.OriginalURL,
	})
}

// ShowPasswordPrompt handles GET /password/{shortURL}
// @Summary Show password prompt page
// @Description Display password prompt page for password-protected URLs
// @Tags URLs
// @Produce html
// @Param shortURL path string true "Short URL"
// @Success 200 {string} string "HTML password prompt page"
// @Failure 404 {object} model.ErrorResponse "URL not found"
// @Router /password/{shortURL} [get]
func (h *URLHandler) ShowPasswordPrompt(w http.ResponseWriter, r *http.Request) {
	// Serve the password prompt HTML
	http.ServeFile(w, r, "handler/password_prompt.html")
}

// SetURLPassword handles PUT /api/user/url/{shortURL}/password
// @Summary Set or update URL password
// @Description Set or update password protection for a short URL (authenticated users only)
// @Tags User
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param shortURL path string true "Short URL"
// @Param request body model.SetPasswordRequest true "Password"
// @Success 200 {object} map[string]interface{} "Password set successfully"
// @Failure 400 {object} model.ErrorResponse "Invalid request"
// @Failure 401 {object} model.ErrorResponse "Not authenticated"
// @Failure 403 {object} model.ErrorResponse "Not authorized"
// @Failure 404 {object} model.ErrorResponse "URL not found"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /api/user/url/{shortURL}/password [put]
func (uh *UserHandler) SetURLPassword(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get authenticated user ID
	userID, ok := r.Context().Value("userID").(string)
	if !ok {
		SendJSONError(w, http.StatusUnauthorized, errors.New("unauthorized"), "Authentication required")
		return
	}

	// Get short URL from path
	vars := mux.Vars(r)
	shortURL := vars["shortURL"]
	if shortURL == "" {
		SendJSONError(w, http.StatusBadRequest, errors.New("missing shortURL"), "Short URL is required")
		return
	}

	// Parse request body
	var req model.SetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendJSONError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Validate password using configured rules for URL protection
	if err := utils.ValidateURLPassword(req.Password, uh.config); err != nil {
		requirements := utils.GetPasswordRequirements(uh.config.Password.URL)
		SendJSONError(w, http.StatusBadRequest, err, "Password does not meet requirements: "+requirements)
		return
	}

	// Get URL from Redis
	urlData, err := uh.redis.Get(ctx, shortURL).Result()
	if err == redis.Nil {
		SendJSONError(w, http.StatusNotFound, errors.New("not found"), "URL not found")
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
		SendJSONError(w, http.StatusForbidden, errors.New("forbidden"), "You do not own this URL")
		return
	}

	// Hash password with bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg("Failed to hash password")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to set password")
		return
	}

	// Update URL with password hash
	urlObj.PasswordHash = string(hashedPassword)
	urlJSON, _ := json.Marshal(urlObj)
	if err := uh.redis.Set(ctx, shortURL, urlJSON, 0).Err(); err != nil {
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to update URL")
		return
	}

	log.Info().
		Str("shortURL", shortURL).
		Str("userID", userID).
		Msg("Password protection enabled")

	SendJSONSuccess(w, http.StatusOK, map[string]interface{}{
		"message":     "Password protection enabled",
		"shortURL":    shortURL,
		"isProtected": true,
	})
}

// RemoveURLPassword handles DELETE /api/user/url/{shortURL}/password
// @Summary Remove URL password
// @Description Remove password protection from a short URL (authenticated users only)
// @Tags User
// @Security BearerAuth
// @Produce json
// @Param shortURL path string true "Short URL"
// @Success 200 {object} map[string]interface{} "Password removed successfully"
// @Failure 401 {object} model.ErrorResponse "Not authenticated"
// @Failure 403 {object} model.ErrorResponse "Not authorized"
// @Failure 404 {object} model.ErrorResponse "URL not found"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /api/user/url/{shortURL}/password [delete]
func (uh *UserHandler) RemoveURLPassword(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get authenticated user ID
	userID, ok := r.Context().Value("userID").(string)
	if !ok {
		SendJSONError(w, http.StatusUnauthorized, errors.New("unauthorized"), "Authentication required")
		return
	}

	// Get short URL from path
	vars := mux.Vars(r)
	shortURL := vars["shortURL"]
	if shortURL == "" {
		SendJSONError(w, http.StatusBadRequest, errors.New("missing shortURL"), "Short URL is required")
		return
	}

	// Get URL from Redis
	urlData, err := uh.redis.Get(ctx, shortURL).Result()
	if err == redis.Nil {
		SendJSONError(w, http.StatusNotFound, errors.New("not found"), "URL not found")
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
		SendJSONError(w, http.StatusForbidden, errors.New("forbidden"), "You do not own this URL")
		return
	}

	// Remove password hash
	urlObj.PasswordHash = ""
	urlJSON, _ := json.Marshal(urlObj)
	if err := uh.redis.Set(ctx, shortURL, urlJSON, 0).Err(); err != nil {
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to update URL")
		return
	}

	// Clear all session cookies for this URL
	sessionPattern := fmt.Sprintf("password_session:%s:*", shortURL)
	keys, _ := uh.redis.Keys(ctx, sessionPattern).Result()
	if len(keys) > 0 {
		uh.redis.Del(ctx, keys...)
	}

	log.Info().
		Str("shortURL", shortURL).
		Str("userID", userID).
		Msg("Password protection removed")

	SendJSONSuccess(w, http.StatusOK, map[string]interface{}{
		"message":     "Password protection removed",
		"shortURL":    shortURL,
		"isProtected": false,
	})
}

// Helper function to get IP address from request
func getIPAddress(r *http.Request) string {
	// Check X-Forwarded-For header first (reverse proxy)
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		// Get first IP if multiple
		ips := r.Header.Get("X-Forwarded-For")
		if idx := len(ips); idx > 0 {
			return ips
		}
	}

	// Check X-Real-IP header
	ip = r.Header.Get("X-Real-IP")
	if ip != "" {
		return ip
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}
