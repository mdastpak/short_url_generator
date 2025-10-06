package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"short-url-generator/model"
	"short-url-generator/utils"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

// UpdateURLRequest represents the request body for updating a URL
type UpdateURLRequest struct {
	OriginalURL    string `json:"originalURL"`
	ShortURL       string `json:"shortURL"`
	NewOriginalURL string `json:"newOriginalURL"`
}

// DeleteURLRequest represents the request body for deleting a URL
type DeleteURLRequest struct {
	OriginalURL string `json:"originalURL"`
	ShortURL    string `json:"shortURL"`
}

// UpdateURL handles PUT /shorten/{managementID} - updates the originalURL of a shortened URL
func (h *URLHandler) UpdateURL(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	managementID := vars["managementID"]

	if managementID == "" {
		SendJSONError(w, http.StatusBadRequest, errors.New("missing managementID"), "Management ID is required")
		return
	}

	// Parse request body
	var input UpdateURLRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		SendJSONError(w, http.StatusBadRequest, err, "Invalid JSON format")
		return
	}

	// Validate required fields
	if input.OriginalURL == "" || input.ShortURL == "" || input.NewOriginalURL == "" {
		SendJSONError(w, http.StatusBadRequest, errors.New("missing required fields"), "originalURL, shortURL, and newOriginalURL are required")
		return
	}

	// Validate new original URL
	if err := utils.ValidateURL(input.NewOriginalURL); err != nil {
		SendJSONError(w, http.StatusBadRequest, err, "Invalid new original URL")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.Redis.OperationTimeout)*time.Second)
	defer cancel()

	// Lookup shortURL from management index
	storedShortURL, err := h.redis.HGet(ctx, managementIndexKey, managementID).Result()
	if err != nil {
		log.Error().Err(err).Str("managementID", managementID).Msg("Management ID not found")
		SendJSONError(w, http.StatusNotFound, errors.New("management ID not found"), "Invalid management ID")
		return
	}

	// Verify shortURL matches
	if storedShortURL != input.ShortURL {
		log.Warn().Str("managementID", managementID).Str("providedShortURL", input.ShortURL).Str("storedShortURL", storedShortURL).Msg("Short URL mismatch")
		SendJSONError(w, http.StatusForbidden, errors.New("validation failed"), "Short URL does not match management ID")
		return
	}

	// Fetch the current URL data
	urlData, err := h.redis.Get(ctx, input.ShortURL).Result()
	if err != nil {
		log.Error().Err(err).Str("shortURL", input.ShortURL).Msg("Failed to fetch URL data")
		SendJSONError(w, http.StatusNotFound, errors.New("URL not found"), "Short URL does not exist")
		return
	}

	var url model.URL
	if err := json.Unmarshal([]byte(urlData), &url); err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal URL data")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to parse URL data")
		return
	}

	// Verify original URL matches
	if url.OriginalURL != input.OriginalURL {
		log.Warn().Str("managementID", managementID).Str("providedOriginalURL", input.OriginalURL).Str("storedOriginalURL", url.OriginalURL).Msg("Original URL mismatch")
		SendJSONError(w, http.StatusForbidden, errors.New("validation failed"), "Original URL does not match")
		return
	}

	// Remove old deduplication index entry (if enabled)
	if h.config.Features.DeduplicationEnabled {
		oldHash := utils.HashURL(url.OriginalURL)
		if err := h.redis.HDel(ctx, urlIndexKey, oldHash).Err(); err != nil {
			log.Error().Err(err).Str("oldHash", oldHash).Msg("Failed to remove old deduplication index entry")
		}
	}

	// Update the original URL
	url.OriginalURL = input.NewOriginalURL

	// Marshal and save updated URL
	updatedData, err := json.Marshal(url)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal updated URL")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to save updated URL")
		return
	}

	// Calculate TTL for the key
	var ttl time.Duration
	if !url.Expiry.IsZero() {
		ttl = time.Until(url.Expiry)
		if ttl < 0 {
			SendJSONError(w, http.StatusGone, errors.New("URL has expired"), "Cannot update expired URL")
			return
		}
	}

	// Save to Redis
	if ttl > 0 {
		err = h.redis.Set(ctx, input.ShortURL, updatedData, ttl).Err()
	} else {
		err = h.redis.Set(ctx, input.ShortURL, updatedData, 0).Err()
	}

	if err != nil {
		log.Error().Err(err).Msg("Failed to update URL in Redis")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to update URL")
		return
	}

	// Add new deduplication index entry (if enabled)
	if h.config.Features.DeduplicationEnabled {
		newHash := utils.HashURL(url.OriginalURL)
		if err := h.redis.HSet(ctx, urlIndexKey, newHash, input.ShortURL).Err(); err != nil {
			log.Error().Err(err).Str("newHash", newHash).Msg("Failed to add new deduplication index entry")
		}
	}

	// Invalidate cache
	if h.cache != nil {
		h.cache.Delete(input.ShortURL)
		log.Debug().Str("shortURL", input.ShortURL).Msg("Cache invalidated after update")
	}

	log.Info().
		Str("managementID", managementID).
		Str("shortURL", input.ShortURL).
		Str("oldURL", input.OriginalURL).
		Str("newURL", input.NewOriginalURL).
		Msg("URL updated successfully")

	// Return updated data
	response := SuccessResponse{
		OriginalURL:  url.OriginalURL,
		ShortURL:     input.ShortURL,
		ManagementID: managementID,
	}

	SendJSONSuccess(w, http.StatusOK, response)
}

// DeleteURL handles DELETE /shorten/{managementID} - deletes a shortened URL
func (h *URLHandler) DeleteURL(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	managementID := vars["managementID"]

	if managementID == "" {
		SendJSONError(w, http.StatusBadRequest, errors.New("missing managementID"), "Management ID is required")
		return
	}

	// Parse request body
	var input DeleteURLRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		SendJSONError(w, http.StatusBadRequest, err, "Invalid JSON format")
		return
	}

	// Validate required fields
	if input.OriginalURL == "" || input.ShortURL == "" {
		SendJSONError(w, http.StatusBadRequest, errors.New("missing required fields"), "originalURL and shortURL are required for validation")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.Redis.OperationTimeout)*time.Second)
	defer cancel()

	// Lookup shortURL from management index
	storedShortURL, err := h.redis.HGet(ctx, managementIndexKey, managementID).Result()
	if err != nil {
		log.Error().Err(err).Str("managementID", managementID).Msg("Management ID not found")
		SendJSONError(w, http.StatusNotFound, errors.New("management ID not found"), "Invalid management ID")
		return
	}

	// Verify shortURL matches (validation 1/3)
	if storedShortURL != input.ShortURL {
		log.Warn().Str("managementID", managementID).Str("providedShortURL", input.ShortURL).Str("storedShortURL", storedShortURL).Msg("Short URL mismatch")
		SendJSONError(w, http.StatusForbidden, errors.New("validation failed"), "Short URL does not match management ID")
		return
	}

	// Fetch the current URL data
	urlData, err := h.redis.Get(ctx, input.ShortURL).Result()
	if err != nil {
		log.Error().Err(err).Str("shortURL", input.ShortURL).Msg("Failed to fetch URL data")
		SendJSONError(w, http.StatusNotFound, errors.New("URL not found"), "Short URL does not exist")
		return
	}

	var url model.URL
	if err := json.Unmarshal([]byte(urlData), &url); err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal URL data")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to parse URL data")
		return
	}

	// Verify original URL matches (validation 2/3)
	if url.OriginalURL != input.OriginalURL {
		log.Warn().Str("managementID", managementID).Str("providedOriginalURL", input.OriginalURL).Str("storedOriginalURL", url.OriginalURL).Msg("Original URL mismatch")
		SendJSONError(w, http.StatusForbidden, errors.New("validation failed"), "Original URL does not match")
		return
	}

	// All 3 validations passed (managementID + shortURL + originalURL)
	// Now proceed with deletion

	// Delete from Redis
	if err := h.redis.Del(ctx, input.ShortURL).Err(); err != nil {
		log.Error().Err(err).Str("shortURL", input.ShortURL).Msg("Failed to delete URL from Redis")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to delete URL")
		return
	}

	// Delete from management index
	if err := h.redis.HDel(ctx, managementIndexKey, managementID).Err(); err != nil {
		log.Error().Err(err).Str("managementID", managementID).Msg("Failed to delete from management index")
	}

	// Delete from deduplication index (if enabled)
	if h.config.Features.DeduplicationEnabled {
		hash := utils.HashURL(url.OriginalURL)
		if err := h.redis.HDel(ctx, urlIndexKey, hash).Err(); err != nil {
			log.Error().Err(err).Str("hash", hash).Msg("Failed to delete from deduplication index")
		}
	}

	// Invalidate cache
	if h.cache != nil {
		h.cache.Delete(input.ShortURL)
		log.Debug().Str("shortURL", input.ShortURL).Msg("Cache invalidated after deletion")
	}

	log.Info().
		Str("managementID", managementID).
		Str("shortURL", input.ShortURL).
		Str("originalURL", input.OriginalURL).
		Msg("URL deleted successfully")

	// Return 204 No Content
	w.WriteHeader(http.StatusNoContent)
}
