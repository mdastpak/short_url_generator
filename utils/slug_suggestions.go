package utils

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

// GenerateSlugSuggestions generates alternative slug suggestions when the requested slug is taken
// It tries multiple strategies:
// 1. Numeric suffixes: my-link-2, my-link-3, my-link-4
// 2. Random suffixes: my-link-x7, my-link-x9
// Returns only available (non-taken) slugs up to maxSuggestions
func GenerateSlugSuggestions(ctx context.Context, redisClient *redis.Client, baseSlug string, maxSuggestions int) []string {
	if maxSuggestions <= 0 {
		maxSuggestions = 3 // Default to 3 suggestions
	}

	suggestions := make([]string, 0, maxSuggestions)
	slugLower := strings.ToLower(baseSlug)

	// Strategy 1: Numeric suffixes (my-link-2, my-link-3, ...)
	for i := 2; i <= maxSuggestions+5 && len(suggestions) < maxSuggestions; i++ {
		candidate := fmt.Sprintf("%s-%d", slugLower, i)
		if isSlugAvailable(ctx, redisClient, candidate) {
			suggestions = append(suggestions, candidate)
		}
	}

	// Strategy 2: Random suffixes (my-link-x7, my-link-x9, ...)
	// Only try this if we don't have enough suggestions yet
	for attempt := 0; attempt < 10 && len(suggestions) < maxSuggestions; attempt++ {
		randomSuffix := rng.Intn(90) + 10 // Random number 10-99
		candidate := fmt.Sprintf("%s-x%d", slugLower, randomSuffix)
		if isSlugAvailable(ctx, redisClient, candidate) {
			// Check if we already added this (unlikely but possible)
			if !contains(suggestions, candidate) {
				suggestions = append(suggestions, candidate)
			}
		}
	}

	// Strategy 3: Fallback - timestamp-based suffix
	// Only use if we still don't have enough suggestions
	if len(suggestions) < maxSuggestions {
		timestamp := time.Now().Unix() % 10000 // Last 4 digits
		candidate := fmt.Sprintf("%s-%d", slugLower, timestamp)
		if isSlugAvailable(ctx, redisClient, candidate) && !contains(suggestions, candidate) {
			suggestions = append(suggestions, candidate)
		}
	}

	return suggestions
}

// isSlugAvailable checks if a slug is available (not taken in Redis)
func isSlugAvailable(ctx context.Context, redisClient *redis.Client, slug string) bool {
	exists, err := redisClient.Exists(ctx, slug).Result()
	if err != nil {
		// If Redis error, assume not available to be safe
		return false
	}
	return exists == 0
}

// contains checks if a slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
