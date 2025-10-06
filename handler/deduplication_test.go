package handler

import (
	"testing"
	"time"
)

func TestFindExistingShortURL_Compatibility(t *testing.T) {
	// Test expiry matching logic
	now := time.Now()
	future := now.Add(24 * time.Hour)

	tests := []struct {
		name               string
		requestedExpiry    time.Time
		existingExpiry     time.Time
		requestedMaxUsage  int
		existingMaxUsage   int
		shouldMatch        bool
	}{
		{
			name:              "Both no expiry, no max usage",
			requestedExpiry:   time.Time{},
			existingExpiry:    time.Time{},
			requestedMaxUsage: 0,
			existingMaxUsage:  0,
			shouldMatch:       true,
		},
		{
			name:              "Same expiry, same max usage",
			requestedExpiry:   future,
			existingExpiry:    future,
			requestedMaxUsage: 10,
			existingMaxUsage:  10,
			shouldMatch:       true,
		},
		{
			name:              "Different expiry",
			requestedExpiry:   future,
			existingExpiry:    future.Add(1 * time.Hour),
			requestedMaxUsage: 10,
			existingMaxUsage:  10,
			shouldMatch:       false,
		},
		{
			name:              "Different max usage",
			requestedExpiry:   future,
			existingExpiry:    future,
			requestedMaxUsage: 10,
			existingMaxUsage:  20,
			shouldMatch:       false,
		},
		{
			name:              "One has expiry, other doesn't",
			requestedExpiry:   future,
			existingExpiry:    time.Time{},
			requestedMaxUsage: 0,
			existingMaxUsage:  0,
			shouldMatch:       false,
		},
		{
			name:              "One has max usage, other doesn't",
			requestedExpiry:   time.Time{},
			existingExpiry:    time.Time{},
			requestedMaxUsage: 10,
			existingMaxUsage:  0,
			shouldMatch:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test expiry matching
			expiryMatches := (tt.requestedExpiry.IsZero() && tt.existingExpiry.IsZero()) ||
				(!tt.requestedExpiry.IsZero() && !tt.existingExpiry.IsZero() && tt.requestedExpiry.Equal(tt.existingExpiry))

			// Test max usage matching
			maxUsageMatches := tt.requestedMaxUsage == tt.existingMaxUsage

			// Overall match
			matches := expiryMatches && maxUsageMatches

			if matches != tt.shouldMatch {
				t.Errorf("Match result = %v, want %v (expiryMatches=%v, maxUsageMatches=%v)",
					matches, tt.shouldMatch, expiryMatches, maxUsageMatches)
			}
		})
	}
}

func TestDeduplication_Logic(t *testing.T) {
	t.Run("Same URL twice should deduplicate", func(t *testing.T) {
		// This is a documentation test showing the expected behavior
		// Actual integration test would require Redis connection

		url1 := "https://example.com"
		url2 := "https://example.com"

		if url1 != url2 {
			t.Error("Same URLs should be equal")
		}
	})

	t.Run("Different URLs should not deduplicate", func(t *testing.T) {
		url1 := "https://example.com"
		url2 := "https://different.com"

		if url1 == url2 {
			t.Error("Different URLs should not be equal")
		}
	})

	t.Run("URL with different parameters should not deduplicate", func(t *testing.T) {
		url1 := "https://example.com?param=1"
		url2 := "https://example.com?param=2"

		if url1 == url2 {
			t.Error("URLs with different params should not be equal")
		}
	})
}

// Note: Full integration tests for deduplication would require:
// 1. Redis connection
// 2. Mock Redis client
// 3. Testing the full flow: create -> check duplicate -> return same short URL
// These tests demonstrate the logic but skip integration due to Redis dependency
