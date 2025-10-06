package utils

import (
	"context"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
)

func setupTestRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	s, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}

	client := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	return client, s
}

func TestGenerateSlugSuggestions_AllAvailable(t *testing.T) {
	client, s := setupTestRedis(t)
	defer s.Close()
	defer client.Close()

	ctx := context.Background()

	// Test generating suggestions when all are available
	suggestions := GenerateSlugSuggestions(ctx, client, "my-link", 3)

	if len(suggestions) != 3 {
		t.Errorf("Expected 3 suggestions, got %d", len(suggestions))
	}

	// Should get numeric suggestions first: my-link-2, my-link-3, my-link-4
	expectedSuggestions := []string{"my-link-2", "my-link-3", "my-link-4"}
	for i, expected := range expectedSuggestions {
		if i >= len(suggestions) {
			break
		}
		if suggestions[i] != expected {
			t.Errorf("Expected suggestion[%d] = %s, got %s", i, expected, suggestions[i])
		}
	}
}

func TestGenerateSlugSuggestions_SomeTaken(t *testing.T) {
	client, s := setupTestRedis(t)
	defer s.Close()
	defer client.Close()

	ctx := context.Background()

	// Pre-populate some slugs as taken
	client.Set(ctx, "my-link-2", "taken", 0)
	client.Set(ctx, "my-link-3", "taken", 0)

	suggestions := GenerateSlugSuggestions(ctx, client, "my-link", 3)

	if len(suggestions) != 3 {
		t.Errorf("Expected 3 suggestions, got %d", len(suggestions))
	}

	// Should skip taken slugs and continue with my-link-4, my-link-5, my-link-6
	for _, suggestion := range suggestions {
		if suggestion == "my-link-2" || suggestion == "my-link-3" {
			t.Errorf("Generated a taken slug: %s", suggestion)
		}
	}
}

func TestGenerateSlugSuggestions_MaxSuggestions(t *testing.T) {
	client, s := setupTestRedis(t)
	defer s.Close()
	defer client.Close()

	ctx := context.Background()

	// Test with different maxSuggestions values
	testCases := []struct {
		name           string
		maxSuggestions int
		expectedCount  int
	}{
		{"Default (3)", 3, 3},
		{"One suggestion", 1, 1},
		{"Five suggestions", 5, 5},
		{"Zero (should default to 3)", 0, 3},
		{"Negative (should default to 3)", -1, 3},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			suggestions := GenerateSlugSuggestions(ctx, client, "test-slug", tc.maxSuggestions)
			if len(suggestions) != tc.expectedCount {
				t.Errorf("Expected %d suggestions, got %d", tc.expectedCount, len(suggestions))
			}
		})
	}
}

func TestGenerateSlugSuggestions_EmptySlug(t *testing.T) {
	client, s := setupTestRedis(t)
	defer s.Close()
	defer client.Close()

	ctx := context.Background()

	// Test with empty slug (edge case)
	suggestions := GenerateSlugSuggestions(ctx, client, "", 3)

	if len(suggestions) == 0 {
		t.Skip("Empty slug returns no suggestions (expected behavior)")
	}

	// Should still generate suggestions like "-2", "-3", "-4"
	for _, suggestion := range suggestions {
		if suggestion == "" {
			t.Error("Generated empty suggestion")
		}
	}
}

func TestGenerateSlugSuggestions_CaseInsensitive(t *testing.T) {
	client, s := setupTestRedis(t)
	defer s.Close()
	defer client.Close()

	ctx := context.Background()

	// Test that suggestions are generated in lowercase
	suggestions := GenerateSlugSuggestions(ctx, client, "My-Link", 3)

	for _, suggestion := range suggestions {
		if suggestion != strings.ToLower(suggestion) {
			t.Errorf("Expected lowercase suggestion, got: %s", suggestion)
		}
	}
}

func TestGenerateSlugSuggestions_NoDuplicates(t *testing.T) {
	client, s := setupTestRedis(t)
	defer s.Close()
	defer client.Close()

	ctx := context.Background()

	// Generate a larger set of suggestions
	suggestions := GenerateSlugSuggestions(ctx, client, "test", 10)

	// Check for duplicates
	seen := make(map[string]bool)
	for _, suggestion := range suggestions {
		if seen[suggestion] {
			t.Errorf("Duplicate suggestion found: %s", suggestion)
		}
		seen[suggestion] = true
	}
}

func TestIsSlugAvailable(t *testing.T) {
	client, s := setupTestRedis(t)
	defer s.Close()
	defer client.Close()

	ctx := context.Background()

	// Test available slug
	if !isSlugAvailable(ctx, client, "available-slug") {
		t.Error("Expected slug to be available")
	}

	// Set a slug and test that it's not available
	client.Set(ctx, "taken-slug", "value", 0)
	if isSlugAvailable(ctx, client, "taken-slug") {
		t.Error("Expected slug to be unavailable")
	}
}

func TestContains(t *testing.T) {
	testCases := []struct {
		name     string
		slice    []string
		item     string
		expected bool
	}{
		{"Contains item", []string{"a", "b", "c"}, "b", true},
		{"Does not contain item", []string{"a", "b", "c"}, "d", false},
		{"Empty slice", []string{}, "a", false},
		{"Single item - match", []string{"a"}, "a", true},
		{"Single item - no match", []string{"a"}, "b", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := contains(tc.slice, tc.item)
			if result != tc.expected {
				t.Errorf("contains(%v, %s) = %v, want %v", tc.slice, tc.item, result, tc.expected)
			}
		})
	}
}
