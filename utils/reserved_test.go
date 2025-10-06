package utils

import "testing"

func TestIsReservedSlug(t *testing.T) {
	tests := []struct {
		name     string
		slug     string
		expected bool
	}{
		{"Reserved - health", "health", true},
		{"Reserved - HEALTH (uppercase)", "HEALTH", true},
		{"Reserved - Health (mixed case)", "Health", true},
		{"Reserved - admin", "admin", true},
		{"Reserved - api", "api", true},
		{"Reserved - shorten", "shorten", true},
		{"Reserved - qr", "qr", true},
		{"Not reserved - my-link", "my-link", false},
		{"Not reserved - custom123", "custom123", false},
		{"Not reserved - promo2024", "promo2024", false},
		{"Not reserved - health-check", "health-check", false}, // Contains reserved word but not exact match
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsReservedSlug(tt.slug)
			if result != tt.expected {
				t.Errorf("IsReservedSlug(%q) = %v, want %v", tt.slug, result, tt.expected)
			}
		})
	}
}
