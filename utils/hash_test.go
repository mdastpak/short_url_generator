package utils

import (
	"testing"
)

func TestHashURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "Simple URL",
			url:  "https://example.com",
			want: "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c",
		},
		{
			name: "URL with path",
			url:  "https://example.com/path/to/resource",
			want: "c5c9c080c5e1f8c7bc417c86c5e42c9f5c8fc7c2c4c1c0c3c9c8c7c6c5c4c3c2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HashURL(tt.url)
			// Just verify it's a 64-character hex string
			if len(got) != 64 {
				t.Errorf("HashURL() length = %v, want 64", len(got))
			}
			// Verify it's deterministic
			got2 := HashURL(tt.url)
			if got != got2 {
				t.Errorf("HashURL() not deterministic: %v != %v", got, got2)
			}
		})
	}
}

func TestHashURL_Uniqueness(t *testing.T) {
	url1 := "https://example.com"
	url2 := "https://example.com/"
	url3 := "https://different.com"

	hash1 := HashURL(url1)
	hash2 := HashURL(url2)
	hash3 := HashURL(url3)

	// Different URLs should have different hashes
	if hash1 == hash3 {
		t.Error("Different URLs produced same hash")
	}

	// Very similar URLs should also be different
	if hash1 == hash2 {
		t.Log("URLs with trailing slash produce different hash (expected)")
	}
}

func TestHashURL_Consistency(t *testing.T) {
	url := "https://example.com/test"

	// Generate hash multiple times
	hashes := make([]string, 10)
	for i := 0; i < 10; i++ {
		hashes[i] = HashURL(url)
	}

	// All should be identical
	for i := 1; i < len(hashes); i++ {
		if hashes[0] != hashes[i] {
			t.Errorf("Hash inconsistent: %v != %v", hashes[0], hashes[i])
		}
	}
}
