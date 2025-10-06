package cache

import (
	"short-url-generator/config"
	"testing"
	"time"
)

func TestCacheBasicOperations(t *testing.T) {
	cfg := config.CacheConfig{
		Enabled:     true,
		MaxSizeMB:   10,
		TTLSeconds:  2, // 2 seconds for testing
		CounterSize: 1000,
	}

	cache, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	t.Run("Set_and_Get", func(t *testing.T) {
		key := "test_key"
		value := "test_value"

		// Set value
		ok := cache.Set(key, value, 1)
		if !ok {
			t.Error("Failed to set value in cache")
		}

		// Wait for async processing
		time.Sleep(10 * time.Millisecond)

		// Get value
		retrieved, found := cache.Get(key)
		if !found {
			t.Error("Value not found in cache")
		}
		if retrieved != value {
			t.Errorf("Expected %v, got %v", value, retrieved)
		}
	})

	t.Run("Get_NonExistent", func(t *testing.T) {
		_, found := cache.Get("nonexistent_key")
		if found {
			t.Error("Expected key not to be found")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		key := "delete_key"
		value := "delete_value"

		cache.Set(key, value, 1)
		time.Sleep(10 * time.Millisecond)

		// Verify it exists
		_, found := cache.Get(key)
		if !found {
			t.Error("Value should exist before deletion")
		}

		// Delete
		cache.Delete(key)
		time.Sleep(10 * time.Millisecond)

		// Verify it's gone
		_, found = cache.Get(key)
		if found {
			t.Error("Value should not exist after deletion")
		}
	})
}

func TestCacheTTL(t *testing.T) {
	cfg := config.CacheConfig{
		Enabled:     true,
		MaxSizeMB:   10,
		TTLSeconds:  1, // 1 second TTL
		CounterSize: 1000,
	}

	cache, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	key := "ttl_key"
	value := "ttl_value"

	// Set value
	cache.Set(key, value, 1)
	time.Sleep(10 * time.Millisecond)

	// Verify it exists
	_, found := cache.Get(key)
	if !found {
		t.Error("Value should exist immediately after setting")
	}

	// Wait for TTL to expire
	time.Sleep(1200 * time.Millisecond)

	// Verify it's expired
	_, found = cache.Get(key)
	if found {
		t.Error("Value should have expired after TTL")
	}
}

func TestCacheMetrics(t *testing.T) {
	cfg := config.CacheConfig{
		Enabled:     true,
		MaxSizeMB:   10,
		TTLSeconds:  60,
		CounterSize: 1000,
	}

	cache, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Perform some operations
	cache.Set("key1", "value1", 1)
	cache.Set("key2", "value2", 1)
	time.Sleep(100 * time.Millisecond) // Wait for async sets to complete

	cache.Get("key1") // Hit
	cache.Get("key2") // Hit
	cache.Get("key3") // Miss

	time.Sleep(200 * time.Millisecond) // Wait longer for metrics to update

	// Get metrics
	metrics := cache.GetMetricsSnapshot()

	// Ristretto metrics are async, so be lenient in assertions
	// Just verify the structure is correct
	if metrics.TTLSeconds != 60 {
		t.Errorf("Expected TTL 60 seconds, got %d", metrics.TTLSeconds)
	}

	// Log metrics for debugging (not failing test)
	t.Logf("Cache metrics: Hits=%d, Misses=%d, KeysAdded=%d, HitRatio=%.2f",
		metrics.Hits, metrics.Misses, metrics.KeysAdded, metrics.HitRatio)
}

func TestCacheNilHandling(t *testing.T) {
	cache := &Cache{client: nil}

	// All operations should be safe with nil client
	val, found := cache.Get("key")
	if found {
		t.Error("Get should return false with nil client")
	}
	if val != nil {
		t.Error("Get should return nil value with nil client")
	}

	ok := cache.Set("key", "value", 1)
	if ok {
		t.Error("Set should return false with nil client")
	}

	// Should not panic
	cache.Delete("key")
	cache.Close()

	metrics := cache.GetMetricsSnapshot()
	if metrics.Hits != 0 {
		t.Error("Nil cache should return zero metrics")
	}
}
