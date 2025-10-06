package cache

import (
	"short-url-generator/config"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/rs/zerolog/log"
)

// Cache wraps Ristretto cache with URL shortener specific methods
type Cache struct {
	client *ristretto.Cache
	ttl    time.Duration
}

// New creates a new cache instance with the given configuration
func New(cfg config.CacheConfig) (*Cache, error) {
	// Calculate max cost in bytes (convert MB to bytes)
	maxCost := int64(cfg.MaxSizeMB) * 1024 * 1024

	// Initialize Ristretto with configuration
	client, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: int64(cfg.CounterSize), // Number of keys to track frequency for admission
		MaxCost:     maxCost,                 // Maximum cache size in bytes
		BufferItems: 64,                      // Number of keys per Get buffer
	})
	if err != nil {
		return nil, err
	}

	log.Info().
		Int("max_size_mb", cfg.MaxSizeMB).
		Int("ttl_seconds", cfg.TTLSeconds).
		Int("counter_size", cfg.CounterSize).
		Msg("Cache initialized successfully")

	return &Cache{
		client: client,
		ttl:    time.Duration(cfg.TTLSeconds) * time.Second,
	}, nil
}

// Get retrieves a value from the cache
// Returns (value, true) if found, (nil, false) if not found
func (c *Cache) Get(key string) (interface{}, bool) {
	if c.client == nil {
		return nil, false
	}
	return c.client.Get(key)
}

// Set stores a value in the cache with the configured TTL
// cost parameter represents the memory cost of the item (use 1 for simple items)
func (c *Cache) Set(key string, value interface{}, cost int64) bool {
	if c.client == nil {
		return false
	}
	return c.client.SetWithTTL(key, value, cost, c.ttl)
}

// Delete removes a key from the cache
func (c *Cache) Delete(key string) {
	if c.client == nil {
		return
	}
	c.client.Del(key)
}

// Close cleanly shuts down the cache
func (c *Cache) Close() {
	if c.client != nil {
		c.client.Close()
		log.Info().Msg("Cache closed")
	}
}

// Metrics returns cache performance metrics
func (c *Cache) Metrics() *ristretto.Metrics {
	if c.client == nil {
		return nil
	}
	return c.client.Metrics
}

// GetMetricsSnapshot returns a snapshot of cache metrics
type MetricsSnapshot struct {
	Hits              uint64  `json:"hits"`
	Misses            uint64  `json:"misses"`
	KeysAdded         uint64  `json:"keys_added"`
	KeysEvicted       uint64  `json:"keys_evicted"`
	CostAdded         uint64  `json:"cost_added"`
	CostEvicted       uint64  `json:"cost_evicted"`
	SetsDropped       uint64  `json:"sets_dropped"`
	SetsRejected      uint64  `json:"sets_rejected"`
	GetsDropped       uint64  `json:"gets_dropped"`
	HitRatio          float64 `json:"hit_ratio"`
	TTLSeconds        int     `json:"ttl_seconds"`
}

// GetMetricsSnapshot returns current cache metrics as a snapshot
func (c *Cache) GetMetricsSnapshot() MetricsSnapshot {
	if c.client == nil || c.client.Metrics == nil {
		return MetricsSnapshot{TTLSeconds: int(c.ttl.Seconds())}
	}

	m := c.client.Metrics
	hits := m.Hits()
	misses := m.Misses()
	total := hits + misses

	hitRatio := 0.0
	if total > 0 {
		hitRatio = float64(hits) / float64(total)
	}

	return MetricsSnapshot{
		Hits:         hits,
		Misses:       misses,
		KeysAdded:    m.KeysAdded(),
		KeysEvicted:  m.KeysEvicted(),
		CostAdded:    m.CostAdded(),
		CostEvicted:  m.CostEvicted(),
		SetsDropped:  m.SetsDropped(),
		SetsRejected: m.SetsRejected(),
		GetsDropped:  m.GetsDropped(),
		HitRatio:     hitRatio,
		TTLSeconds:   int(c.ttl.Seconds()),
	}
}
