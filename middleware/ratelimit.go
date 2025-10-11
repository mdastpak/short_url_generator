package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

// RateLimiter implements per-IP rate limiting
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	r        rate.Limit
	b        int
	redis    *redis.Client
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requestsPerSecond float64, burst int, rdb *redis.Client) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		r:        rate.Limit(requestsPerSecond),
		b:        burst,
		redis:    rdb,
	}
}

// getLimiter returns the rate limiter for a given IP
func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.r, rl.b)
		rl.limiters[ip] = limiter
	}

	return limiter
}

// Limit is a middleware that rate limits requests
func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client IP
		ip := r.RemoteAddr

		// Get limiter for this IP
		limiter := rl.getLimiter(ip)

		// Check if request is allowed
		if !limiter.Allow() {
			log.Warn().
				Str("ip", ip).
				Str("path", r.URL.Path).
				Msg("Rate limit exceeded")

			// Track rate limit violation in Redis
			if rl.redis != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				// Increment total rate limit violations counter
				rl.redis.Incr(ctx, "security:rate_limit_violations")

				// Add to timeline for 24h tracking
				now := time.Now().Unix()
				rl.redis.ZAdd(ctx, "security:rate_limit_timeline", &redis.Z{
					Score:  float64(now),
					Member: ip,
				})

				// Track IP in blocked IPs
				rl.redis.ZIncrBy(ctx, "security:blocked_ips", 1, ip)

				// Track block reason
				rl.redis.ZIncrBy(ctx, "security:block_reasons", 1, "rate_limit_exceeded")
			}

			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error": "Rate limit exceeded. Please try again later."}`, http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
