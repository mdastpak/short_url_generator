package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"short-url-generator/security"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
)

// BotProtection is a middleware that blocks suspected bots
type BotProtection struct {
	detector *security.BotDetector
	enabled  bool
	redis    *redis.Client
}

// NewBotProtection creates a new bot protection middleware
func NewBotProtection(maxRequestsPerMinute int, enabled bool, rdb *redis.Client) *BotProtection {
	return &BotProtection{
		detector: security.NewBotDetector(maxRequestsPerMinute),
		enabled:  enabled,
		redis:    rdb,
	}
}

// Protect returns a middleware function that blocks bots
func (bp *BotProtection) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip bot detection if disabled
		if !bp.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Check if request is from a bot
		isBot, reason := bp.detector.IsBot(r)

		if isBot {
			log.Warn().
				Str("ip", r.RemoteAddr).
				Str("user_agent", r.UserAgent()).
				Str("reason", reason).
				Str("path", r.URL.Path).
				Msg("Bot detected - request blocked")

			// Track bot detection in Redis
			if bp.redis != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				// Increment total bot detection counter
				bp.redis.Incr(ctx, "security:bot_detections")

				// Add to timeline for 24h tracking (sorted set with current timestamp as score)
				now := time.Now().Unix()
				bp.redis.ZAdd(ctx, "security:bot_detections_timeline", &redis.Z{
					Score:  float64(now),
					Member: r.RemoteAddr,
				})

				// Track IP in blocked IPs (sorted set with count as score)
				bp.redis.ZIncrBy(ctx, "security:blocked_ips", 1, r.RemoteAddr)

				// Track block reason (sorted set with count as score)
				bp.redis.ZIncrBy(ctx, "security:block_reasons", 1, reason)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)

			response := map[string]interface{}{
				"error":   "Bot detected",
				"message": "This request appears to be automated. If you believe this is an error, please contact support.",
				"reason":  reason,
			}

			json.NewEncoder(w).Encode(response)
			return
		}

		// Allow request to proceed
		next.ServeHTTP(w, r)
	})
}

// GetStats returns bot detection statistics
func (bp *BotProtection) GetStats() map[string]interface{} {
	return bp.detector.GetStats()
}
