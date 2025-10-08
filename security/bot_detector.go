package security

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// BotDetector provides bot detection functionality
type BotDetector struct {
	// Request tracking for rate-based detection
	requestTracker map[string]*requestHistory
	mu             sync.RWMutex

	// Configuration
	maxRequestsPerMinute int
	cleanupInterval      time.Duration
}

// requestHistory tracks request history for an IP
type requestHistory struct {
	requests  []time.Time
	lastSeen  time.Time
	userAgent string
}

// NewBotDetector creates a new bot detector instance
func NewBotDetector(maxRequestsPerMinute int) *BotDetector {
	bd := &BotDetector{
		requestTracker:       make(map[string]*requestHistory),
		maxRequestsPerMinute: maxRequestsPerMinute,
		cleanupInterval:      5 * time.Minute,
	}

	// Start cleanup goroutine
	go bd.cleanupOldEntries()

	return bd
}

// IsBot checks if a request appears to be from a bot
func (bd *BotDetector) IsBot(r *http.Request) (bool, string) {
	userAgent := r.UserAgent()
	ip := getClientIP(r)

	// Check known bot user agents
	if isKnownBot := bd.checkKnownBotUserAgent(userAgent); isKnownBot {
		return true, "known_bot_user_agent"
	}

	// Check suspicious user agents
	if isSuspicious := bd.checkSuspiciousUserAgent(userAgent); isSuspicious {
		return true, "suspicious_user_agent"
	}

	// Check request rate
	if isRateLimited := bd.checkRequestRate(ip, userAgent); isRateLimited {
		return true, "excessive_request_rate"
	}

	return false, ""
}

// checkKnownBotUserAgent checks if user agent is a known bot
func (bd *BotDetector) checkKnownBotUserAgent(userAgent string) bool {
	userAgentLower := strings.ToLower(userAgent)

	// List of known legitimate bots (allow these)
	legitimateBots := []string{
		"googlebot",
		"bingbot",
		"slackbot",
		"twitterbot",
		"facebookexternalhit",
		"linkedinbot",
		"whatsapp",
		"telegrambot",
		"discordbot",
	}

	for _, bot := range legitimateBots {
		if strings.Contains(userAgentLower, bot) {
			log.Debug().Str("user_agent", userAgent).Str("bot", bot).Msg("Legitimate bot detected")
			return false // Allow legitimate bots
		}
	}

	// Check for known malicious bot patterns
	maliciousBots := []string{
		"bot",
		"crawler",
		"spider",
		"scraper",
		"curl",
		"wget",
		"python-requests",
		"go-http-client",
		"java/",
		"ruby",
		"php",
		"perl",
		"node-fetch",
		"axios",
	}

	for _, pattern := range maliciousBots {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}

	return false
}

// checkSuspiciousUserAgent checks for suspicious user agent patterns
func (bd *BotDetector) checkSuspiciousUserAgent(userAgent string) bool {
	// Empty or very short user agent
	if len(userAgent) < 10 {
		return true
	}

	// Missing common browser indicators
	hasCommonBrowser := strings.Contains(userAgent, "Mozilla") ||
		strings.Contains(userAgent, "Chrome") ||
		strings.Contains(userAgent, "Safari") ||
		strings.Contains(userAgent, "Firefox") ||
		strings.Contains(userAgent, "Edge") ||
		strings.Contains(userAgent, "Opera")

	// If it doesn't have common browser strings and isn't empty, it's suspicious
	if !hasCommonBrowser && len(userAgent) > 0 {
		userAgentLower := strings.ToLower(userAgent)

		// Unless it's a known legitimate service
		legitimateServices := []string{
			"bot", "crawler", "spider", // We handle these separately
			"monitor", "uptime", "pingdom", "statuspage",
		}

		for _, service := range legitimateServices {
			if strings.Contains(userAgentLower, service) {
				return false
			}
		}

		return true
	}

	return false
}

// checkRequestRate checks if IP is making too many requests
func (bd *BotDetector) checkRequestRate(ip, userAgent string) bool {
	bd.mu.Lock()
	defer bd.mu.Unlock()

	now := time.Now()
	oneMinuteAgo := now.Add(-1 * time.Minute)

	history, exists := bd.requestTracker[ip]
	if !exists {
		// First request from this IP
		bd.requestTracker[ip] = &requestHistory{
			requests:  []time.Time{now},
			lastSeen:  now,
			userAgent: userAgent,
		}
		return false
	}

	// Filter out requests older than 1 minute
	recentRequests := []time.Time{}
	for _, reqTime := range history.requests {
		if reqTime.After(oneMinuteAgo) {
			recentRequests = append(recentRequests, reqTime)
		}
	}

	// Add current request
	recentRequests = append(recentRequests, now)
	history.requests = recentRequests
	history.lastSeen = now
	history.userAgent = userAgent

	// Check if rate limit exceeded
	if len(recentRequests) > bd.maxRequestsPerMinute {
		log.Warn().
			Str("ip", ip).
			Str("user_agent", userAgent).
			Int("requests", len(recentRequests)).
			Msg("Request rate limit exceeded - potential bot")
		return true
	}

	return false
}

// cleanupOldEntries periodically removes old tracking entries
func (bd *BotDetector) cleanupOldEntries() {
	ticker := time.NewTicker(bd.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		bd.mu.Lock()

		cutoff := time.Now().Add(-10 * time.Minute)
		for ip, history := range bd.requestTracker {
			if history.lastSeen.Before(cutoff) {
				delete(bd.requestTracker, ip)
			}
		}

		bd.mu.Unlock()

		log.Debug().Int("tracked_ips", len(bd.requestTracker)).Msg("Cleaned up bot detection tracker")
	}
}

// getClientIP extracts client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies/load balancers)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take the first IP if there are multiple
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Remove port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	return ip
}

// AllowBot allows a specific user agent pattern
func (bd *BotDetector) AllowBot(pattern string) {
	// This could be implemented to maintain a whitelist
	log.Info().Str("pattern", pattern).Msg("Bot pattern allowed")
}

// GetStats returns bot detection statistics
func (bd *BotDetector) GetStats() map[string]interface{} {
	bd.mu.RLock()
	defer bd.mu.RUnlock()

	return map[string]interface{}{
		"tracked_ips":            len(bd.requestTracker),
		"max_requests_per_minute": bd.maxRequestsPerMinute,
	}
}
