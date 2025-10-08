package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"short-url-generator/cache"
	"short-url-generator/config"
	_ "short-url-generator/docs" // Swagger docs
	"short-url-generator/handler"
	appLogger "short-url-generator/logger"
	"short-url-generator/middleware"
	redisClient "short-url-generator/redis"
	"short-url-generator/security"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	httpSwagger "github.com/swaggo/http-swagger"
)

// @title Short URL Generator API
// @version 2.0
// @description Production-ready URL shortening service with Redis persistence, caching, rate limiting, and comprehensive management features.
// @termsOfService https://github.com/yourusername/short-url-generator

// @contact.name API Support
// @contact.url https://github.com/yourusername/short-url-generator/issues
// @contact.email support@example.com

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /
// @schemes http https

// @tag.name URLs
// @tag.description Operations for creating, redirecting, and managing short URLs

// @tag.name Management
// @tag.description Secure operations for updating and deleting short URLs (requires managementID)

// @tag.name System
// @tag.description Health checks and system metrics

func main() {
	// Initialize logger
	appLogger.Initialize()

	// Load configuration
	cfg := config.MustLoadConfig()
	log.Info().Msg("Configuration loaded successfully")

	// Initialize Redis client
	rdb := redisClient.NewClient(cfg.Redis)

	// Initialize cache (if enabled)
	var cacheClient *cache.Cache
	if cfg.Cache.Enabled {
		var err error
		cacheClient, err = cache.New(cfg.Cache)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to initialize cache")
		}
	} else {
		log.Info().Msg("Cache disabled in configuration")
	}

	// Initialize URL scanner for malware/phishing detection
	urlScanner := security.NewURLScanner(
		cfg.Security.SafeBrowsingAPIKey,
		cfg.Security.BlocklistEnabled,
	)
	log.Info().
		Bool("url_scanning_enabled", cfg.Security.URLScanningEnabled).
		Bool("blocklist_enabled", cfg.Security.BlocklistEnabled).
		Bool("safe_browsing_enabled", cfg.Security.SafeBrowsingAPIKey != "").
		Msg("URL security scanner initialized")

	// Create handler with dependency injection
	urlHandler := handler.NewURLHandler(rdb, cacheClient, cfg, urlScanner)

	// Set up router
	r := mux.NewRouter()

	// Apply global middleware
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimit.RequestsPerSecond, cfg.RateLimit.Burst)
	botProtection := middleware.NewBotProtection(cfg.Security.BotMaxRequestsPerMinute, cfg.Security.BotDetectionEnabled)

	r.Use(middleware.CORS)
	r.Use(middleware.RequestLogger)
	r.Use(rateLimiter.Limit)
	r.Use(botProtection.Protect) // Bot detection middleware

	// Register routes
	r.HandleFunc("/health", urlHandler.HealthCheck).Methods("GET")
	r.HandleFunc("/cache/metrics", urlHandler.CacheMetrics).Methods("GET")
	r.HandleFunc("/shorten", urlHandler.CreateShortURL).Methods("POST")
	r.HandleFunc("/shorten/{managementID}", urlHandler.UpdateURL).Methods("PUT")
	r.HandleFunc("/shorten/{managementID}", urlHandler.DeleteURL).Methods("DELETE")
	r.HandleFunc("/qr/{shortURL}", urlHandler.GenerateQR).Methods("GET")      // QR code generation
	r.HandleFunc("/preview/{shortURL}", urlHandler.ShowPreview).Methods("GET") // URL preview (anti-phishing)

	// Swagger UI
	r.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)

	// Redirect route (must be last to avoid conflicts)
	r.HandleFunc("/{shortURL}", urlHandler.RedirectURL).Methods("GET")

	// Configure HTTP server
	serverAddress := fmt.Sprintf("%s:%s", cfg.WebServer.IP, cfg.WebServer.Port)
	server := &http.Server{
		Addr:         serverAddress,
		Handler:      r,
		ReadTimeout:  time.Duration(cfg.WebServer.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.WebServer.WriteTimeout) * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Info().
			Str("address", serverAddress).
			Str("scheme", cfg.WebServer.Scheme).
			Msg("Starting server")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Failed to start server")
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.WebServer.ShutdownTimeout)*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	// Close cache
	if cacheClient != nil {
		cacheClient.Close()
	}

	// Close Redis connection
	if err := rdb.Close(); err != nil {
		log.Error().Err(err).Msg("Failed to close Redis connection")
	}

	log.Info().Msg("Server stopped gracefully")
}
