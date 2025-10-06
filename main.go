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
	"short-url-generator/handler"
	appLogger "short-url-generator/logger"
	"short-url-generator/middleware"
	redisClient "short-url-generator/redis"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

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

	// Create handler with dependency injection
	urlHandler := handler.NewURLHandler(rdb, cacheClient, cfg)

	// Set up router
	r := mux.NewRouter()

	// Apply global middleware
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimit.RequestsPerSecond, cfg.RateLimit.Burst)
	r.Use(middleware.CORS)
	r.Use(middleware.RequestLogger)
	r.Use(rateLimiter.Limit)

	// Register routes
	r.HandleFunc("/health", urlHandler.HealthCheck).Methods("GET")
	r.HandleFunc("/cache/metrics", urlHandler.CacheMetrics).Methods("GET")
	r.HandleFunc("/shorten", urlHandler.CreateShortURL).Methods("POST")
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
