package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"short-url-generator/auth"
	"short-url-generator/cache"
	"short-url-generator/config"
	_ "short-url-generator/docs" // Swagger docs
	"short-url-generator/email"
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

// @tag.name Admin
// @tag.description Admin dashboard and management endpoints (requires API key authentication)

// @tag.name Authentication
// @tag.description User registration, login, and OTP verification

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name X-Admin-Key
// @description Admin API key for accessing protected endpoints

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

	// Initialize email service
	emailService := email.NewEmailService(
		cfg.Email.SMTPHost,
		cfg.Email.SMTPPort,
		cfg.Email.SMTPUsername,
		cfg.Email.SMTPPassword,
		cfg.Email.FromEmail,
		cfg.Email.FromName,
		cfg.Email.Enabled,
	)
	log.Info().
		Bool("email_enabled", cfg.Email.Enabled).
		Str("smtp_host", cfg.Email.SMTPHost).
		Msg("Email service initialized")

	// Initialize JWT manager
	accessTokenDuration, err := time.ParseDuration(cfg.JWT.AccessTokenDuration)
	if err != nil {
		log.Fatal().Err(err).Msg("Invalid access token duration")
	}
	refreshTokenDuration, err := time.ParseDuration(cfg.JWT.RefreshTokenDuration)
	if err != nil {
		log.Fatal().Err(err).Msg("Invalid refresh token duration")
	}
	otpDuration, err := time.ParseDuration(cfg.JWT.OTPDuration)
	if err != nil {
		log.Fatal().Err(err).Msg("Invalid OTP duration")
	}

	jwtManager := auth.NewJWTManager(cfg.JWT.SecretKey, accessTokenDuration, refreshTokenDuration)
	log.Info().
		Dur("access_token_duration", accessTokenDuration).
		Dur("refresh_token_duration", refreshTokenDuration).
		Dur("otp_duration", otpDuration).
		Msg("JWT manager initialized")

	// Create user handler
	userHandler := handler.NewUserHandler(rdb, jwtManager, emailService, otpDuration, cfg)
	log.Info().
		Bool("registration_enabled", cfg.UserFeatures.RegistrationEnabled).
		Msg("User handler initialized")

	// Set up router
	r := mux.NewRouter()

	// Apply global middleware
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimit.RequestsPerSecond, cfg.RateLimit.Burst, rdb)
	botProtection := middleware.NewBotProtection(cfg.Security.BotMaxRequestsPerMinute, cfg.Security.BotDetectionEnabled, rdb)

	r.Use(middleware.CORS)
	r.Use(middleware.RequestLogger)
	r.Use(rateLimiter.Limit)
	r.Use(botProtection.Protect) // Bot detection middleware

	// Create user auth middleware
	userAuth := middleware.NewUserAuth(jwtManager)

	// Register routes
	r.HandleFunc("/health", urlHandler.HealthCheck).Methods("GET")
	r.HandleFunc("/cache/metrics", urlHandler.CacheMetrics).Methods("GET")

	// URL shortening with optional authentication (will associate with user if logged in)
	r.Handle("/shorten", userAuth.Optional(http.HandlerFunc(urlHandler.CreateShortURL))).Methods("POST")
	r.Handle("/shorten/{managementID}", userAuth.Optional(http.HandlerFunc(urlHandler.UpdateURL))).Methods("PUT")
	r.Handle("/shorten/{managementID}", userAuth.Optional(http.HandlerFunc(urlHandler.DeleteURL))).Methods("DELETE")

	r.HandleFunc("/qr/{shortURL}", urlHandler.GenerateQR).Methods("GET")      // QR code generation
	r.HandleFunc("/preview/{shortURL}", urlHandler.ShowPreview).Methods("GET") // URL preview (anti-phishing)

	// User authentication routes (public)
	r.HandleFunc("/api/auth/register", userHandler.Register).Methods("POST")
	r.HandleFunc("/api/auth/verify-otp", userHandler.VerifyOTP).Methods("POST")
	r.HandleFunc("/api/auth/login", userHandler.Login).Methods("POST")
	r.HandleFunc("/api/auth/refresh", userHandler.RefreshToken).Methods("POST")
	r.HandleFunc("/api/auth/resend-otp", userHandler.ResendOTP).Methods("POST")

	// Password reset routes (public)
	r.HandleFunc("/api/auth/forgot-password", userHandler.ForgotPassword).Methods("POST")
	r.HandleFunc("/api/auth/reset-password", userHandler.ValidateResetToken).Methods("GET")
	r.HandleFunc("/api/auth/reset-password", userHandler.ResetPassword).Methods("POST")

	// Protected user routes (requires authentication)
	userRouter := r.PathPrefix("/api/user").Subrouter()
	userRouter.Use(userAuth.Protect)
	userRouter.HandleFunc("/urls", userHandler.GetUserURLs).Methods("GET")
	userRouter.HandleFunc("/profile", userHandler.GetProfile).Methods("GET")
	userRouter.HandleFunc("/change-password", userHandler.ChangePassword).Methods("POST")
	userRouter.HandleFunc("/security-phrase", userHandler.SetSecurityPhrase).Methods("PUT")
	userRouter.HandleFunc("/activity", userHandler.GetActivityLogs).Methods("GET")
	userRouter.HandleFunc("/analytics", userHandler.GetUserAnalytics).Methods("GET")
	userRouter.HandleFunc("/url/{shortURL}/logs", userHandler.GetURLAccessLogs).Methods("GET")
	userRouter.HandleFunc("/url/{shortURL}/password", userHandler.SetURLPassword).Methods("PUT")
	userRouter.HandleFunc("/url/{shortURL}/password", userHandler.RemoveURLPassword).Methods("DELETE")

	log.Info().
		Bool("registration_enabled", cfg.UserFeatures.RegistrationEnabled).
		Msg("User authentication routes configured")

	// Password protection routes (public)
	r.HandleFunc("/password/{shortURL}", urlHandler.ShowPasswordPrompt).Methods("GET")
	r.HandleFunc("/verify-password/{shortURL}", urlHandler.VerifyPassword).Methods("POST")

	// User panel (public - has login/register screens)
	r.HandleFunc("/panel", userHandler.ServeUserPanel).Methods("GET")
	r.HandleFunc("/", userHandler.ServeUserPanel).Methods("GET") // Root redirects to panel

	// Admin dashboard (public - has login screen)
	r.HandleFunc("/admin/dashboard", urlHandler.ServeDashboard).Methods("GET")

	// Admin API routes (protected with API key authentication)
	adminAuth := middleware.NewAdminAuth(cfg.Admin.APIKey, cfg.Admin.Enabled)
	adminRouter := r.PathPrefix("/admin").Subrouter()
	adminRouter.Use(adminAuth.Protect)
	adminRouter.HandleFunc("/stats", urlHandler.GetAdminStats).Methods("GET")
	adminRouter.HandleFunc("/urls", urlHandler.GetURLsList).Methods("GET")
	adminRouter.HandleFunc("/urls/{shortURL}", urlHandler.GetURLDetail).Methods("GET")
	adminRouter.HandleFunc("/urls/bulk-delete", urlHandler.BulkDeleteURLs).Methods("POST")
	adminRouter.HandleFunc("/system/health", urlHandler.GetSystemHealth).Methods("GET")
	adminRouter.HandleFunc("/security/stats", urlHandler.GetSecurityStats).Methods("GET")

	log.Info().
		Bool("admin_enabled", cfg.Admin.Enabled).
		Bool("admin_api_key_set", cfg.Admin.APIKey != "").
		Msg("Admin routes configured")

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
