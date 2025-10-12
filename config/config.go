package config

import (
	"log"

	"github.com/spf13/viper"
)

type WebServerConfig struct {
	Port            string `mapstructure:"port"`
	IP              string `mapstructure:"ip"`
	Scheme          string `mapstructure:"scheme"`
	BaseURL         string `mapstructure:"base_url"`
	ReadTimeout     int    `mapstructure:"read_timeout"`
	WriteTimeout    int    `mapstructure:"write_timeout"`
	ShutdownTimeout int    `mapstructure:"shutdown_timeout"`
}

type RedisConfig struct {
	Address          string `mapstructure:"address"`
	Password         string `mapstructure:"password"`
	DB               int    `mapstructure:"db"`
	PoolSize         int    `mapstructure:"pool_size"`
	MinIdleConns     int    `mapstructure:"min_idle_conns"`
	OperationTimeout int    `mapstructure:"operation_timeout"`
}

type RateLimitConfig struct {
	RequestsPerSecond float64 `mapstructure:"requests_per_second"`
	Burst             int     `mapstructure:"burst"`
}

type CacheConfig struct {
	Enabled     bool `mapstructure:"enabled"`
	MaxSizeMB   int  `mapstructure:"max_size_mb"`
	TTLSeconds  int  `mapstructure:"ttl_seconds"`
	CounterSize int  `mapstructure:"counter_size"`
}

type FeaturesConfig struct {
	DeduplicationEnabled  bool `mapstructure:"deduplication_enabled"`
	CustomSlugsEnabled    bool `mapstructure:"custom_slugs_enabled"`
	MinSlugLength         int  `mapstructure:"min_slug_length"`
	MaxSlugLength         int  `mapstructure:"max_slug_length"`
	RequireAuthForCustom  bool `mapstructure:"require_auth_for_custom"`   // Future: require API auth for custom slugs
	SlugSuggestionsCount  int  `mapstructure:"slug_suggestions_count"`    // Number of alternative suggestions to provide on conflict
	PreviewEnabled        bool `mapstructure:"preview_enabled"`           // Enable URL preview feature
	PreviewAutoRedirect   int  `mapstructure:"preview_auto_redirect"`     // Auto-redirect seconds (0 = disabled)
}

type SecurityConfig struct {
	URLScanningEnabled      bool   `mapstructure:"url_scanning_enabled"`       // Enable URL malware/phishing scanning
	BlocklistEnabled        bool   `mapstructure:"blocklist_enabled"`          // Enable local blocklist
	SafeBrowsingAPIKey      string `mapstructure:"safe_browsing_api_key"`      // Google Safe Browsing API key (optional)
	BotDetectionEnabled     bool   `mapstructure:"bot_detection_enabled"`      // Enable bot detection
	BotMaxRequestsPerMinute int    `mapstructure:"bot_max_requests_per_minute"` // Max requests per minute before flagging as bot
}

type AdminConfig struct {
	Enabled bool   `mapstructure:"enabled"` // Enable admin dashboard and API
	APIKey  string `mapstructure:"api_key"` // Admin API key for authentication
}

type EmailConfig struct {
	Enabled      bool   `mapstructure:"enabled"`       // Enable email sending
	SMTPHost     string `mapstructure:"smtp_host"`     // SMTP server host
	SMTPPort     string `mapstructure:"smtp_port"`     // SMTP server port
	SMTPUsername string `mapstructure:"smtp_username"` // SMTP username
	SMTPPassword string `mapstructure:"smtp_password"` // SMTP password
	FromEmail    string `mapstructure:"from_email"`    // From email address
	FromName     string `mapstructure:"from_name"`     // From name
}

type JWTConfig struct {
	SecretKey            string `mapstructure:"secret_key"`             // JWT signing secret (min 32 chars)
	AccessTokenDuration  string `mapstructure:"access_token_duration"`  // e.g., "15m", "1h"
	RefreshTokenDuration string `mapstructure:"refresh_token_duration"` // e.g., "168h" (7 days)
	OTPDuration          string `mapstructure:"otp_duration"`           // e.g., "10m"
}

type UserFeaturesConfig struct {
	RegistrationEnabled         bool `mapstructure:"registration_enabled"`            // Allow new user registration
	CustomDomainsEnabled        bool `mapstructure:"custom_domains_enabled"`          // Allow custom domains
	PasswordProtectedURLsEnabled bool `mapstructure:"password_protected_urls_enabled"` // Allow password-protected URLs
	ScheduledURLsEnabled        bool `mapstructure:"scheduled_urls_enabled"`          // Allow scheduled activation
	URLAliasesEnabled           bool `mapstructure:"url_aliases_enabled"`             // Allow URL aliases
	MaxURLsPerUser              int  `mapstructure:"max_urls_per_user"`               // Max URLs per user (0 = unlimited)
	MaxAliasesPerURL            int  `mapstructure:"max_aliases_per_url"`             // Max aliases per URL
}

type PasswordRulesConfig struct {
	MinLength        int  `mapstructure:"min_length"`        // Minimum password length
	MaxLength        int  `mapstructure:"max_length"`        // Maximum password length (bcrypt limit: 72)
	RequireUppercase bool `mapstructure:"require_uppercase"` // Require at least one uppercase letter
	RequireLowercase bool `mapstructure:"require_lowercase"` // Require at least one lowercase letter
	RequireDigit     bool `mapstructure:"require_digit"`     // Require at least one digit
	RequireSpecial   bool `mapstructure:"require_special"`   // Require at least one special character
}

type PasswordConfig struct {
	User PasswordRulesConfig `mapstructure:"user"` // User account password rules
	URL  PasswordRulesConfig `mapstructure:"url"`  // URL protection password rules
}

type Config struct {
	WebServer    WebServerConfig    `mapstructure:"webserver"`
	Redis        RedisConfig        `mapstructure:"redis"`
	Cache        CacheConfig        `mapstructure:"cache"`
	RateLimit    RateLimitConfig    `mapstructure:"ratelimit"`
	Features     FeaturesConfig     `mapstructure:"features"`
	Security     SecurityConfig     `mapstructure:"security"`
	Admin        AdminConfig        `mapstructure:"admin"`
	Email        EmailConfig        `mapstructure:"email"`
	JWT          JWTConfig          `mapstructure:"jwt"`
	UserFeatures UserFeaturesConfig `mapstructure:"user_features"`
	Password     PasswordConfig     `mapstructure:"password"`
}

func LoadConfig() (Config, error) {
	var config Config

	viper.AddConfigPath(".")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	// Enable environment variable overrides
	viper.SetEnvPrefix("SHORTURL")
	viper.AutomaticEnv()

	// Set defaults
	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("Error reading config file: %v", err)
		return config, err
	}

	if err := viper.Unmarshal(&config); err != nil {
		log.Printf("Unable to decode into struct: %v", err)
		return config, err
	}

	log.Println("Configuration loaded successfully")
	return config, nil
}

func MustLoadConfig() Config {
	config, err := LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	return config
}

func setDefaults() {
	// WebServer defaults
	viper.SetDefault("webserver.port", "8080")
	viper.SetDefault("webserver.ip", "127.0.0.1")
	viper.SetDefault("webserver.scheme", "http")
	viper.SetDefault("webserver.base_url", "")
	viper.SetDefault("webserver.read_timeout", 15)
	viper.SetDefault("webserver.write_timeout", 15)
	viper.SetDefault("webserver.shutdown_timeout", 30)

	// Redis defaults
	viper.SetDefault("redis.address", "localhost:6379")
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.pool_size", 10)
	viper.SetDefault("redis.min_idle_conns", 5)
	viper.SetDefault("redis.operation_timeout", 5)

	// Cache defaults
	viper.SetDefault("cache.enabled", true)
	viper.SetDefault("cache.max_size_mb", 100)
	viper.SetDefault("cache.ttl_seconds", 300)      // 5 minutes
	viper.SetDefault("cache.counter_size", 1000000) // 1M keys

	// RateLimit defaults
	viper.SetDefault("ratelimit.requests_per_second", 10.0)
	viper.SetDefault("ratelimit.burst", 20)

	// Features defaults
	viper.SetDefault("features.deduplication_enabled", true)
	viper.SetDefault("features.custom_slugs_enabled", true)
	viper.SetDefault("features.min_slug_length", 3)
	viper.SetDefault("features.max_slug_length", 64)
	viper.SetDefault("features.require_auth_for_custom", false)
	viper.SetDefault("features.slug_suggestions_count", 3)
	viper.SetDefault("features.preview_enabled", true)
	viper.SetDefault("features.preview_auto_redirect", 0) // 0 = disabled, >0 = seconds

	// Security defaults
	viper.SetDefault("security.url_scanning_enabled", true)
	viper.SetDefault("security.blocklist_enabled", true)
	viper.SetDefault("security.safe_browsing_api_key", "")       // Optional, leave empty to use blocklist only
	viper.SetDefault("security.bot_detection_enabled", true)
	viper.SetDefault("security.bot_max_requests_per_minute", 60) // 60 req/min per IP

	// Admin defaults
	viper.SetDefault("admin.enabled", true)
	viper.SetDefault("admin.api_key", "") // MUST be set via config file or environment variable

	// Email defaults
	viper.SetDefault("email.enabled", false) // Disabled by default for development
	viper.SetDefault("email.smtp_host", "smtp.gmail.com")
	viper.SetDefault("email.smtp_port", "587")
	viper.SetDefault("email.smtp_username", "")
	viper.SetDefault("email.smtp_password", "")
	viper.SetDefault("email.from_email", "noreply@localhost")
	viper.SetDefault("email.from_name", "Short URL Generator")

	// JWT defaults
	viper.SetDefault("jwt.secret_key", "") // MUST be set via config file or environment variable
	viper.SetDefault("jwt.access_token_duration", "15m")
	viper.SetDefault("jwt.refresh_token_duration", "168h") // 7 days
	viper.SetDefault("jwt.otp_duration", "10m")

	// User features defaults
	viper.SetDefault("user_features.registration_enabled", true)
	viper.SetDefault("user_features.custom_domains_enabled", true)
	viper.SetDefault("user_features.password_protected_urls_enabled", true)
	viper.SetDefault("user_features.scheduled_urls_enabled", true)
	viper.SetDefault("user_features.url_aliases_enabled", true)
	viper.SetDefault("user_features.max_urls_per_user", 1000)
	viper.SetDefault("user_features.max_aliases_per_url", 10)

	// Password validation defaults
	// User account password rules (stricter)
	viper.SetDefault("password.user.min_length", 8)
	viper.SetDefault("password.user.max_length", 72)
	viper.SetDefault("password.user.require_uppercase", true)
	viper.SetDefault("password.user.require_lowercase", true)
	viper.SetDefault("password.user.require_digit", true)
	viper.SetDefault("password.user.require_special", false)
	// URL protection password rules (more lenient)
	viper.SetDefault("password.url.min_length", 6)
	viper.SetDefault("password.url.max_length", 72)
	viper.SetDefault("password.url.require_uppercase", false)
	viper.SetDefault("password.url.require_lowercase", false)
	viper.SetDefault("password.url.require_digit", false)
	viper.SetDefault("password.url.require_special", false)
}
