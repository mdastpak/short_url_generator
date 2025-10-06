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

type FeaturesConfig struct {
	DeduplicationEnabled bool `mapstructure:"deduplication_enabled"`
}

type Config struct {
	WebServer WebServerConfig `mapstructure:"webserver"`
	Redis     RedisConfig     `mapstructure:"redis"`
	RateLimit RateLimitConfig `mapstructure:"ratelimit"`
	Features  FeaturesConfig  `mapstructure:"features"`
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

	// RateLimit defaults
	viper.SetDefault("ratelimit.requests_per_second", 10.0)
	viper.SetDefault("ratelimit.burst", 20)

	// Features defaults
	viper.SetDefault("features.deduplication_enabled", true)
}
