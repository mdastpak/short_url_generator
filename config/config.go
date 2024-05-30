package config

import (
	"log"

	"github.com/spf13/viper"
)

type WebServerConfig struct {
	Port string `mapstructure:"port"`
	IP   string `mapstructure:"ip"`
}

type RedisConfig struct {
	Address  string `mapstructure:"address"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type Config struct {
	WebServer WebServerConfig `mapstructure:"webserver"`
	Redis     RedisConfig     `mapstructure:"redis"`
}

func LoadConfig() (Config, error) {
	var config Config

	viper.AddConfigPath(".")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AutomaticEnv()

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
