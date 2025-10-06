package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Initialize sets up the global logger
func Initialize() {
	// Use pretty console output for development
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	log.Logger = zerolog.New(output).With().Timestamp().Caller().Logger()

	// Set global log level
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
}

// Get returns the global logger
func Get() *zerolog.Logger {
	return &log.Logger
}
