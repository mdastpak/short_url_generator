package redis

import (
	"context"
	"short-url-generator/config"

	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
)

var ctx = context.Background()

func NewClient(cfg config.RedisConfig) *redis.Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:         cfg.Address,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
	})

	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to Redis")
	}

	log.Info().Msg("Connected to Redis successfully")
	return rdb
}
