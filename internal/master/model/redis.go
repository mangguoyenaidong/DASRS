package model

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// InitRedis 初始化 Redis 连接
func InitRedis(cfg *Config) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Master.Redis.Host, cfg.Master.Redis.Port),
		Password: cfg.Master.Redis.Password,
		DB:       cfg.Master.Redis.DB,
		PoolSize: cfg.Master.Redis.PoolSize,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect redis: %w", err)
	}

	return client, nil
}
