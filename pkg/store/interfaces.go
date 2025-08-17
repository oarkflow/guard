package store

import (
	"context"
	"time"
)

// StateStore interface for distributed state management
type StateStore interface {
	Get(ctx context.Context, key string) (any, error)
	Set(ctx context.Context, key string, value any, ttl time.Duration) error
	Increment(ctx context.Context, key string, delta int64) (int64, error)
	IncrementWithTTL(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error)
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
	Keys(ctx context.Context, pattern string) ([]string, error)
	Close() error
	Health() error
	GetStats() map[string]any
}

// StoreConfig represents configuration for a state store
type StoreConfig struct {
	Type       string         `json:"type"`     // "memory", "redis", "etcd"
	Address    string         `json:"address"`  // Connection address
	Password   string         `json:"password"` // Authentication password
	Database   int            `json:"database"` // Database number (for Redis)
	Prefix     string         `json:"prefix"`   // Key prefix
	MaxRetries int            `json:"max_retries"`
	Timeout    time.Duration  `json:"timeout"`
	Options    map[string]any `json:"options"` // Store-specific options
}

// StoreFactory creates state store instances
type StoreFactory interface {
	CreateStore(config StoreConfig) (StateStore, error)
	SupportedTypes() []string
}
