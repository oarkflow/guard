package plugins

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
)

// RequestContext represents the context of an incoming request
type RequestContext struct {
	IP            string
	UserAgent     string
	Method        string
	Path          string
	Headers       map[string]string
	QueryParams   map[string]string
	Body          any // Request body content as string, map[string]any, or []map[string]any
	ContentLength int64
	Country       string
	ASN           string
	Timestamp     time.Time
	UserID        string
	SessionID     string
	Metadata      map[string]any
}

// DetectionResult represents the result of a detection operation
type DetectionResult struct {
	Threat     bool
	Confidence float64
	Details    string
	Severity   int
	Tags       []string
	Metadata   map[string]any
}

// RuleResult represents the result of a rule evaluation
type RuleResult struct {
	Triggered  bool
	Action     string
	Confidence float64
	Details    string
	RuleName   string
	Severity   int
	Metadata   map[string]any
}

// DetectorPlugin interface for detection plugins
type DetectorPlugin interface {
	Name() string
	Version() string
	Description() string
	Initialize(config map[string]any) error
	Detect(ctx context.Context, reqCtx *RequestContext) DetectionResult
	Cleanup() error
	Health() error
	GetMetrics() map[string]any
}

// ActionPlugin interface for action plugins
type ActionPlugin interface {
	Name() string
	Version() string
	Description() string
	Initialize(config map[string]any) error
	Execute(ctx context.Context, reqCtx *RequestContext, result RuleResult) error
	Cleanup() error
	Health() error
	GetMetrics() map[string]any
	Render(ctx context.Context, c *fiber.Ctx, data map[string]any) error
}

// SecurityEvent represents a security event in the system
type SecurityEvent struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Timestamp time.Time      `json:"timestamp"`
	IP        string         `json:"ip"`
	UserID    string         `json:"user_id"`
	Severity  int            `json:"severity"`
	Details   map[string]any `json:"details"`
	Source    string         `json:"source"`
	Tags      []string       `json:"tags"`
	Metadata  map[string]any `json:"metadata"`
}

// EventHandler interface for handling security events
type EventHandler interface {
	Name() string
	Handle(ctx context.Context, event SecurityEvent) error
	CanHandle(eventType string) bool
	Priority() int
	Initialize(config map[string]any) error
	Cleanup() error
}

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

// PluginMetadata contains metadata about a plugin
type PluginMetadata struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Description  string            `json:"description"`
	Author       string            `json:"author"`
	Type         string            `json:"type"` // "detector", "action", "handler"
	Config       map[string]string `json:"config"`
	Dependencies []string          `json:"dependencies"`
	Enabled      bool              `json:"enabled"`
}

// PluginConfig represents configuration for a plugin
type PluginConfig struct {
	Enabled    bool           `json:"enabled"`
	Priority   int            `json:"priority"`
	Parameters map[string]any `json:"parameters"`
}
