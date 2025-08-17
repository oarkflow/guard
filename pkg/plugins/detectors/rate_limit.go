package detectors

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/guard/pkg/store"
)

// RateLimitDetector implements DetectorPlugin for rate limiting detection
type RateLimitDetector struct {
	name        string
	version     string
	description string
	store       store.StateStore
	config      RateLimitConfig
	metrics     struct {
		totalChecks int64
		violations  int64
		allowedReqs int64
	}
	mu sync.RWMutex
}

// RateLimitConfig holds configuration for rate limiting
type RateLimitConfig struct {
	WindowSize    time.Duration `json:"window_size"`
	MaxRequests   int64         `json:"max_requests"`
	KeyTemplate   string        `json:"key_template"`  // e.g., "rate_limit:{ip}" or "rate_limit:{user_id}"
	BurstAllowed  int64         `json:"burst_allowed"` // Allow burst requests
	CleanupPeriod time.Duration `json:"cleanup_period"`
}

// NewRateLimitDetector creates a new rate limit detector plugin
func NewRateLimitDetector(stateStore store.StateStore) *RateLimitDetector {
	return &RateLimitDetector{
		name:        "rate_limit_detector",
		version:     "1.0.0",
		description: "Detects rate limit violations based on configurable windows",
		store:       stateStore,
		config: RateLimitConfig{
			WindowSize:    time.Minute,
			MaxRequests:   10, // Lower limit for testing
			KeyTemplate:   "rate_limit:{ip}",
			BurstAllowed:  5,
			CleanupPeriod: 5 * time.Minute,
		},
	}
}

// Name returns the plugin name
func (d *RateLimitDetector) Name() string {
	return d.name
}

// Version returns the plugin version
func (d *RateLimitDetector) Version() string {
	return d.version
}

// Description returns the plugin description
func (d *RateLimitDetector) Description() string {
	return d.description
}

// Initialize initializes the plugin with configuration
func (d *RateLimitDetector) Initialize(config map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Parse window size
	if windowStr, ok := config["window_size"].(string); ok {
		if duration, err := time.ParseDuration(windowStr); err == nil {
			d.config.WindowSize = duration
		}
	}

	// Parse max requests
	if maxReqs, ok := config["max_requests"].(float64); ok {
		d.config.MaxRequests = int64(maxReqs)
	}

	// Parse key template
	if keyTemplate, ok := config["key_template"].(string); ok {
		d.config.KeyTemplate = keyTemplate
	}

	// Parse burst allowed
	if burst, ok := config["burst_allowed"].(float64); ok {
		d.config.BurstAllowed = int64(burst)
	}

	// Parse cleanup period
	if cleanupStr, ok := config["cleanup_period"].(string); ok {
		if duration, err := time.ParseDuration(cleanupStr); err == nil {
			d.config.CleanupPeriod = duration
		}
	}

	return nil
}

// Detect performs rate limit detection
func (d *RateLimitDetector) Detect(ctx context.Context, reqCtx *plugins.RequestContext) plugins.DetectionResult {
	d.mu.RLock()
	config := d.config
	d.mu.RUnlock()

	d.metrics.totalChecks++

	// Generate key based on template
	key := d.generateKey(config.KeyTemplate, reqCtx)

	// Get current count with proper TTL handling
	currentCount, err := d.store.IncrementWithTTL(ctx, key, 1, config.WindowSize)
	if err != nil {
		// If increment fails, assume it's the first request
		currentCount = 1
		d.store.Set(ctx, key, currentCount, config.WindowSize)
	}

	// Check if rate limit is exceeded
	if currentCount > config.MaxRequests {
		d.metrics.violations++

		// Calculate severity based on how much the limit is exceeded
		excess := currentCount - config.MaxRequests
		severity := 5 // Medium severity by default
		if excess > config.BurstAllowed {
			severity = 8 // High severity for significant violations
		}

		confidence := 0.9
		if excess > config.MaxRequests {
			confidence = 1.0 // Very confident for extreme violations
		}

		return plugins.DetectionResult{
			Threat:     true,
			Confidence: confidence,
			Details:    fmt.Sprintf("Rate limit exceeded: %d requests in window (limit: %d)", currentCount, config.MaxRequests),
			Severity:   severity,
			Tags:       []string{"rate_limit", "ddos", "abuse"},
			Metadata: map[string]any{
				"current_count": currentCount,
				"max_requests":  config.MaxRequests,
				"window_size":   config.WindowSize.String(),
				"key":           key,
				"excess":        excess,
			},
		}
	}

	d.metrics.allowedReqs++
	return plugins.DetectionResult{
		Threat:     false,
		Confidence: 0,
		Details:    fmt.Sprintf("Rate limit OK: %d/%d requests", currentCount, config.MaxRequests),
		Severity:   0,
		Tags:       []string{},
		Metadata: map[string]any{
			"current_count": currentCount,
			"max_requests":  config.MaxRequests,
			"remaining":     config.MaxRequests - currentCount,
		},
	}
}

// generateKey generates a key based on the template and request context
func (d *RateLimitDetector) generateKey(template string, reqCtx *plugins.RequestContext) string {
	key := template

	// Replace placeholders
	replacements := map[string]string{
		"{ip}":      reqCtx.IP,
		"{user_id}": reqCtx.UserID,
		"{path}":    reqCtx.Path,
		"{method}":  reqCtx.Method,
	}

	for placeholder, value := range replacements {
		if value != "" {
			key = strings.Replace(key, placeholder, value, -1)
		}
	}

	return key
}

// Cleanup cleans up plugin resources
func (d *RateLimitDetector) Cleanup() error {
	return nil
}

// Health checks plugin health
func (d *RateLimitDetector) Health() error {
	if d.store == nil {
		return fmt.Errorf("state store not initialized")
	}
	return d.store.Health()
}

// GetMetrics returns plugin metrics
func (d *RateLimitDetector) GetMetrics() map[string]any {
	d.mu.RLock()
	defer d.mu.RUnlock()

	violationRate := float64(0)
	if d.metrics.totalChecks > 0 {
		violationRate = float64(d.metrics.violations) / float64(d.metrics.totalChecks)
	}

	return map[string]any{
		"total_checks":   d.metrics.totalChecks,
		"violations":     d.metrics.violations,
		"allowed_reqs":   d.metrics.allowedReqs,
		"violation_rate": violationRate,
		"window_size":    d.config.WindowSize.String(),
		"max_requests":   d.config.MaxRequests,
	}
}
