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

// BruteForceDetector implements DetectorPlugin for brute force detection
type BruteForceDetector struct {
	name        string
	version     string
	description string
	store       store.StateStore
	config      BruteForceConfig
	metrics     struct {
		totalChecks     int64
		threatsFound    int64
		loginAttempts   int64
		blockedAttempts int64
	}
	mu sync.RWMutex
}

// BruteForceConfig holds configuration for brute force detection
type BruteForceConfig struct {
	LoginEndpoints  []string      `json:"login_endpoints"`
	MaxAttempts     int64         `json:"max_attempts"`
	WindowSize      time.Duration `json:"window_size"`
	KeyTemplate     string        `json:"key_template"`
	TrackUsernames  bool          `json:"track_usernames"`
	UsernameLimit   int64         `json:"username_limit"`
	FailureHeaders  []string      `json:"failure_headers"`
	FailureStatuses []int         `json:"failure_statuses"`
}

// NewBruteForceDetector creates a new brute force detector plugin
func NewBruteForceDetector(stateStore store.StateStore) *BruteForceDetector {
	return &BruteForceDetector{
		name:        "brute_force_detector",
		version:     "1.0.0",
		description: "Detects brute force login attempts",
		store:       stateStore,
		config: BruteForceConfig{
			LoginEndpoints:  []string{"/login", "/auth", "/signin", "/api/auth"},
			MaxAttempts:     5,
			WindowSize:      5 * time.Minute,
			KeyTemplate:     "brute_force:{ip}:{endpoint}",
			TrackUsernames:  true,
			UsernameLimit:   10,
			FailureHeaders:  []string{"X-Auth-Failed", "X-Login-Failed"},
			FailureStatuses: []int{401, 403},
		},
	}
}

// Name returns the plugin name
func (d *BruteForceDetector) Name() string {
	return d.name
}

// Version returns the plugin version
func (d *BruteForceDetector) Version() string {
	return d.version
}

// Description returns the plugin description
func (d *BruteForceDetector) Description() string {
	return d.description
}

// Initialize initializes the plugin with configuration
func (d *BruteForceDetector) Initialize(config map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Parse login endpoints
	if endpoints, ok := config["login_endpoints"].([]any); ok {
		d.config.LoginEndpoints = make([]string, len(endpoints))
		for i, ep := range endpoints {
			if epStr, ok := ep.(string); ok {
				d.config.LoginEndpoints[i] = epStr
			}
		}
	}

	// Parse max attempts
	if maxAttempts, ok := config["max_attempts"].(float64); ok {
		d.config.MaxAttempts = int64(maxAttempts)
	}

	// Parse window size
	if windowStr, ok := config["window_size"].(string); ok {
		if duration, err := time.ParseDuration(windowStr); err == nil {
			d.config.WindowSize = duration
		}
	}

	// Parse key template
	if keyTemplate, ok := config["key_template"].(string); ok {
		d.config.KeyTemplate = keyTemplate
	}

	// Parse track usernames
	if trackUsernames, ok := config["track_usernames"].(bool); ok {
		d.config.TrackUsernames = trackUsernames
	}

	// Parse username limit
	if usernameLimit, ok := config["username_limit"].(float64); ok {
		d.config.UsernameLimit = int64(usernameLimit)
	}

	return nil
}

// Detect performs brute force detection
func (d *BruteForceDetector) Detect(ctx context.Context, reqCtx *plugins.RequestContext) plugins.DetectionResult {
	d.mu.RLock()
	config := d.config
	d.mu.RUnlock()

	d.metrics.totalChecks++

	// Check if this is a login endpoint
	if !d.isLoginEndpoint(reqCtx.Path, config.LoginEndpoints) {
		return plugins.DetectionResult{
			Threat:     false,
			Confidence: 0,
			Details:    "Not a login endpoint",
			Severity:   0,
			Tags:       []string{},
			Metadata:   map[string]any{},
		}
	}

	d.metrics.loginAttempts++

	// Generate keys for tracking
	attemptKey := d.generateKey(config.KeyTemplate, reqCtx)
	usernameKey := fmt.Sprintf("brute_usernames:%s", reqCtx.IP)

	// Get current attempt count
	currentAttempts, err := d.store.IncrementWithTTL(ctx, attemptKey, 1, config.WindowSize)
	if err != nil {
		currentAttempts = 1
		d.store.Set(ctx, attemptKey, currentAttempts, config.WindowSize)
	}

	// Track usernames if configured
	var usernameCount int64
	if config.TrackUsernames {
		username := d.extractUsername(reqCtx)
		if username != "" {
			usernameSetKey := fmt.Sprintf("%s:%s", usernameKey, username)
			d.store.Set(ctx, usernameSetKey, 1, config.WindowSize)

			// Count unique usernames
			if keys, err := d.store.Keys(ctx, usernameKey+":*"); err == nil {
				usernameCount = int64(len(keys))
			}
		}
	}

	// Check if brute force threshold is exceeded
	if currentAttempts > config.MaxAttempts {
		d.metrics.threatsFound++
		d.metrics.blockedAttempts++

		severity := 6 // Medium-high severity
		confidence := 0.8

		// Increase severity based on attempt count
		if currentAttempts > config.MaxAttempts*2 {
			severity = 8
			confidence = 0.9
		}
		if currentAttempts > config.MaxAttempts*5 {
			severity = 9
			confidence = 0.95
		}

		// Increase severity if many usernames are being tried
		if usernameCount > config.UsernameLimit {
			severity = 9
			confidence = 1.0
		}

		return plugins.DetectionResult{
			Threat:     true,
			Confidence: confidence,
			Details:    fmt.Sprintf("Brute force attack detected: %d attempts in %s (limit: %d)", currentAttempts, config.WindowSize, config.MaxAttempts),
			Severity:   severity,
			Tags:       []string{"brute_force", "login_abuse", "authentication_attack"},
			Metadata: map[string]any{
				"current_attempts": currentAttempts,
				"max_attempts":     config.MaxAttempts,
				"window_size":      config.WindowSize.String(),
				"endpoint":         reqCtx.Path,
				"username_count":   usernameCount,
				"key":              attemptKey,
			},
		}
	}

	// Check if approaching threshold (warning)
	if currentAttempts > config.MaxAttempts/2 {
		return plugins.DetectionResult{
			Threat:     true,
			Confidence: 0.3,
			Details:    fmt.Sprintf("Elevated login attempts: %d/%d in %s", currentAttempts, config.MaxAttempts, config.WindowSize),
			Severity:   3, // Low severity warning
			Tags:       []string{"brute_force", "login_attempts", "suspicious"},
			Metadata: map[string]any{
				"current_attempts": currentAttempts,
				"max_attempts":     config.MaxAttempts,
				"window_size":      config.WindowSize.String(),
				"endpoint":         reqCtx.Path,
				"username_count":   usernameCount,
				"warning":          true,
			},
		}
	}

	return plugins.DetectionResult{
		Threat:     false,
		Confidence: 0,
		Details:    fmt.Sprintf("Login attempts within normal range: %d/%d", currentAttempts, config.MaxAttempts),
		Severity:   0,
		Tags:       []string{},
		Metadata: map[string]any{
			"current_attempts": currentAttempts,
			"max_attempts":     config.MaxAttempts,
		},
	}
}

// isLoginEndpoint checks if the path matches any login endpoint
func (d *BruteForceDetector) isLoginEndpoint(path string, endpoints []string) bool {
	path = strings.ToLower(path)
	for _, endpoint := range endpoints {
		if strings.Contains(path, strings.ToLower(endpoint)) {
			return true
		}
	}
	return false
}

// generateKey generates a key based on the template and request context
func (d *BruteForceDetector) generateKey(template string, reqCtx *plugins.RequestContext) string {
	key := template

	// Replace placeholders
	replacements := map[string]string{
		"{ip}":       reqCtx.IP,
		"{user_id}":  reqCtx.UserID,
		"{endpoint}": reqCtx.Path,
		"{method}":   reqCtx.Method,
	}

	for placeholder, value := range replacements {
		if value != "" {
			key = strings.Replace(key, placeholder, value, -1)
		}
	}

	return key
}

// extractUsername attempts to extract username from request
func (d *BruteForceDetector) extractUsername(reqCtx *plugins.RequestContext) string {
	// Try to get username from common parameter names
	commonUsernameFields := []string{"username", "user", "email", "login", "account"}

	for _, field := range commonUsernameFields {
		if value, exists := reqCtx.QueryParams[field]; exists && value != "" {
			return value
		}
	}

	// Could also check headers or body if available
	if userHeader, exists := reqCtx.Headers["X-Username"]; exists {
		return userHeader
	}

	return ""
}

// ResetAttempts resets the attempt count for an IP/endpoint combination
func (d *BruteForceDetector) ResetAttempts(ctx context.Context, ip, endpoint string) error {
	key := strings.Replace(d.config.KeyTemplate, "{ip}", ip, -1)
	key = strings.Replace(key, "{endpoint}", endpoint, -1)
	return d.store.Delete(ctx, key)
}

// GetAttemptCount returns the current attempt count for an IP/endpoint
func (d *BruteForceDetector) GetAttemptCount(ctx context.Context, ip, endpoint string) (int64, error) {
	key := strings.Replace(d.config.KeyTemplate, "{ip}", ip, -1)
	key = strings.Replace(key, "{endpoint}", endpoint, -1)

	count, err := d.store.Get(ctx, key)
	if err != nil {
		return 0, nil // No attempts if key doesn't exist
	}

	if countVal, ok := count.(int64); ok {
		return countVal, nil
	}

	return 0, nil
}

// Cleanup cleans up plugin resources
func (d *BruteForceDetector) Cleanup() error {
	return nil
}

// Health checks plugin health
func (d *BruteForceDetector) Health() error {
	if d.store == nil {
		return fmt.Errorf("state store not initialized")
	}
	return d.store.Health()
}

// GetMetrics returns plugin metrics
func (d *BruteForceDetector) GetMetrics() map[string]any {
	d.mu.RLock()
	defer d.mu.RUnlock()

	detectionRate := float64(0)
	if d.metrics.loginAttempts > 0 {
		detectionRate = float64(d.metrics.threatsFound) / float64(d.metrics.loginAttempts)
	}

	return map[string]any{
		"total_checks":     d.metrics.totalChecks,
		"threats_found":    d.metrics.threatsFound,
		"login_attempts":   d.metrics.loginAttempts,
		"blocked_attempts": d.metrics.blockedAttempts,
		"detection_rate":   detectionRate,
		"max_attempts":     d.config.MaxAttempts,
		"window_size":      d.config.WindowSize.String(),
		"login_endpoints":  len(d.config.LoginEndpoints),
	}
}
