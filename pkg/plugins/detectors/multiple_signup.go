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

// MultipleSignupDetector implements DetectorPlugin for multiple signup detection
type MultipleSignupDetector struct {
	name        string
	version     string
	description string
	store       store.StateStore
	config      MultipleSignupConfig
	metrics     struct {
		totalChecks     int64
		threatsFound    int64
		signupAttempts  int64
		blockedAttempts int64
	}
	mu sync.RWMutex
}

// MultipleSignupConfig holds configuration for multiple signup detection
type MultipleSignupConfig struct {
	SignupEndpoints []string      `json:"signup_endpoints"`
	MaxSignups      int64         `json:"max_signups"`
	WindowSize      time.Duration `json:"window_size"`
	KeyTemplate     string        `json:"key_template"`
	TrackUsernames  bool          `json:"track_usernames"`
	UsernameLimit   int64         `json:"username_limit"`
}

// NewMultipleSignupDetector creates a new multiple signup detector plugin
func NewMultipleSignupDetector(stateStore store.StateStore) *MultipleSignupDetector {
	return &MultipleSignupDetector{
		name:        "multiple_signup_detector",
		version:     "1.0.0",
		description: "Detects multiple signup attempts from same IP",
		store:       stateStore,
		config: MultipleSignupConfig{
			SignupEndpoints: []string{"/signup", "/register", "/api/signup", "/api/register"},
			MaxSignups:      3,
			WindowSize:      1 * time.Hour,
			KeyTemplate:     "multiple_signup:{ip}",
			TrackUsernames:  true,
			UsernameLimit:   5,
		},
	}
}

// Name returns the plugin name
func (d *MultipleSignupDetector) Name() string {
	return d.name
}

// Version returns the plugin version
func (d *MultipleSignupDetector) Version() string {
	return d.version
}

// Description returns the plugin description
func (d *MultipleSignupDetector) Description() string {
	return d.description
}

// Initialize initializes the plugin with configuration
func (d *MultipleSignupDetector) Initialize(config map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Parse signup endpoints
	if endpoints, ok := config["signup_endpoints"].([]any); ok {
		d.config.SignupEndpoints = make([]string, len(endpoints))
		for i, ep := range endpoints {
			if epStr, ok := ep.(string); ok {
				d.config.SignupEndpoints[i] = epStr
			}
		}
	}

	// Parse max signups
	if maxSignups, ok := config["max_signups"].(float64); ok {
		d.config.MaxSignups = int64(maxSignups)
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

// Detect performs multiple signup detection
func (d *MultipleSignupDetector) Detect(ctx context.Context, reqCtx *plugins.RequestContext) plugins.DetectionResult {
	d.mu.RLock()
	config := d.config
	d.mu.RUnlock()

	d.metrics.totalChecks++

	// Check if this is a signup endpoint
	if !d.isSignupEndpoint(reqCtx.Path, config.SignupEndpoints) {
		return plugins.DetectionResult{
			Threat:     false,
			Confidence: 0,
			Details:    "Not a signup endpoint",
			Severity:   0,
			Tags:       []string{},
			Metadata:   map[string]any{},
		}
	}

	d.metrics.signupAttempts++

	// Generate keys for tracking
	attemptKey := d.generateKey(config.KeyTemplate, reqCtx)
	usernameKey := fmt.Sprintf("signup_usernames:%s", reqCtx.IP)

	// Get current signup count
	currentSignups, err := d.store.IncrementWithTTL(ctx, attemptKey, 1, config.WindowSize)
	if err != nil {
		currentSignups = 1
		d.store.Set(ctx, attemptKey, currentSignups, config.WindowSize)
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

	// Check if multiple signup threshold is exceeded
	if currentSignups > config.MaxSignups {
		d.metrics.threatsFound++
		d.metrics.blockedAttempts++

		severity := 5 // Medium severity
		confidence := 0.7

		// Increase severity based on signup count
		if currentSignups > config.MaxSignups*2 {
			severity = 7
			confidence = 0.8
		}
		if currentSignups > config.MaxSignups*5 {
			severity = 9
			confidence = 0.9
		}

		// Increase severity if many usernames are being used
		if usernameCount > config.UsernameLimit {
			severity = 8
			confidence = 0.85
		}

		return plugins.DetectionResult{
			Threat:     true,
			Confidence: confidence,
			Details:    fmt.Sprintf("Multiple signup attempts detected: %d signups in %s (limit: %d)", currentSignups, config.WindowSize, config.MaxSignups),
			Severity:   severity,
			Tags:       []string{"multiple_signup", "account_abuse", "spam"},
			Metadata: map[string]any{
				"current_signups": currentSignups,
				"max_signups":     config.MaxSignups,
				"window_size":     config.WindowSize.String(),
				"endpoint":        reqCtx.Path,
				"username_count":  usernameCount,
				"key":             attemptKey,
			},
		}
	}

	// Check if approaching threshold (warning)
	if currentSignups > config.MaxSignups/2 {
		return plugins.DetectionResult{
			Threat:     true,
			Confidence: 0.4,
			Details:    fmt.Sprintf("Elevated signup attempts: %d/%d in %s", currentSignups, config.MaxSignups, config.WindowSize),
			Severity:   3, // Low severity warning
			Tags:       []string{"multiple_signup", "signup_attempts", "suspicious"},
			Metadata: map[string]any{
				"current_signups": currentSignups,
				"max_signups":     config.MaxSignups,
				"window_size":     config.WindowSize.String(),
				"endpoint":        reqCtx.Path,
				"username_count":  usernameCount,
				"warning":         true,
			},
		}
	}

	return plugins.DetectionResult{
		Threat:     false,
		Confidence: 0,
		Details:    fmt.Sprintf("Signup attempts within normal range: %d/%d", currentSignups, config.MaxSignups),
		Severity:   0,
		Tags:       []string{},
		Metadata: map[string]any{
			"current_signups": currentSignups,
			"max_signups":     config.MaxSignups,
		},
	}
}

// isSignupEndpoint checks if the path matches any signup endpoint
func (d *MultipleSignupDetector) isSignupEndpoint(path string, endpoints []string) bool {
	path = strings.ToLower(path)
	for _, endpoint := range endpoints {
		if strings.Contains(path, strings.ToLower(endpoint)) {
			return true
		}
	}
	return false
}

// generateKey generates a key based on the template and request context
func (d *MultipleSignupDetector) generateKey(template string, reqCtx *plugins.RequestContext) string {
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
func (d *MultipleSignupDetector) extractUsername(reqCtx *plugins.RequestContext) string {
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

// ResetSignups resets the signup count for an IP
func (d *MultipleSignupDetector) ResetSignups(ctx context.Context, ip string) error {
	key := strings.Replace(d.config.KeyTemplate, "{ip}", ip, -1)
	return d.store.Delete(ctx, key)
}

// GetSignupCount returns the current signup count for an IP
func (d *MultipleSignupDetector) GetSignupCount(ctx context.Context, ip string) (int64, error) {
	key := strings.Replace(d.config.KeyTemplate, "{ip}", ip, -1)

	count, err := d.store.Get(ctx, key)
	if err != nil {
		return 0, nil // No signups if key doesn't exist
	}

	if countVal, ok := count.(int64); ok {
		return countVal, nil
	}

	return 0, nil
}

// Cleanup cleans up plugin resources
func (d *MultipleSignupDetector) Cleanup() error {
	return nil
}

// Health checks plugin health
func (d *MultipleSignupDetector) Health() error {
	if d.store == nil {
		return fmt.Errorf("state store not initialized")
	}
	return d.store.Health()
}

// GetMetrics returns plugin metrics
func (d *MultipleSignupDetector) GetMetrics() map[string]any {
	d.mu.RLock()
	defer d.mu.RUnlock()

	detectionRate := float64(0)
	if d.metrics.signupAttempts > 0 {
		detectionRate = float64(d.metrics.threatsFound) / float64(d.metrics.signupAttempts)
	}

	return map[string]any{
		"total_checks":     d.metrics.totalChecks,
		"threats_found":    d.metrics.threatsFound,
		"signup_attempts":  d.metrics.signupAttempts,
		"blocked_attempts": d.metrics.blockedAttempts,
		"detection_rate":   detectionRate,
		"max_signups":      d.config.MaxSignups,
		"window_size":      d.config.WindowSize.String(),
		"signup_endpoints": len(d.config.SignupEndpoints),
	}
}
