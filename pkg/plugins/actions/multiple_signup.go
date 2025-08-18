package actions

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/guard/pkg/store"
)

// MultipleSignupAction implements ActionPlugin for handling multiple signup attempts
type MultipleSignupAction struct {
	name        string
	version     string
	description string
	store       store.StateStore
	config      MultipleSignupConfig
	metrics     struct {
		totalSignups      int64
		blockedSignups    int64
		warningSignups    int64
		suspiciousSignups int64
		escalatedSignups  int64
	}
	mu sync.RWMutex
}

// MultipleSignupConfig holds configuration for multiple signup action
type MultipleSignupConfig struct {
	LogMultipleSignups    bool                       `json:"log_multiple_signups"`
	NotificationThreshold int                        `json:"notification_threshold"`
	EscalationRules       []MultipleSignupEscalation `json:"escalation_rules"`
	WindowDuration        time.Duration              `json:"window_duration"`
	MaxSignupsPerWindow   int                        `json:"max_signups_per_window"`
	BlockDuration         time.Duration              `json:"block_duration"`
	EnableNotifications   bool                       `json:"enable_notifications"`
}

// MultipleSignupEscalation defines escalation rules for multiple signups
type MultipleSignupEscalation struct {
	SignupCount int           `json:"signup_count"`
	Action      string        `json:"action"` // "log", "warn", "block", "permanent_block"
	Description string        `json:"description"`
	Duration    time.Duration `json:"duration,omitempty"`
}

// MultipleSignupInfo represents signup tracking information
type MultipleSignupInfo struct {
	IP            string                 `json:"ip"`
	SignupCount   int64                  `json:"signup_count"`
	FirstSignup   time.Time              `json:"first_signup"`
	LastSignup    time.Time              `json:"last_signup"`
	Usernames     []string               `json:"usernames"`
	Emails        []string               `json:"emails"`
	IsBlocked     bool                   `json:"is_blocked"`
	BlockedAt     *time.Time             `json:"blocked_at,omitempty"`
	BlockDuration time.Duration          `json:"block_duration"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// NewMultipleSignupAction creates a new multiple signup action plugin
func NewMultipleSignupAction(stateStore store.StateStore) *MultipleSignupAction {
	return &MultipleSignupAction{
		name:        "multiple_signup_action",
		version:     "1.0.0",
		description: "Handles multiple signup attempts from the same IP address",
		store:       stateStore,
		config: MultipleSignupConfig{
			LogMultipleSignups:    true,
			NotificationThreshold: 3,
			WindowDuration:        time.Hour,
			MaxSignupsPerWindow:   2,
			BlockDuration:         time.Hour,
			EnableNotifications:   true,
			EscalationRules: []MultipleSignupEscalation{
				{SignupCount: 3, Action: "log", Description: "Log multiple signup attempts"},
				{SignupCount: 5, Action: "warn", Description: "Send warning notification"},
				{SignupCount: 10, Action: "block", Description: "Temporarily block IP", Duration: time.Hour},
				{SignupCount: 20, Action: "permanent_block", Description: "Permanently block IP"},
			},
		},
	}
}

// Name returns the plugin name
func (a *MultipleSignupAction) Name() string {
	return a.name
}

// Version returns the plugin version
func (a *MultipleSignupAction) Version() string {
	return a.version
}

// Description returns the plugin description
func (a *MultipleSignupAction) Description() string {
	return a.description
}

// Initialize initializes the plugin with configuration
func (a *MultipleSignupAction) Initialize(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Parse log multiple signups
	if logSignups, ok := config["log_multiple_signups"].(bool); ok {
		a.config.LogMultipleSignups = logSignups
	}

	// Parse notification threshold
	if threshold, ok := config["notification_threshold"].(float64); ok {
		a.config.NotificationThreshold = int(threshold)
	}

	// Parse window duration
	if windowStr, ok := config["window_duration"].(string); ok {
		if duration, err := time.ParseDuration(windowStr); err == nil {
			a.config.WindowDuration = duration
		}
	}

	// Parse max signups per window
	if maxSignups, ok := config["max_signups_per_window"].(float64); ok {
		a.config.MaxSignupsPerWindow = int(maxSignups)
	}

	// Parse block duration
	if blockStr, ok := config["block_duration"].(string); ok {
		if duration, err := time.ParseDuration(blockStr); err == nil {
			a.config.BlockDuration = duration
		}
	}

	// Parse enable notifications
	if enableNotifications, ok := config["enable_notifications"].(bool); ok {
		a.config.EnableNotifications = enableNotifications
	}

	// Parse escalation rules
	if escalationRaw, ok := config["escalation_rules"].([]interface{}); ok {
		a.config.EscalationRules = []MultipleSignupEscalation{}
		for _, ruleRaw := range escalationRaw {
			if ruleMap, ok := ruleRaw.(map[string]interface{}); ok {
				rule := MultipleSignupEscalation{}
				if count, ok := ruleMap["signup_count"].(float64); ok {
					rule.SignupCount = int(count)
				}
				if action, ok := ruleMap["action"].(string); ok {
					rule.Action = action
				}
				if desc, ok := ruleMap["description"].(string); ok {
					rule.Description = desc
				}
				if durStr, ok := ruleMap["duration"].(string); ok {
					if duration, err := time.ParseDuration(durStr); err == nil {
						rule.Duration = duration
					}
				}
				a.config.EscalationRules = append(a.config.EscalationRules, rule)
			}
		}
	}

	return nil
}

// Execute executes the multiple signup action
func (a *MultipleSignupAction) Execute(ctx context.Context, reqCtx *plugins.RequestContext, result plugins.RuleResult) error {
	a.mu.RLock()
	config := a.config
	a.mu.RUnlock()

	a.metrics.totalSignups++

	// Generate keys
	signupKey := fmt.Sprintf("multiple_signup:%s", reqCtx.IP)
	windowKey := fmt.Sprintf("signup_window:%s:%s", reqCtx.IP, time.Now().Format("2006-01-02-15"))

	// Get current signup info
	var signupInfo MultipleSignupInfo
	if existingData, err := a.store.Get(ctx, signupKey); err == nil {
		if existing, ok := existingData.(MultipleSignupInfo); ok {
			signupInfo = existing
		}
	}

	// Initialize if new
	if signupInfo.IP == "" {
		signupInfo = MultipleSignupInfo{
			IP:          reqCtx.IP,
			SignupCount: 0,
			FirstSignup: time.Now(),
			Usernames:   []string{},
			Emails:      []string{},
			Metadata:    make(map[string]interface{}),
		}
	}

	// Update signup info
	signupInfo.SignupCount++
	signupInfo.LastSignup = time.Now()

	// Extract username and email from request body if available
	if reqCtx.Body != "" {
		// Simple extraction - in real implementation, you'd parse JSON properly
		signupInfo.Metadata["last_request_body"] = reqCtx.Body
		signupInfo.Metadata["user_agent"] = reqCtx.UserAgent
		signupInfo.Metadata["path"] = reqCtx.Path
	}

	// Check window-based signups
	windowCount, _ := a.store.Increment(ctx, windowKey, 1)
	a.store.Set(ctx, windowKey, windowCount, config.WindowDuration)

	// Determine action based on escalation rules
	action := a.determineAction(signupInfo.SignupCount, config)

	// Execute the determined action
	switch action.Action {
	case "log":
		if config.LogMultipleSignups {
			signupInfo.Metadata["action"] = "logged"
			signupInfo.Metadata["logged_at"] = time.Now()
		}
	case "warn":
		a.metrics.warningSignups++
		signupInfo.Metadata["action"] = "warned"
		signupInfo.Metadata["warned_at"] = time.Now()
	case "block":
		a.metrics.blockedSignups++
		signupInfo.IsBlocked = true
		now := time.Now()
		signupInfo.BlockedAt = &now
		signupInfo.BlockDuration = action.Duration
		if signupInfo.BlockDuration == 0 {
			signupInfo.BlockDuration = config.BlockDuration
		}
		signupInfo.Metadata["action"] = "blocked"
		signupInfo.Metadata["blocked_at"] = now
	case "permanent_block":
		a.metrics.blockedSignups++
		signupInfo.IsBlocked = true
		now := time.Now()
		signupInfo.BlockedAt = &now
		signupInfo.BlockDuration = 0 // Permanent
		signupInfo.Metadata["action"] = "permanent_block"
		signupInfo.Metadata["blocked_at"] = now
	}

	// Store updated signup info
	ttl := 24 * time.Hour
	if signupInfo.IsBlocked && signupInfo.BlockDuration > 0 {
		ttl = signupInfo.BlockDuration
	}

	err := a.store.Set(ctx, signupKey, signupInfo, ttl)
	if err != nil {
		return fmt.Errorf("failed to store signup info: %w", err)
	}

	// Update metrics
	if signupInfo.SignupCount >= int64(config.NotificationThreshold) {
		a.metrics.suspiciousSignups++
	}
	if action.Action != "log" {
		a.metrics.escalatedSignups++
	}

	return nil
}

// determineAction determines the appropriate action based on signup count
func (a *MultipleSignupAction) determineAction(signupCount int64, config MultipleSignupConfig) MultipleSignupEscalation {
	// Find the highest matching escalation rule
	var selectedRule MultipleSignupEscalation
	for _, rule := range config.EscalationRules {
		if signupCount >= int64(rule.SignupCount) {
			selectedRule = rule
		}
	}

	// Default to log if no rule matches
	if selectedRule.Action == "" {
		selectedRule = MultipleSignupEscalation{
			SignupCount: 1,
			Action:      "log",
			Description: "Default logging action",
		}
	}

	return selectedRule
}

// IsBlocked checks if an IP is currently blocked for multiple signups
func (a *MultipleSignupAction) IsBlocked(ctx context.Context, ip string) (bool, *MultipleSignupInfo, error) {
	signupKey := fmt.Sprintf("multiple_signup:%s", ip)

	signupData, err := a.store.Get(ctx, signupKey)
	if err != nil {
		return false, nil, nil // Not blocked if key doesn't exist
	}

	if info, ok := signupData.(MultipleSignupInfo); ok {
		if info.IsBlocked {
			// Check if temporary block has expired
			if info.BlockDuration > 0 && info.BlockedAt != nil {
				if time.Since(*info.BlockedAt) > info.BlockDuration {
					// Block expired, unblock
					info.IsBlocked = false
					info.BlockedAt = nil
					a.store.Set(ctx, signupKey, info, 24*time.Hour)
					return false, &info, nil
				}
			}
			return true, &info, nil
		}
	}

	return false, nil, nil
}

// GetSignupInfo retrieves signup information for an IP
func (a *MultipleSignupAction) GetSignupInfo(ctx context.Context, ip string) (*MultipleSignupInfo, error) {
	signupKey := fmt.Sprintf("multiple_signup:%s", ip)

	signupData, err := a.store.Get(ctx, signupKey)
	if err != nil {
		return nil, nil // No info if key doesn't exist
	}

	if info, ok := signupData.(MultipleSignupInfo); ok {
		return &info, nil
	}

	return nil, nil
}

// ClearSignupInfo clears signup information for an IP
func (a *MultipleSignupAction) ClearSignupInfo(ctx context.Context, ip string) error {
	signupKey := fmt.Sprintf("multiple_signup:%s", ip)
	return a.store.Delete(ctx, signupKey)
}

// Cleanup cleans up plugin resources
func (a *MultipleSignupAction) Cleanup() error {
	return nil
}

// Health checks plugin health
func (a *MultipleSignupAction) Health() error {
	if a.store == nil {
		return fmt.Errorf("state store not initialized")
	}
	return a.store.Health()
}

// GetMetrics returns plugin metrics
func (a *MultipleSignupAction) GetMetrics() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return map[string]interface{}{
		"total_signups":      a.metrics.totalSignups,
		"blocked_signups":    a.metrics.blockedSignups,
		"warning_signups":    a.metrics.warningSignups,
		"suspicious_signups": a.metrics.suspiciousSignups,
		"escalated_signups":  a.metrics.escalatedSignups,
		"window_duration":    a.config.WindowDuration.String(),
		"max_signups_window": a.config.MaxSignupsPerWindow,
		"block_duration":     a.config.BlockDuration.String(),
		"escalation_rules":   len(a.config.EscalationRules),
	}
}
