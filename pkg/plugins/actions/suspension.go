package actions

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/guard/pkg/store"
)

// SuspensionAction implements ActionPlugin for temporary suspensions lasting days
type SuspensionAction struct {
	name        string
	version     string
	description string
	store       store.StateStore
	config      SuspensionConfig
	metrics     struct {
		totalSuspensions  int64
		shortSuspensions  int64 // 1-3 days
		mediumSuspensions int64 // 4-7 days
		longSuspensions   int64 // 8-30 days
		activeSuspensions int64
	}
	mu sync.RWMutex
}

// SuspensionConfig holds configuration for suspension action
type SuspensionConfig struct {
	ShortDuration     time.Duration              `json:"short_duration"`  // 1 day
	MediumDuration    time.Duration              `json:"medium_duration"` // 7 days
	LongDuration      time.Duration              `json:"long_duration"`   // 30 days
	MaxDuration       time.Duration              `json:"max_duration"`    // 90 days
	EscalationRules   []SuspensionEscalationRule `json:"escalation_rules"`
	SuspensionMessage string                     `json:"suspension_message"`
	NotifyUser        bool                       `json:"notify_user"`
	LogSuspensions    bool                       `json:"log_suspensions"`
}

// SuspensionEscalationRule defines how to escalate suspensions
type SuspensionEscalationRule struct {
	ViolationCount int           `json:"violation_count"`
	Duration       time.Duration `json:"duration"`
	SuspensionType string        `json:"suspension_type"` // "short", "medium", "long", "max"
}

// SuspensionInfo represents an active suspension
type SuspensionInfo struct {
	ID             string                 `json:"id"`
	IP             string                 `json:"ip"`
	UserID         string                 `json:"user_id"`
	StartTime      time.Time              `json:"start_time"`
	EndTime        time.Time              `json:"end_time"`
	Duration       time.Duration          `json:"duration"`
	Reason         string                 `json:"reason"`
	SuspensionType string                 `json:"suspension_type"`
	ViolationCount int64                  `json:"violation_count"`
	Severity       int                    `json:"severity"`
	Metadata       map[string]interface{} `json:"metadata"`
	IsActive       bool                   `json:"is_active"`
}

// NewSuspensionAction creates a new suspension action plugin
func NewSuspensionAction(stateStore store.StateStore) *SuspensionAction {
	return &SuspensionAction{
		name:        "suspension_action",
		version:     "1.0.0",
		description: "Implements temporary suspensions for days with escalation rules",
		store:       stateStore,
		config: SuspensionConfig{
			ShortDuration:  24 * time.Hour,
			MediumDuration: 7 * 24 * time.Hour,
			LongDuration:   30 * 24 * time.Hour,
			MaxDuration:    90 * 24 * time.Hour,
			EscalationRules: []SuspensionEscalationRule{
				{ViolationCount: 1, Duration: 24 * time.Hour, SuspensionType: "short"},
				{ViolationCount: 3, Duration: 3 * 24 * time.Hour, SuspensionType: "short"},
				{ViolationCount: 5, Duration: 7 * 24 * time.Hour, SuspensionType: "medium"},
				{ViolationCount: 10, Duration: 30 * 24 * time.Hour, SuspensionType: "long"},
				{ViolationCount: 20, Duration: 90 * 24 * time.Hour, SuspensionType: "max"},
			},
			SuspensionMessage: "Your access has been temporarily suspended due to security policy violations",
			NotifyUser:        true,
			LogSuspensions:    true,
		},
	}
}

// Name returns the plugin name
func (a *SuspensionAction) Name() string {
	return a.name
}

// Version returns the plugin version
func (a *SuspensionAction) Version() string {
	return a.version
}

// Description returns the plugin description
func (a *SuspensionAction) Description() string {
	return a.description
}

// Initialize initializes the plugin with configuration
func (a *SuspensionAction) Initialize(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Parse durations
	if shortStr, ok := config["short_duration"].(string); ok {
		if duration, err := time.ParseDuration(shortStr); err == nil {
			a.config.ShortDuration = duration
		}
	}

	if mediumStr, ok := config["medium_duration"].(string); ok {
		if duration, err := time.ParseDuration(mediumStr); err == nil {
			a.config.MediumDuration = duration
		}
	}

	if longStr, ok := config["long_duration"].(string); ok {
		if duration, err := time.ParseDuration(longStr); err == nil {
			a.config.LongDuration = duration
		}
	}

	if maxStr, ok := config["max_duration"].(string); ok {
		if duration, err := time.ParseDuration(maxStr); err == nil {
			a.config.MaxDuration = duration
		}
	}

	// Parse suspension message
	if message, ok := config["suspension_message"].(string); ok {
		a.config.SuspensionMessage = message
	}

	// Parse notify user
	if notify, ok := config["notify_user"].(bool); ok {
		a.config.NotifyUser = notify
	}

	// Parse log suspensions
	if logSuspensions, ok := config["log_suspensions"].(bool); ok {
		a.config.LogSuspensions = logSuspensions
	}

	return nil
}

// Execute executes the suspension action
func (a *SuspensionAction) Execute(ctx context.Context, reqCtx *plugins.RequestContext, result plugins.RuleResult) error {
	a.mu.RLock()
	config := a.config
	a.mu.RUnlock()

	a.metrics.totalSuspensions++

	// Generate keys
	suspensionKey := fmt.Sprintf("suspension:%s", reqCtx.IP)
	violationKey := fmt.Sprintf("susp_violations:%s", reqCtx.IP)

	// Get current violation count
	violationCount, err := a.store.Increment(ctx, violationKey, 1)
	if err != nil {
		violationCount = 1
		a.store.Set(ctx, violationKey, violationCount, 365*24*time.Hour) // Keep for a year
	}

	// Determine suspension duration and type
	duration, suspensionType := a.determineSuspension(violationCount, config)

	// Update metrics
	a.updateMetrics(suspensionType)

	// Generate suspension ID
	suspensionID := fmt.Sprintf("susp_%d_%s", time.Now().Unix(), reqCtx.IP)

	// Create suspension info
	suspensionInfo := SuspensionInfo{
		ID:             suspensionID,
		IP:             reqCtx.IP,
		UserID:         reqCtx.UserID,
		StartTime:      time.Now(),
		EndTime:        time.Now().Add(duration),
		Duration:       duration,
		Reason:         fmt.Sprintf("Suspension level %s - violation #%d: %s", suspensionType, violationCount, result.Details),
		SuspensionType: suspensionType,
		ViolationCount: violationCount,
		Severity:       result.Severity,
		Metadata: map[string]interface{}{
			"rule_name":  result.RuleName,
			"confidence": result.Confidence,
			"user_agent": reqCtx.UserAgent,
			"path":       reqCtx.Path,
			"method":     reqCtx.Method,
		},
		IsActive: true,
	}

	// Set suspension in store
	err = a.store.Set(ctx, suspensionKey, suspensionInfo, duration)
	if err != nil {
		return fmt.Errorf("failed to set suspension: %w", err)
	}

	a.metrics.activeSuspensions++

	return nil
}

// determineSuspension determines the appropriate suspension duration and type
func (a *SuspensionAction) determineSuspension(violationCount int64, config SuspensionConfig) (time.Duration, string) {
	// Find the appropriate escalation rule
	for i := len(config.EscalationRules) - 1; i >= 0; i-- {
		rule := config.EscalationRules[i]
		if violationCount >= int64(rule.ViolationCount) {
			return rule.Duration, rule.SuspensionType
		}
	}

	// Default to short suspension
	return config.ShortDuration, "short"
}

// updateMetrics updates the metrics based on suspension type
func (a *SuspensionAction) updateMetrics(suspensionType string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch suspensionType {
	case "short":
		a.metrics.shortSuspensions++
	case "medium":
		a.metrics.mediumSuspensions++
	case "long", "max":
		a.metrics.longSuspensions++
	}
}

// IsSuspended checks if an IP/User is currently suspended
func (a *SuspensionAction) IsSuspended(ctx context.Context, ip string) (bool, SuspensionInfo, error) {
	suspensionKey := fmt.Sprintf("suspension:%s", ip)

	suspensionData, err := a.store.Get(ctx, suspensionKey)
	if err != nil {
		return false, SuspensionInfo{}, nil // Not suspended if key doesn't exist
	}

	if info, ok := suspensionData.(SuspensionInfo); ok {
		// Check if suspension is still active
		if time.Now().Before(info.EndTime) && info.IsActive {
			return true, info, nil
		} else {
			// Suspension expired, clean up
			a.store.Delete(ctx, suspensionKey)
			a.metrics.activeSuspensions--
		}
	}

	return false, SuspensionInfo{}, nil
}

// GetViolationCount returns the current violation count for an IP
func (a *SuspensionAction) GetViolationCount(ctx context.Context, ip string) (int64, error) {
	violationKey := fmt.Sprintf("susp_violations:%s", ip)

	count, err := a.store.Get(ctx, violationKey)
	if err != nil {
		return 0, nil // No violations if key doesn't exist
	}

	if countVal, ok := count.(int64); ok {
		return countVal, nil
	}

	return 0, nil
}

// LiftSuspension manually lifts a suspension for an IP
func (a *SuspensionAction) LiftSuspension(ctx context.Context, ip string, reason string) error {
	suspensionKey := fmt.Sprintf("suspension:%s", ip)

	// Get current suspension
	suspended, info, err := a.IsSuspended(ctx, ip)
	if err != nil {
		return err
	}

	if suspended {
		// Mark as inactive and update
		info.IsActive = false
		info.Metadata["lift_reason"] = reason
		info.Metadata["lifted_at"] = time.Now()

		// Update in store with short TTL for record keeping
		err = a.store.Set(ctx, suspensionKey, info, 24*time.Hour)
		if err != nil {
			return fmt.Errorf("failed to update suspension: %w", err)
		}

		a.metrics.activeSuspensions--
	}

	return nil
}

// GetActiveSuspensions returns all currently active suspensions
func (a *SuspensionAction) GetActiveSuspensions(ctx context.Context) (map[string]SuspensionInfo, error) {
	keys, err := a.store.Keys(ctx, "suspension:*")
	if err != nil {
		return nil, err
	}

	activeSuspensions := make(map[string]SuspensionInfo)
	for _, key := range keys {
		// Extract IP from key (remove "suspension:" prefix)
		if len(key) > 11 {
			ip := key[11:]
			if suspended, info, err := a.IsSuspended(ctx, ip); err == nil && suspended {
				activeSuspensions[ip] = info
			}
		}
	}

	return activeSuspensions, nil
}

// Cleanup cleans up plugin resources
func (a *SuspensionAction) Cleanup() error {
	return nil
}

// Health checks plugin health
func (a *SuspensionAction) Health() error {
	if a.store == nil {
		return fmt.Errorf("state store not initialized")
	}
	return a.store.Health()
}

// GetMetrics returns plugin metrics
func (a *SuspensionAction) GetMetrics() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return map[string]interface{}{
		"total_suspensions":  a.metrics.totalSuspensions,
		"short_suspensions":  a.metrics.shortSuspensions,
		"medium_suspensions": a.metrics.mediumSuspensions,
		"long_suspensions":   a.metrics.longSuspensions,
		"active_suspensions": a.metrics.activeSuspensions,
		"short_duration":     a.config.ShortDuration.String(),
		"medium_duration":    a.config.MediumDuration.String(),
		"long_duration":      a.config.LongDuration.String(),
		"max_duration":       a.config.MaxDuration.String(),
		"escalation_rules":   len(a.config.EscalationRules),
	}
}

func (a *SuspensionAction) Render(ctx context.Context, c *fiber.Ctx, data map[string]any) error {
	return c.Next()
}
