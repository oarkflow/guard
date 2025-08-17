package actions

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/guard/pkg/store"
)

// WarningAction implements ActionPlugin for displaying warning messages
type WarningAction struct {
	name        string
	version     string
	description string
	store       store.StateStore
	config      WarningConfig
	metrics     struct {
		totalWarnings  int64
		apiWarnings    int64
		pageWarnings   int64
		emailWarnings  int64
		activeWarnings int64
	}
	mu sync.RWMutex
}

// WarningConfig holds configuration for warning action
type WarningConfig struct {
	WarningTypes      []string                `json:"warning_types"` // "api", "page", "email", "popup"
	DefaultMessage    string                  `json:"default_message"`
	MessageTemplates  map[string]string       `json:"message_templates"` // Templates by severity/type
	ShowDuration      time.Duration           `json:"show_duration"`     // How long to show warning
	CooldownPeriod    time.Duration           `json:"cooldown_period"`   // Time between warnings for same IP
	MaxWarningsPerDay int                     `json:"max_warnings_per_day"`
	IncludeDetails    bool                    `json:"include_details"` // Include threat details in warning
	LogWarnings       bool                    `json:"log_warnings"`
	EscalationRules   []WarningEscalationRule `json:"escalation_rules"`
}

// WarningEscalationRule defines how warnings escalate
type WarningEscalationRule struct {
	ViolationCount int           `json:"violation_count"`
	WarningType    string        `json:"warning_type"` // "info", "warning", "error", "critical"
	MessageKey     string        `json:"message_key"`  // Key for message template
	ShowDuration   time.Duration `json:"show_duration"`
	RequireAck     bool          `json:"require_ack"` // Require user acknowledgment
}

// WarningInfo represents an active warning
type WarningInfo struct {
	ID             string                 `json:"id"`
	IP             string                 `json:"ip"`
	UserID         string                 `json:"user_id"`
	WarningType    string                 `json:"warning_type"` // "info", "warning", "error", "critical"
	DisplayType    string                 `json:"display_type"` // "api", "page", "email", "popup"
	Message        string                 `json:"message"`
	Details        string                 `json:"details"`
	Severity       int                    `json:"severity"`
	ViolationCount int64                  `json:"violation_count"`
	StartTime      time.Time              `json:"start_time"`
	EndTime        time.Time              `json:"end_time"`
	IsActive       bool                   `json:"is_active"`
	RequireAck     bool                   `json:"require_ack"`
	Acknowledged   bool                   `json:"acknowledged"`
	AckTime        *time.Time             `json:"ack_time,omitempty"`
	Metadata       map[string]interface{} `json:"metadata"`
	CreatedAt      time.Time              `json:"created_at"`
}

// NewWarningAction creates a new warning action plugin
func NewWarningAction(stateStore store.StateStore) *WarningAction {
	return &WarningAction{
		name:        "warning_action",
		version:     "1.0.0",
		description: "Displays warning messages on API responses or web pages",
		store:       stateStore,
		config: WarningConfig{
			WarningTypes:      []string{"api", "page"},
			DefaultMessage:    "Security warning: Suspicious activity detected from your connection",
			ShowDuration:      30 * time.Minute,
			CooldownPeriod:    5 * time.Minute,
			MaxWarningsPerDay: 10,
			IncludeDetails:    false,
			LogWarnings:       true,
			MessageTemplates: map[string]string{
				"info":     "Information: Please be aware that your activity is being monitored for security purposes",
				"warning":  "Warning: Suspicious activity detected. Please ensure you are following security guidelines",
				"error":    "Error: Security policy violation detected. Your access may be restricted if this continues",
				"critical": "Critical: Severe security violation detected. Your access is being reviewed",
			},
			EscalationRules: []WarningEscalationRule{
				{ViolationCount: 1, WarningType: "info", MessageKey: "info", ShowDuration: 15 * time.Minute, RequireAck: false},
				{ViolationCount: 3, WarningType: "warning", MessageKey: "warning", ShowDuration: 30 * time.Minute, RequireAck: false},
				{ViolationCount: 5, WarningType: "error", MessageKey: "error", ShowDuration: 60 * time.Minute, RequireAck: true},
				{ViolationCount: 10, WarningType: "critical", MessageKey: "critical", ShowDuration: 120 * time.Minute, RequireAck: true},
			},
		},
	}
}

// Name returns the plugin name
func (a *WarningAction) Name() string {
	return a.name
}

// Version returns the plugin version
func (a *WarningAction) Version() string {
	return a.version
}

// Description returns the plugin description
func (a *WarningAction) Description() string {
	return a.description
}

// Initialize initializes the plugin with configuration
func (a *WarningAction) Initialize(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Parse warning types
	if warningTypes, ok := config["warning_types"].([]interface{}); ok {
		a.config.WarningTypes = make([]string, len(warningTypes))
		for i, wt := range warningTypes {
			if wtStr, ok := wt.(string); ok {
				a.config.WarningTypes[i] = wtStr
			}
		}
	}

	// Parse default message
	if message, ok := config["default_message"].(string); ok {
		a.config.DefaultMessage = message
	}

	// Parse show duration
	if showDurStr, ok := config["show_duration"].(string); ok {
		if duration, err := time.ParseDuration(showDurStr); err == nil {
			a.config.ShowDuration = duration
		}
	}

	// Parse cooldown period
	if cooldownStr, ok := config["cooldown_period"].(string); ok {
		if duration, err := time.ParseDuration(cooldownStr); err == nil {
			a.config.CooldownPeriod = duration
		}
	}

	// Parse max warnings per day
	if maxWarnings, ok := config["max_warnings_per_day"].(float64); ok {
		a.config.MaxWarningsPerDay = int(maxWarnings)
	}

	// Parse include details
	if includeDetails, ok := config["include_details"].(bool); ok {
		a.config.IncludeDetails = includeDetails
	}

	// Parse log warnings
	if logWarnings, ok := config["log_warnings"].(bool); ok {
		a.config.LogWarnings = logWarnings
	}

	return nil
}

// Execute executes the warning action
func (a *WarningAction) Execute(ctx context.Context, reqCtx *plugins.RequestContext, result plugins.RuleResult) error {
	a.mu.RLock()
	config := a.config
	a.mu.RUnlock()

	a.metrics.totalWarnings++

	// Generate keys
	warningKey := fmt.Sprintf("warning:%s", reqCtx.IP)
	violationKey := fmt.Sprintf("warn_violations:%s", reqCtx.IP)
	dailyCountKey := fmt.Sprintf("warn_daily:%s:%s", reqCtx.IP, time.Now().Format("2006-01-02"))

	// Check daily limit
	dailyCount, _ := a.store.Get(ctx, dailyCountKey)
	if count, ok := dailyCount.(int64); ok && count >= int64(config.MaxWarningsPerDay) {
		return fmt.Errorf("daily warning limit reached for IP %s", reqCtx.IP)
	}

	// Check cooldown period
	if existingWarning, err := a.store.Get(ctx, warningKey); err == nil {
		if warning, ok := existingWarning.(WarningInfo); ok && warning.IsActive {
			if time.Since(warning.CreatedAt) < config.CooldownPeriod {
				return fmt.Errorf("warning cooldown period active for IP %s", reqCtx.IP)
			}
		}
	}

	// Get current violation count
	violationCount, err := a.store.Increment(ctx, violationKey, 1)
	if err != nil {
		violationCount = 1
		a.store.Set(ctx, violationKey, violationCount, 24*time.Hour) // Reset daily
	}

	// Increment daily count
	a.store.Increment(ctx, dailyCountKey, 1)
	a.store.Set(ctx, dailyCountKey, violationCount, 24*time.Hour)

	// Determine warning type and settings
	warningType, messageKey, showDuration, requireAck := a.determineWarning(violationCount, config)

	// Get message template
	message := a.getWarningMessage(messageKey, config, result)

	// Determine display type (prefer API for programmatic access)
	displayType := "api"
	if len(config.WarningTypes) > 0 {
		displayType = config.WarningTypes[0]
	}

	// Update metrics
	a.updateMetrics(displayType)

	// Generate warning ID
	warningID := fmt.Sprintf("warn_%d_%s", time.Now().Unix(), reqCtx.IP)

	// Create warning info
	warningInfo := WarningInfo{
		ID:             warningID,
		IP:             reqCtx.IP,
		UserID:         reqCtx.UserID,
		WarningType:    warningType,
		DisplayType:    displayType,
		Message:        message,
		Details:        result.Details,
		Severity:       result.Severity,
		ViolationCount: violationCount,
		StartTime:      time.Now(),
		EndTime:        time.Now().Add(showDuration),
		IsActive:       true,
		RequireAck:     requireAck,
		Acknowledged:   false,
		Metadata: map[string]interface{}{
			"rule_name":   result.RuleName,
			"confidence":  result.Confidence,
			"user_agent":  reqCtx.UserAgent,
			"path":        reqCtx.Path,
			"method":      reqCtx.Method,
			"message_key": messageKey,
		},
		CreatedAt: time.Now(),
	}

	// Set warning in store
	err = a.store.Set(ctx, warningKey, warningInfo, showDuration)
	if err != nil {
		return fmt.Errorf("failed to set warning: %w", err)
	}

	a.metrics.activeWarnings++

	return nil
}

// determineWarning determines the appropriate warning type and settings
func (a *WarningAction) determineWarning(violationCount int64, config WarningConfig) (string, string, time.Duration, bool) {
	// Find the appropriate escalation rule
	for i := len(config.EscalationRules) - 1; i >= 0; i-- {
		rule := config.EscalationRules[i]
		if violationCount >= int64(rule.ViolationCount) {
			duration := rule.ShowDuration
			if duration == 0 {
				duration = config.ShowDuration
			}
			return rule.WarningType, rule.MessageKey, duration, rule.RequireAck
		}
	}

	// Default warning
	return "info", "info", config.ShowDuration, false
}

// getWarningMessage gets the appropriate warning message
func (a *WarningAction) getWarningMessage(messageKey string, config WarningConfig, result plugins.RuleResult) string {
	// Get template message
	message := config.DefaultMessage
	if template, exists := config.MessageTemplates[messageKey]; exists {
		message = template
	}

	// Add details if configured
	if config.IncludeDetails && result.Details != "" {
		message = fmt.Sprintf("%s (Details: %s)", message, result.Details)
	}

	return message
}

// updateMetrics updates the metrics based on display type
func (a *WarningAction) updateMetrics(displayType string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch displayType {
	case "api":
		a.metrics.apiWarnings++
	case "page":
		a.metrics.pageWarnings++
	case "email":
		a.metrics.emailWarnings++
	}
}

// GetActiveWarning retrieves the active warning for an IP
func (a *WarningAction) GetActiveWarning(ctx context.Context, ip string) (bool, WarningInfo, error) {
	warningKey := fmt.Sprintf("warning:%s", ip)

	warningData, err := a.store.Get(ctx, warningKey)
	if err != nil {
		return false, WarningInfo{}, nil // No warning if key doesn't exist
	}

	if info, ok := warningData.(WarningInfo); ok {
		// Check if warning is still active
		if info.IsActive && time.Now().Before(info.EndTime) {
			return true, info, nil
		} else if info.IsActive {
			// Warning expired, deactivate
			info.IsActive = false
			a.store.Set(ctx, warningKey, info, 24*time.Hour) // Keep for 24 hours
			a.metrics.activeWarnings--
		}
	}

	return false, WarningInfo{}, nil
}

// AcknowledgeWarning acknowledges a warning (for warnings that require acknowledgment)
func (a *WarningAction) AcknowledgeWarning(ctx context.Context, ip string) error {
	hasWarning, info, err := a.GetActiveWarning(ctx, ip)
	if err != nil {
		return err
	}

	if !hasWarning {
		return fmt.Errorf("no active warning found for IP %s", ip)
	}

	if !info.RequireAck {
		return fmt.Errorf("warning does not require acknowledgment")
	}

	if info.Acknowledged {
		return fmt.Errorf("warning already acknowledged")
	}

	// Update acknowledgment
	now := time.Now()
	info.Acknowledged = true
	info.AckTime = &now
	info.Metadata["acknowledged_at"] = now

	warningKey := fmt.Sprintf("warning:%s", ip)
	err = a.store.Set(ctx, warningKey, info, time.Until(info.EndTime))
	if err != nil {
		return fmt.Errorf("failed to acknowledge warning: %w", err)
	}

	return nil
}

// GetWarningForResponse formats warning for API response
func (a *WarningAction) GetWarningForResponse(ctx context.Context, ip string) map[string]interface{} {
	hasWarning, info, err := a.GetActiveWarning(ctx, ip)
	if err != nil || !hasWarning {
		return nil
	}

	response := map[string]interface{}{
		"warning": map[string]interface{}{
			"id":           info.ID,
			"type":         info.WarningType,
			"message":      info.Message,
			"severity":     info.Severity,
			"require_ack":  info.RequireAck,
			"acknowledged": info.Acknowledged,
			"expires_at":   info.EndTime,
		},
	}

	// Add details if configured
	if a.config.IncludeDetails && info.Details != "" {
		response["warning"].(map[string]interface{})["details"] = info.Details
	}

	return response
}

// ClearWarning manually clears a warning for an IP
func (a *WarningAction) ClearWarning(ctx context.Context, ip string) error {
	warningKey := fmt.Sprintf("warning:%s", ip)

	hasWarning, info, err := a.GetActiveWarning(ctx, ip)
	if err != nil {
		return err
	}

	if hasWarning {
		info.IsActive = false
		info.Metadata["cleared_at"] = time.Now()

		// Keep for 24 hours for record keeping
		err = a.store.Set(ctx, warningKey, info, 24*time.Hour)
		if err != nil {
			return fmt.Errorf("failed to clear warning: %w", err)
		}

		a.metrics.activeWarnings--
	}

	return nil
}

// GetActiveWarnings returns all currently active warnings
func (a *WarningAction) GetActiveWarnings(ctx context.Context) (map[string]WarningInfo, error) {
	keys, err := a.store.Keys(ctx, "warning:*")
	if err != nil {
		return nil, err
	}

	activeWarnings := make(map[string]WarningInfo)
	for _, key := range keys {
		// Extract IP from key (remove "warning:" prefix)
		if len(key) > 8 {
			ip := key[8:]
			if hasWarning, info, err := a.GetActiveWarning(ctx, ip); err == nil && hasWarning {
				activeWarnings[ip] = info
			}
		}
	}

	return activeWarnings, nil
}

// Cleanup cleans up plugin resources
func (a *WarningAction) Cleanup() error {
	return nil
}

// Health checks plugin health
func (a *WarningAction) Health() error {
	if a.store == nil {
		return fmt.Errorf("state store not initialized")
	}
	return a.store.Health()
}

// GetMetrics returns plugin metrics
func (a *WarningAction) GetMetrics() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return map[string]interface{}{
		"total_warnings":       a.metrics.totalWarnings,
		"api_warnings":         a.metrics.apiWarnings,
		"page_warnings":        a.metrics.pageWarnings,
		"email_warnings":       a.metrics.emailWarnings,
		"active_warnings":      a.metrics.activeWarnings,
		"warning_types":        a.config.WarningTypes,
		"show_duration":        a.config.ShowDuration.String(),
		"cooldown_period":      a.config.CooldownPeriod.String(),
		"max_warnings_per_day": a.config.MaxWarningsPerDay,
		"escalation_rules":     len(a.config.EscalationRules),
	}
}
