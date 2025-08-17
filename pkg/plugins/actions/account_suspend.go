package actions

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/guard/pkg/store"
)

// AccountSuspendAction implements ActionPlugin for permanent account suspensions
type AccountSuspendAction struct {
	name        string
	version     string
	description string
	store       store.StateStore
	config      AccountSuspendConfig
	metrics     struct {
		totalSuspensions     int64
		permanentSuspensions int64
		temporarySuspensions int64
		activeSuspensions    int64
		appealsPending       int64
	}
	mu sync.RWMutex
}

// AccountSuspendConfig holds configuration for account suspension
type AccountSuspendConfig struct {
	RequireUserID         bool                    `json:"require_user_id"`         // Must have user ID to suspend account
	DefaultSuspensionType string                  `json:"default_suspension_type"` // "temporary" or "permanent"
	TemporaryDuration     time.Duration           `json:"temporary_duration"`      // For temporary account suspensions
	AllowAppeals          bool                    `json:"allow_appeals"`
	AppealPeriod          time.Duration           `json:"appeal_period"`
	SuspensionMessage     string                  `json:"suspension_message"`
	NotifyUser            bool                    `json:"notify_user"`
	NotifyAdmin           bool                    `json:"notify_admin"`
	LogSuspensions        bool                    `json:"log_suspensions"`
	EscalationRules       []AccountEscalationRule `json:"escalation_rules"`
}

// AccountEscalationRule defines escalation for account suspensions
type AccountEscalationRule struct {
	ViolationCount  int           `json:"violation_count"`
	SuspensionType  string        `json:"suspension_type"`  // "temporary" or "permanent"
	Duration        time.Duration `json:"duration"`         // Only for temporary
	RequireApproval bool          `json:"require_approval"` // Require admin approval
	AutoReview      bool          `json:"auto_review"`      // Automatically review after period
}

// AccountSuspensionInfo represents an account suspension
type AccountSuspensionInfo struct {
	ID             string                 `json:"id"`
	UserID         string                 `json:"user_id"`
	IP             string                 `json:"ip"`
	SuspensionType string                 `json:"suspension_type"` // "temporary" or "permanent"
	StartTime      time.Time              `json:"start_time"`
	EndTime        *time.Time             `json:"end_time,omitempty"` // nil for permanent
	Duration       *time.Duration         `json:"duration,omitempty"` // nil for permanent
	Reason         string                 `json:"reason"`
	ViolationCount int64                  `json:"violation_count"`
	Severity       int                    `json:"severity"`
	IsActive       bool                   `json:"is_active"`
	AppealAllowed  bool                   `json:"appeal_allowed"`
	AppealDeadline *time.Time             `json:"appeal_deadline,omitempty"`
	AppealStatus   string                 `json:"appeal_status"` // "none", "pending", "approved", "denied"
	SuspendedBy    string                 `json:"suspended_by"`  // "system" or admin ID
	ReviewRequired bool                   `json:"review_required"`
	ReviewDeadline *time.Time             `json:"review_deadline,omitempty"`
	Metadata       map[string]interface{} `json:"metadata"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// NewAccountSuspendAction creates a new account suspend action plugin
func NewAccountSuspendAction(stateStore store.StateStore) *AccountSuspendAction {
	return &AccountSuspendAction{
		name:        "account_suspend_action",
		version:     "1.0.0",
		description: "Implements account-level suspensions with appeal process",
		store:       stateStore,
		config: AccountSuspendConfig{
			RequireUserID:         true,
			DefaultSuspensionType: "temporary",
			TemporaryDuration:     30 * 24 * time.Hour, // 30 days
			AllowAppeals:          true,
			AppealPeriod:          14 * 24 * time.Hour, // 14 days to appeal
			SuspensionMessage:     "Your account has been suspended due to security policy violations",
			NotifyUser:            true,
			NotifyAdmin:           true,
			LogSuspensions:        true,
			EscalationRules: []AccountEscalationRule{
				{ViolationCount: 1, SuspensionType: "temporary", Duration: 7 * 24 * time.Hour, RequireApproval: false, AutoReview: true},
				{ViolationCount: 3, SuspensionType: "temporary", Duration: 30 * 24 * time.Hour, RequireApproval: true, AutoReview: true},
				{ViolationCount: 5, SuspensionType: "permanent", RequireApproval: true, AutoReview: false},
			},
		},
	}
}

// Name returns the plugin name
func (a *AccountSuspendAction) Name() string {
	return a.name
}

// Version returns the plugin version
func (a *AccountSuspendAction) Version() string {
	return a.version
}

// Description returns the plugin description
func (a *AccountSuspendAction) Description() string {
	return a.description
}

// Initialize initializes the plugin with configuration
func (a *AccountSuspendAction) Initialize(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Parse require user ID
	if requireUserID, ok := config["require_user_id"].(bool); ok {
		a.config.RequireUserID = requireUserID
	}

	// Parse default suspension type
	if suspType, ok := config["default_suspension_type"].(string); ok {
		a.config.DefaultSuspensionType = suspType
	}

	// Parse temporary duration
	if tempDurStr, ok := config["temporary_duration"].(string); ok {
		if duration, err := time.ParseDuration(tempDurStr); err == nil {
			a.config.TemporaryDuration = duration
		}
	}

	// Parse allow appeals
	if allowAppeals, ok := config["allow_appeals"].(bool); ok {
		a.config.AllowAppeals = allowAppeals
	}

	// Parse appeal period
	if appealPeriodStr, ok := config["appeal_period"].(string); ok {
		if duration, err := time.ParseDuration(appealPeriodStr); err == nil {
			a.config.AppealPeriod = duration
		}
	}

	// Parse suspension message
	if message, ok := config["suspension_message"].(string); ok {
		a.config.SuspensionMessage = message
	}

	// Parse notification settings
	if notifyUser, ok := config["notify_user"].(bool); ok {
		a.config.NotifyUser = notifyUser
	}

	if notifyAdmin, ok := config["notify_admin"].(bool); ok {
		a.config.NotifyAdmin = notifyAdmin
	}

	// Parse log suspensions
	if logSuspensions, ok := config["log_suspensions"].(bool); ok {
		a.config.LogSuspensions = logSuspensions
	}

	return nil
}

// Execute executes the account suspension action
func (a *AccountSuspendAction) Execute(ctx context.Context, reqCtx *plugins.RequestContext, result plugins.RuleResult) error {
	a.mu.RLock()
	config := a.config
	a.mu.RUnlock()

	// Check if user ID is required and available
	if config.RequireUserID && reqCtx.UserID == "" {
		return fmt.Errorf("user ID required for account suspension but not provided")
	}

	// Use IP if no user ID available
	identifier := reqCtx.UserID
	if identifier == "" {
		identifier = reqCtx.IP
	}

	a.metrics.totalSuspensions++

	// Generate keys
	suspensionKey := fmt.Sprintf("account_susp:%s", identifier)
	violationKey := fmt.Sprintf("account_violations:%s", identifier)

	// Get current violation count
	violationCount, err := a.store.Increment(ctx, violationKey, 1)
	if err != nil {
		violationCount = 1
		a.store.Set(ctx, violationKey, violationCount, 365*24*time.Hour) // Keep for a year
	}

	// Determine suspension type and duration
	suspensionType, duration, requireApproval, autoReview := a.determineSuspension(violationCount, config)

	// Update metrics
	a.updateMetrics(suspensionType)

	// Generate suspension ID
	suspensionID := fmt.Sprintf("acc_susp_%d_%s", time.Now().Unix(), identifier)

	// Create suspension info
	suspensionInfo := AccountSuspensionInfo{
		ID:             suspensionID,
		UserID:         reqCtx.UserID,
		IP:             reqCtx.IP,
		SuspensionType: suspensionType,
		StartTime:      time.Now(),
		Reason:         fmt.Sprintf("Account suspension (%s) - violation #%d: %s", suspensionType, violationCount, result.Details),
		ViolationCount: violationCount,
		Severity:       result.Severity,
		IsActive:       !requireApproval, // If approval required, not active until approved
		AppealAllowed:  config.AllowAppeals,
		AppealStatus:   "none",
		SuspendedBy:    "system",
		ReviewRequired: autoReview,
		Metadata: map[string]interface{}{
			"rule_name":        result.RuleName,
			"confidence":       result.Confidence,
			"user_agent":       reqCtx.UserAgent,
			"path":             reqCtx.Path,
			"method":           reqCtx.Method,
			"require_approval": requireApproval,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Set end time and duration for temporary suspensions
	if suspensionType == "temporary" && duration != nil {
		endTime := time.Now().Add(*duration)
		suspensionInfo.EndTime = &endTime
		suspensionInfo.Duration = duration
	}

	// Set appeal deadline if appeals are allowed
	if config.AllowAppeals {
		appealDeadline := time.Now().Add(config.AppealPeriod)
		suspensionInfo.AppealDeadline = &appealDeadline
	}

	// Set review deadline if auto review is enabled
	if autoReview {
		reviewDeadline := time.Now().Add(30 * 24 * time.Hour) // 30 days for review
		suspensionInfo.ReviewDeadline = &reviewDeadline
	}

	// Determine TTL for store
	var ttl time.Duration
	if suspensionType == "permanent" {
		ttl = 10 * 365 * 24 * time.Hour // 10 years for permanent
	} else if duration != nil {
		ttl = *duration + 30*24*time.Hour // Duration + 30 days for records
	} else {
		ttl = 365 * 24 * time.Hour // 1 year default
	}

	// Set suspension in store
	err = a.store.Set(ctx, suspensionKey, suspensionInfo, ttl)
	if err != nil {
		return fmt.Errorf("failed to set account suspension: %w", err)
	}

	if suspensionInfo.IsActive {
		a.metrics.activeSuspensions++
	}

	return nil
}

// determineSuspension determines the appropriate suspension type and settings
func (a *AccountSuspendAction) determineSuspension(violationCount int64, config AccountSuspendConfig) (string, *time.Duration, bool, bool) {
	// Find the appropriate escalation rule
	for i := len(config.EscalationRules) - 1; i >= 0; i-- {
		rule := config.EscalationRules[i]
		if violationCount >= int64(rule.ViolationCount) {
			var duration *time.Duration
			if rule.SuspensionType == "temporary" {
				if rule.Duration > 0 {
					duration = &rule.Duration
				} else {
					duration = &config.TemporaryDuration
				}
			}
			return rule.SuspensionType, duration, rule.RequireApproval, rule.AutoReview
		}
	}

	// Default suspension
	if config.DefaultSuspensionType == "temporary" {
		return "temporary", &config.TemporaryDuration, false, true
	}
	return "permanent", nil, true, false
}

// updateMetrics updates the metrics based on suspension type
func (a *AccountSuspendAction) updateMetrics(suspensionType string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch suspensionType {
	case "temporary":
		a.metrics.temporarySuspensions++
	case "permanent":
		a.metrics.permanentSuspensions++
	}
}

// IsAccountSuspended checks if an account is currently suspended
func (a *AccountSuspendAction) IsAccountSuspended(ctx context.Context, identifier string) (bool, AccountSuspensionInfo, error) {
	suspensionKey := fmt.Sprintf("account_susp:%s", identifier)

	suspensionData, err := a.store.Get(ctx, suspensionKey)
	if err != nil {
		return false, AccountSuspensionInfo{}, nil // Not suspended if key doesn't exist
	}

	if info, ok := suspensionData.(AccountSuspensionInfo); ok {
		// Check if suspension is still active
		if info.IsActive {
			// For temporary suspensions, check if expired
			if info.SuspensionType == "temporary" && info.EndTime != nil && time.Now().After(*info.EndTime) {
				// Suspension expired, deactivate
				info.IsActive = false
				info.UpdatedAt = time.Now()
				a.store.Set(ctx, suspensionKey, info, 30*24*time.Hour) // Keep for 30 days
				a.metrics.activeSuspensions--
				return false, info, nil
			}
			return true, info, nil
		}
	}

	return false, AccountSuspensionInfo{}, nil
}

// SubmitAppeal submits an appeal for a suspension
func (a *AccountSuspendAction) SubmitAppeal(ctx context.Context, identifier string, appealReason string) error {
	suspended, info, err := a.IsAccountSuspended(ctx, identifier)
	if err != nil {
		return err
	}

	if !suspended {
		return fmt.Errorf("no active suspension found for %s", identifier)
	}

	if !info.AppealAllowed {
		return fmt.Errorf("appeals not allowed for this suspension")
	}

	if info.AppealDeadline != nil && time.Now().After(*info.AppealDeadline) {
		return fmt.Errorf("appeal deadline has passed")
	}

	if info.AppealStatus != "none" {
		return fmt.Errorf("appeal already submitted with status: %s", info.AppealStatus)
	}

	// Update appeal status
	info.AppealStatus = "pending"
	info.Metadata["appeal_reason"] = appealReason
	info.Metadata["appeal_submitted_at"] = time.Now()
	info.UpdatedAt = time.Now()

	suspensionKey := fmt.Sprintf("account_susp:%s", identifier)
	err = a.store.Set(ctx, suspensionKey, info, 365*24*time.Hour)
	if err != nil {
		return fmt.Errorf("failed to update appeal status: %w", err)
	}

	a.metrics.appealsPending++
	return nil
}

// ProcessAppeal processes an appeal (approve or deny)
func (a *AccountSuspendAction) ProcessAppeal(ctx context.Context, identifier string, approved bool, reviewerID string, reviewNotes string) error {
	_, info, err := a.IsAccountSuspended(ctx, identifier)
	if err != nil {
		return err
	}

	if info.AppealStatus != "pending" {
		return fmt.Errorf("no pending appeal found for %s", identifier)
	}

	// Update appeal status
	if approved {
		info.AppealStatus = "approved"
		info.IsActive = false // Lift suspension
		a.metrics.activeSuspensions--
	} else {
		info.AppealStatus = "denied"
	}

	info.Metadata["appeal_processed_at"] = time.Now()
	info.Metadata["appeal_reviewer"] = reviewerID
	info.Metadata["appeal_notes"] = reviewNotes
	info.UpdatedAt = time.Now()

	suspensionKey := fmt.Sprintf("account_susp:%s", identifier)
	err = a.store.Set(ctx, suspensionKey, info, 365*24*time.Hour)
	if err != nil {
		return fmt.Errorf("failed to update appeal: %w", err)
	}

	a.metrics.appealsPending--
	return nil
}

// GetActiveSuspensions returns all currently active account suspensions
func (a *AccountSuspendAction) GetActiveSuspensions(ctx context.Context) (map[string]AccountSuspensionInfo, error) {
	keys, err := a.store.Keys(ctx, "account_susp:*")
	if err != nil {
		return nil, err
	}

	activeSuspensions := make(map[string]AccountSuspensionInfo)
	for _, key := range keys {
		// Extract identifier from key (remove "account_susp:" prefix)
		if len(key) > 13 {
			identifier := key[13:]
			if suspended, info, err := a.IsAccountSuspended(ctx, identifier); err == nil && suspended {
				activeSuspensions[identifier] = info
			}
		}
	}

	return activeSuspensions, nil
}

// Cleanup cleans up plugin resources
func (a *AccountSuspendAction) Cleanup() error {
	return nil
}

// Health checks plugin health
func (a *AccountSuspendAction) Health() error {
	if a.store == nil {
		return fmt.Errorf("state store not initialized")
	}
	return a.store.Health()
}

// GetMetrics returns plugin metrics
func (a *AccountSuspendAction) GetMetrics() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return map[string]interface{}{
		"total_suspensions":     a.metrics.totalSuspensions,
		"permanent_suspensions": a.metrics.permanentSuspensions,
		"temporary_suspensions": a.metrics.temporarySuspensions,
		"active_suspensions":    a.metrics.activeSuspensions,
		"appeals_pending":       a.metrics.appealsPending,
		"require_user_id":       a.config.RequireUserID,
		"allow_appeals":         a.config.AllowAppeals,
		"temporary_duration":    a.config.TemporaryDuration.String(),
		"appeal_period":         a.config.AppealPeriod.String(),
		"escalation_rules":      len(a.config.EscalationRules),
	}
}
