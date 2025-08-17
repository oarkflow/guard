package actions

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/guard/pkg/store"
)

// BlockAction implements ActionPlugin for blocking requests
type BlockAction struct {
	name        string
	version     string
	description string
	store       store.StateStore
	config      BlockConfig
	metrics     struct {
		totalBlocks   int64
		temporaryBans int64
		permanentBans int64
	}
	mu sync.RWMutex
}

// BlockConfig holds configuration for blocking action
type BlockConfig struct {
	DefaultDuration time.Duration    `json:"default_duration"`
	MaxDuration     time.Duration    `json:"max_duration"`
	EscalationRules []EscalationRule `json:"escalation_rules"`
	BlockMessage    string           `json:"block_message"`
	LogBlocks       bool             `json:"log_blocks"`
}

// EscalationRule defines how to escalate blocking based on violations
type EscalationRule struct {
	ViolationCount int           `json:"violation_count"`
	Duration       time.Duration `json:"duration"`
	Permanent      bool          `json:"permanent"`
}

// NewBlockAction creates a new block action plugin
func NewBlockAction(stateStore store.StateStore) *BlockAction {
	return &BlockAction{
		name:        "block_action",
		version:     "1.0.0",
		description: "Blocks requests from malicious sources with escalation",
		store:       stateStore,
		config: BlockConfig{
			DefaultDuration: 5 * time.Minute,
			MaxDuration:     24 * time.Hour,
			BlockMessage:    "Access denied due to security policy violation",
			LogBlocks:       true,
			EscalationRules: []EscalationRule{
				{ViolationCount: 1, Duration: 5 * time.Minute, Permanent: false},
				{ViolationCount: 3, Duration: 30 * time.Minute, Permanent: false},
				{ViolationCount: 5, Duration: 2 * time.Hour, Permanent: false},
				{ViolationCount: 10, Duration: 24 * time.Hour, Permanent: false},
				{ViolationCount: 20, Duration: 0, Permanent: true},
			},
		},
	}
}

// Name returns the plugin name
func (a *BlockAction) Name() string {
	return a.name
}

// Version returns the plugin version
func (a *BlockAction) Version() string {
	return a.version
}

// Description returns the plugin description
func (a *BlockAction) Description() string {
	return a.description
}

// Initialize initializes the plugin with configuration
func (a *BlockAction) Initialize(config map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Parse default duration
	if durationStr, ok := config["default_duration"].(string); ok {
		if duration, err := time.ParseDuration(durationStr); err == nil {
			a.config.DefaultDuration = duration
		}
	}

	// Parse max duration
	if maxDurationStr, ok := config["max_duration"].(string); ok {
		if duration, err := time.ParseDuration(maxDurationStr); err == nil {
			a.config.MaxDuration = duration
		}
	}

	// Parse block message
	if message, ok := config["block_message"].(string); ok {
		a.config.BlockMessage = message
	}

	// Parse log blocks
	if logBlocks, ok := config["log_blocks"].(bool); ok {
		a.config.LogBlocks = logBlocks
	}

	return nil
}

// Execute executes the block action
func (a *BlockAction) Execute(ctx context.Context, reqCtx *plugins.RequestContext, result plugins.RuleResult) error {
	a.mu.RLock()
	config := a.config
	a.mu.RUnlock()

	a.metrics.totalBlocks++

	// Generate block key
	blockKey := fmt.Sprintf("block:%s", reqCtx.IP)
	violationKey := fmt.Sprintf("violations:%s", reqCtx.IP)

	// Get current violation count with proper TTL handling
	violationCount, err := a.store.IncrementWithTTL(ctx, violationKey, 1, 24*time.Hour)
	if err != nil {
		violationCount = 1
		a.store.Set(ctx, violationKey, violationCount, 24*time.Hour) // Keep violation history for 24h
	}

	// Determine block duration based on escalation rules
	duration := config.DefaultDuration
	permanent := false

	for _, rule := range config.EscalationRules {
		if violationCount >= int64(rule.ViolationCount) {
			if rule.Permanent {
				permanent = true
				a.metrics.permanentBans++
				break
			} else {
				duration = rule.Duration
				if duration > config.MaxDuration {
					duration = config.MaxDuration
				}
			}
		}
	}

	if !permanent {
		a.metrics.temporaryBans++
	}

	// Create block entry
	blockInfo := map[string]any{
		"blocked_at":      time.Now(),
		"reason":          result.Details,
		"rule_name":       result.RuleName,
		"violation_count": violationCount,
		"permanent":       permanent,
		"severity":        result.Severity,
		"confidence":      result.Confidence,
	}

	// Set block in store
	if permanent {
		// Permanent block (no TTL)
		err = a.store.Set(ctx, blockKey, blockInfo, 0)
	} else {
		// Temporary block with TTL
		err = a.store.Set(ctx, blockKey, blockInfo, duration)
	}

	if err != nil {
		return fmt.Errorf("failed to set block: %w", err)
	}

	return nil
}

// IsBlocked checks if an IP is currently blocked
func (a *BlockAction) IsBlocked(ctx context.Context, ip string) (bool, map[string]any, error) {
	blockKey := fmt.Sprintf("block:%s", ip)

	blockInfo, err := a.store.Get(ctx, blockKey)
	if err != nil {
		return false, nil, nil // Not blocked if key doesn't exist
	}

	if info, ok := blockInfo.(map[string]any); ok {
		return true, info, nil
	}

	return true, map[string]any{"reason": "blocked"}, nil
}

// GetDetailedBlockInfo returns detailed information about a block including retry time
func (a *BlockAction) GetDetailedBlockInfo(ctx context.Context, ip string) (*BlockDetails, error) {
	blocked, blockInfo, err := a.IsBlocked(ctx, ip)
	if err != nil {
		return nil, err
	}

	if !blocked {
		return nil, nil
	}

	details := &BlockDetails{
		IP:        ip,
		IsBlocked: true,
		Reason:    "Security policy violation",
	}

	if blockInfo != nil {
		if reason, ok := blockInfo["reason"].(string); ok {
			details.Reason = reason
		}

		if permanent, ok := blockInfo["permanent"].(bool); ok {
			details.IsPermanent = permanent
		}

		if blockedAtInterface, ok := blockInfo["blocked_at"]; ok {
			if blockedAt, ok := blockedAtInterface.(time.Time); ok {
				details.BlockedAt = blockedAt
			}
		}

		if violationCount, ok := blockInfo["violation_count"].(int64); ok {
			details.ViolationCount = violationCount
		}

		if severity, ok := blockInfo["severity"].(int); ok {
			details.Severity = severity
		}

		if ruleName, ok := blockInfo["rule_name"].(string); ok {
			details.RuleName = ruleName
		}
	}

	// Calculate retry time for temporary blocks
	if !details.IsPermanent && !details.BlockedAt.IsZero() {
		a.mu.RLock()
		config := a.config
		a.mu.RUnlock()

		// Determine block duration based on violation count
		duration := config.DefaultDuration
		for _, rule := range config.EscalationRules {
			if details.ViolationCount >= int64(rule.ViolationCount) {
				if rule.Permanent {
					details.IsPermanent = true
					break
				} else {
					duration = rule.Duration
					if duration > config.MaxDuration {
						duration = config.MaxDuration
					}
				}
			}
		}

		if !details.IsPermanent {
			details.RetryAfter = details.BlockedAt.Add(duration)
			details.RemainingTime = time.Until(details.RetryAfter)
			if details.RemainingTime < 0 {
				details.RemainingTime = 0
			}
		}
	}

	return details, nil
}

// BlockDetails contains detailed information about a block
type BlockDetails struct {
	IP             string        `json:"ip"`
	IsBlocked      bool          `json:"is_blocked"`
	IsPermanent    bool          `json:"is_permanent"`
	Reason         string        `json:"reason"`
	BlockedAt      time.Time     `json:"blocked_at"`
	RetryAfter     time.Time     `json:"retry_after,omitempty"`
	RemainingTime  time.Duration `json:"remaining_time,omitempty"`
	ViolationCount int64         `json:"violation_count"`
	Severity       int           `json:"severity"`
	RuleName       string        `json:"rule_name"`
}

// FormatUserMessage returns a user-friendly message about the block
func (bd *BlockDetails) FormatUserMessage() string {
	if bd.IsPermanent {
		return fmt.Sprintf("Your access has been permanently blocked due to %s. Contact support if you believe this is an error.", bd.Reason)
	}

	if bd.RemainingTime > 0 {
		return fmt.Sprintf("Your access is temporarily blocked due to %s. Please try again in %s.",
			bd.Reason, bd.formatDuration(bd.RemainingTime))
	}

	return fmt.Sprintf("Your access was temporarily blocked due to %s. You may try again now.", bd.Reason)
}

// formatDuration formats a duration in a user-friendly way
func (bd *BlockDetails) formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	} else if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%d hours", int(d.Hours()))
	} else {
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

// UnblockIP removes a block for a specific IP
func (a *BlockAction) UnblockIP(ctx context.Context, ip string) error {
	blockKey := fmt.Sprintf("block:%s", ip)
	return a.store.Delete(ctx, blockKey)
}

// GetBlockedIPs returns a list of currently blocked IPs
func (a *BlockAction) GetBlockedIPs(ctx context.Context) ([]string, error) {
	keys, err := a.store.Keys(ctx, "block:*")
	if err != nil {
		return nil, err
	}

	var blockedIPs []string
	for _, key := range keys {
		// Extract IP from key (remove "block:" prefix)
		if len(key) > 6 {
			ip := key[6:]
			blockedIPs = append(blockedIPs, ip)
		}
	}

	return blockedIPs, nil
}

// Cleanup cleans up plugin resources
func (a *BlockAction) Cleanup() error {
	return nil
}

// Health checks plugin health
func (a *BlockAction) Health() error {
	if a.store == nil {
		return fmt.Errorf("state store not initialized")
	}
	return a.store.Health()
}

// GetMetrics returns plugin metrics
func (a *BlockAction) GetMetrics() map[string]any {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return map[string]any{
		"total_blocks":     a.metrics.totalBlocks,
		"temporary_bans":   a.metrics.temporaryBans,
		"permanent_bans":   a.metrics.permanentBans,
		"default_duration": a.config.DefaultDuration.String(),
		"max_duration":     a.config.MaxDuration.String(),
		"escalation_rules": len(a.config.EscalationRules),
	}
}
