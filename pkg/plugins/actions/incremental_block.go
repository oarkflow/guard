package actions

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/guard/pkg/store"
)

// IncrementalBlockAction implements ActionPlugin for incremental blocking within a day
type IncrementalBlockAction struct {
	name        string
	version     string
	description string
	store       store.StateStore
	config      IncrementalBlockConfig
	metrics     struct {
		totalBlocks    int64
		level1Blocks   int64
		level2Blocks   int64
		level3Blocks   int64
		maxLevelBlocks int64
	}
	mu sync.RWMutex
}

// IncrementalBlockConfig holds configuration for incremental blocking
type IncrementalBlockConfig struct {
	Level1Duration time.Duration `json:"level1_duration"` // 5 minutes
	Level2Duration time.Duration `json:"level2_duration"` // 30 minutes
	Level3Duration time.Duration `json:"level3_duration"` // 2 hours
	MaxDuration    time.Duration `json:"max_duration"`    // 24 hours
	ResetPeriod    time.Duration `json:"reset_period"`    // 24 hours to reset violation count
	BlockMessage   string        `json:"block_message"`
	LogBlocks      bool          `json:"log_blocks"`
}

// BlockLevel represents the current blocking level
type BlockLevel struct {
	Level     int           `json:"level"`
	Duration  time.Duration `json:"duration"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Reason    string        `json:"reason"`
}

// NewIncrementalBlockAction creates a new incremental block action plugin
func NewIncrementalBlockAction(stateStore store.StateStore) *IncrementalBlockAction {
	return &IncrementalBlockAction{
		name:        "incremental_block_action",
		version:     "1.0.0",
		description: "Implements incremental blocking with escalating durations within a day",
		store:       stateStore,
		config: IncrementalBlockConfig{
			Level1Duration: 5 * time.Minute,
			Level2Duration: 30 * time.Minute,
			Level3Duration: 2 * time.Hour,
			MaxDuration:    24 * time.Hour,
			ResetPeriod:    24 * time.Hour,
			BlockMessage:   "Access temporarily restricted due to security policy violations",
			LogBlocks:      true,
		},
	}
}

// Name returns the plugin name
func (a *IncrementalBlockAction) Name() string {
	return a.name
}

// Version returns the plugin version
func (a *IncrementalBlockAction) Version() string {
	return a.version
}

// Description returns the plugin description
func (a *IncrementalBlockAction) Description() string {
	return a.description
}

// Initialize initializes the plugin with configuration
func (a *IncrementalBlockAction) Initialize(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Parse level durations
	if level1Str, ok := config["level1_duration"].(string); ok {
		if duration, err := time.ParseDuration(level1Str); err == nil {
			a.config.Level1Duration = duration
		}
	}

	if level2Str, ok := config["level2_duration"].(string); ok {
		if duration, err := time.ParseDuration(level2Str); err == nil {
			a.config.Level2Duration = duration
		}
	}

	if level3Str, ok := config["level3_duration"].(string); ok {
		if duration, err := time.ParseDuration(level3Str); err == nil {
			a.config.Level3Duration = duration
		}
	}

	if maxStr, ok := config["max_duration"].(string); ok {
		if duration, err := time.ParseDuration(maxStr); err == nil {
			a.config.MaxDuration = duration
		}
	}

	if resetStr, ok := config["reset_period"].(string); ok {
		if duration, err := time.ParseDuration(resetStr); err == nil {
			a.config.ResetPeriod = duration
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

// Execute executes the incremental block action
func (a *IncrementalBlockAction) Execute(ctx context.Context, reqCtx *plugins.RequestContext, result plugins.RuleResult) error {
	a.mu.RLock()
	config := a.config
	a.mu.RUnlock()

	a.metrics.totalBlocks++

	// Generate keys
	blockKey := fmt.Sprintf("inc_block:%s", reqCtx.IP)
	violationKey := fmt.Sprintf("inc_violations:%s", reqCtx.IP)

	// Get current violation count for the day
	violationCount, err := a.store.Increment(ctx, violationKey, 1)
	if err != nil {
		violationCount = 1
		a.store.Set(ctx, violationKey, violationCount, config.ResetPeriod)
	}

	// Determine block level and duration
	level, duration := a.determineBlockLevel(violationCount, config)

	// Update metrics
	a.updateMetrics(level)

	// Create block info
	blockInfo := BlockLevel{
		Level:     level,
		Duration:  duration,
		StartTime: time.Now(),
		EndTime:   time.Now().Add(duration),
		Reason:    fmt.Sprintf("Incremental block level %d - violation #%d: %s", level, violationCount, result.Details),
	}

	// Set block in store
	err = a.store.Set(ctx, blockKey, blockInfo, duration)
	if err != nil {
		return fmt.Errorf("failed to set incremental block: %w", err)
	}

	return nil
}

// determineBlockLevel determines the appropriate block level and duration
func (a *IncrementalBlockAction) determineBlockLevel(violationCount int64, config IncrementalBlockConfig) (int, time.Duration) {
	switch {
	case violationCount <= 2:
		return 1, config.Level1Duration
	case violationCount <= 5:
		return 2, config.Level2Duration
	case violationCount <= 10:
		return 3, config.Level3Duration
	default:
		return 4, config.MaxDuration
	}
}

// updateMetrics updates the metrics based on block level
func (a *IncrementalBlockAction) updateMetrics(level int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch level {
	case 1:
		a.metrics.level1Blocks++
	case 2:
		a.metrics.level2Blocks++
	case 3:
		a.metrics.level3Blocks++
	default:
		a.metrics.maxLevelBlocks++
	}
}

// IsBlocked checks if an IP is currently blocked
func (a *IncrementalBlockAction) IsBlocked(ctx context.Context, ip string) (bool, BlockLevel, error) {
	blockKey := fmt.Sprintf("inc_block:%s", ip)

	blockInfo, err := a.store.Get(ctx, blockKey)
	if err != nil {
		return false, BlockLevel{}, nil // Not blocked if key doesn't exist
	}

	if info, ok := blockInfo.(BlockLevel); ok {
		// Check if block is still active
		if time.Now().Before(info.EndTime) {
			return true, info, nil
		}
	}

	return false, BlockLevel{}, nil
}

// GetViolationCount returns the current violation count for an IP
func (a *IncrementalBlockAction) GetViolationCount(ctx context.Context, ip string) (int64, error) {
	violationKey := fmt.Sprintf("inc_violations:%s", ip)

	count, err := a.store.Get(ctx, violationKey)
	if err != nil {
		return 0, nil // No violations if key doesn't exist
	}

	if countVal, ok := count.(int64); ok {
		return countVal, nil
	}

	return 0, nil
}

// ResetViolations resets the violation count for an IP
func (a *IncrementalBlockAction) ResetViolations(ctx context.Context, ip string) error {
	violationKey := fmt.Sprintf("inc_violations:%s", ip)
	return a.store.Delete(ctx, violationKey)
}

// UnblockIP removes an incremental block for a specific IP
func (a *IncrementalBlockAction) UnblockIP(ctx context.Context, ip string) error {
	blockKey := fmt.Sprintf("inc_block:%s", ip)
	return a.store.Delete(ctx, blockKey)
}

// GetBlockedIPs returns a list of currently blocked IPs with their levels
func (a *IncrementalBlockAction) GetBlockedIPs(ctx context.Context) (map[string]BlockLevel, error) {
	keys, err := a.store.Keys(ctx, "inc_block:*")
	if err != nil {
		return nil, err
	}

	blockedIPs := make(map[string]BlockLevel)
	for _, key := range keys {
		// Extract IP from key (remove "inc_block:" prefix)
		if len(key) > 10 {
			ip := key[10:]
			if blocked, blockInfo, err := a.IsBlocked(ctx, ip); err == nil && blocked {
				blockedIPs[ip] = blockInfo
			}
		}
	}

	return blockedIPs, nil
}

// Cleanup cleans up plugin resources
func (a *IncrementalBlockAction) Cleanup() error {
	return nil
}

// Health checks plugin health
func (a *IncrementalBlockAction) Health() error {
	if a.store == nil {
		return fmt.Errorf("state store not initialized")
	}
	return a.store.Health()
}

// GetMetrics returns plugin metrics
func (a *IncrementalBlockAction) GetMetrics() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return map[string]interface{}{
		"total_blocks":     a.metrics.totalBlocks,
		"level1_blocks":    a.metrics.level1Blocks,
		"level2_blocks":    a.metrics.level2Blocks,
		"level3_blocks":    a.metrics.level3Blocks,
		"max_level_blocks": a.metrics.maxLevelBlocks,
		"level1_duration":  a.config.Level1Duration.String(),
		"level2_duration":  a.config.Level2Duration.String(),
		"level3_duration":  a.config.Level3Duration.String(),
		"max_duration":     a.config.MaxDuration.String(),
		"reset_period":     a.config.ResetPeriod.String(),
	}
}
