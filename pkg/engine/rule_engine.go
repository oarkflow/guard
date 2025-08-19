package engine

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/oarkflow/guard/pkg/config"
	"github.com/oarkflow/log"

	"github.com/oarkflow/guard/pkg/events"
	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/guard/pkg/store"
)

// RuleEngine orchestrates detection, action execution, and event publishing
type RuleEngine struct {
	registry     *plugins.PluginRegistry
	eventBus     *events.EventBus
	eventFactory *events.EventFactory
	store        store.StateStore
	config       Config
	metrics      Metrics
	mu           sync.RWMutex
}

// Config is an alias to config.EngineConfig for backward compatibility
type Config = config.EngineConfig

// ActionRule is an alias to config.ActionRule for backward compatibility
type ActionRule = config.ActionRule

// Metrics holds metrics for the rule engine
type Metrics struct {
	TotalRequests      int64         `json:"total_requests"`
	ThreatsDetected    int64         `json:"threats_detected"`
	ActionsExecuted    int64         `json:"actions_executed"`
	EventsPublished    int64         `json:"events_published"`
	Errors             int64         `json:"errors"`
	AverageProcessTime time.Duration `json:"average_process_time"`
}

// ProcessingResult holds the result of request processing
type ProcessingResult struct {
	Allowed     bool                      `json:"allowed"`
	Detections  []plugins.DetectionResult `json:"detections"`
	Actions     []string                  `json:"actions"`
	Events      []plugins.SecurityEvent   `json:"events"`
	ProcessTime time.Duration             `json:"process_time"`
	Error       error                     `json:"error,omitempty"`
}

// NewRuleEngine creates a new rule engine
func NewRuleEngine(registry *plugins.PluginRegistry, eventBus *events.EventBus, stateStore store.StateStore) *RuleEngine {
	return &RuleEngine{
		registry:     registry,
		eventBus:     eventBus,
		eventFactory: events.NewEventFactory("rule_engine"),
		store:        stateStore,
		config: config.EngineConfig{
			MaxConcurrentRequests: 1000,
			RequestTimeout:        30 * time.Second,
			EnableMetrics:         true,
			EnableEvents:          true,
			DefaultAction:         "allow",
			FailureMode:           "allow",
			ActionRules:           getDefaultActionRules(),
		},
	}
}

// getDefaultActionRules returns minimal fallback action rules
func getDefaultActionRules() []config.ActionRule {
	return []config.ActionRule{
		{
			Name:          "Fallback Critical Block",
			Description:   "Fallback rule for critical threats when no specific rules match",
			MinSeverity:   10,
			MinConfidence: 0.95,
			Actions:       []string{"block_action"},
			Priority:      1, // Very low priority - only used as fallback
			Enabled:       true,
		},
	}
}

// ProcessRequest processes a request through all detection and action plugins
func (re *RuleEngine) ProcessRequest(ctx context.Context, reqCtx *plugins.RequestContext) ProcessingResult {
	startTime := time.Now()

	re.mu.Lock()
	re.metrics.TotalRequests++
	re.mu.Unlock()

	result := ProcessingResult{
		Allowed:     true,
		Detections:  make([]plugins.DetectionResult, 0),
		Actions:     make([]string, 0),
		Events:      make([]plugins.SecurityEvent, 0),
		ProcessTime: 0,
	}

	// Create context with timeout
	processCtx, cancel := context.WithTimeout(ctx, re.config.RequestTimeout)
	defer cancel()

	// Check if IP is already blocked (endpoint-specific or global)
	if blocked, blockInfo := re.isIPBlocked(processCtx, reqCtx.IP, reqCtx.Path); blocked {
		result.Allowed = false
		result.Actions = append(result.Actions, "block_action")

		// Create a detection result for the existing block
		result.Detections = append(result.Detections, plugins.DetectionResult{
			Threat:     true,
			Confidence: 1.0,
			Details:    fmt.Sprintf("IP %s is currently blocked: %v", reqCtx.IP, blockInfo),
			Severity:   9,
			Tags:       []string{"blocked", "existing_block"},
			Metadata:   map[string]any{"block_info": blockInfo},
		})

		result.ProcessTime = time.Since(startTime)
		return result
	}

	// Run detection phase
	detections := re.runDetections(processCtx, reqCtx)
	result.Detections = detections

	// Evaluate detections and determine actions
	actions := re.evaluateDetections(detections, reqCtx)

	// Execute actions
	for _, action := range actions {
		if err := re.executeAction(processCtx, action, reqCtx, detections); err != nil {
			log.Error().Str("action", action).Err(err).Msg("Failed to execute action")
			re.mu.Lock()
			re.metrics.Errors++
			re.mu.Unlock()
		} else {
			result.Actions = append(result.Actions, action)
			re.mu.Lock()
			re.metrics.ActionsExecuted++
			re.mu.Unlock()
		}
	}

	// Determine if request should be allowed
	result.Allowed = re.shouldAllowRequest(detections, actions)

	// Publish events if enabled
	if re.config.EnableEvents {
		eve := re.generateEvents(reqCtx, detections, actions, result.Allowed)
		result.Events = eve

		for _, event := range eve {
			re.eventBus.PublishAsync(event)
			re.mu.Lock()
			re.metrics.EventsPublished++
			re.mu.Unlock()
		}
	}

	// Update metrics
	result.ProcessTime = time.Since(startTime)
	re.updateProcessingMetrics(result.ProcessTime)

	return result
}

// runDetections runs all enabled detector plugins
func (re *RuleEngine) runDetections(ctx context.Context, reqCtx *plugins.RequestContext) []plugins.DetectionResult {
	detectors := re.registry.GetAllDetectors()
	results := make([]plugins.DetectionResult, 0, len(detectors))

	// Run detections concurrently
	resultChan := make(chan plugins.DetectionResult, len(detectors))
	var wg sync.WaitGroup

	for _, detector := range detectors {
		wg.Add(1)
		go func(d plugins.DetectorPlugin) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Error().Str("detector", d.Name()).Interface("panic", r).Msg("Detector panicked")
				}
			}()

			detection := d.Detect(ctx, reqCtx)
			if detection.Threat {
				re.mu.Lock()
				re.metrics.ThreatsDetected++
				re.mu.Unlock()
			}
			resultChan <- detection
		}(detector)
	}

	// Wait for all detections to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for detection := range resultChan {
		results = append(results, detection)
	}

	return results
}

// evaluateDetections determines which actions to take based on configurable rules
func (re *RuleEngine) evaluateDetections(detections []plugins.DetectionResult, _ *plugins.RequestContext) []string {
	actions := make([]string, 0)

	// Filter only threat detections
	threatDetections := make([]plugins.DetectionResult, 0)
	for _, detection := range detections {
		if detection.Threat {
			threatDetections = append(threatDetections, detection)
		}
	}

	// If no threats detected, return empty actions
	if len(threatDetections) == 0 {
		return actions
	}

	// Sort rules by priority (highest first)
	rules := make([]ActionRule, len(re.config.ActionRules))
	copy(rules, re.config.ActionRules)
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})

	// Evaluate each rule against all threat detections
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// Check if rule matches any detection
		if re.ruleMatches(rule, threatDetections) {
			log.Debug().Str("rule", rule.Name).Interface("actions", rule.Actions).Msg("Action rule matched")
			// Add all actions from this rule
			for _, action := range rule.Actions {
				// Avoid duplicate actions
				found := false
				for _, existingAction := range actions {
					if existingAction == action {
						found = true
						break
					}
				}
				if !found {
					actions = append(actions, action)
				}
			}

			// For now, we'll continue evaluating other rules
			// In the future, we could add a "stop_on_match" flag to rules
		}
	}

	return actions
}

// ruleMatches checks if a rule matches any of the threat detections
func (re *RuleEngine) ruleMatches(rule config.ActionRule, detections []plugins.DetectionResult) bool {
	for _, detection := range detections {
		if re.detectionMatchesRule(rule, detection) {
			return true
		}
	}
	return false
}

// detectionMatchesRule checks if a single detection matches a rule
func (re *RuleEngine) detectionMatchesRule(rule config.ActionRule, detection plugins.DetectionResult) bool {
	log.Debug().
		Str("rule", rule.Name).
		Int("rule_severity", rule.MinSeverity).
		Float64("rule_confidence", rule.MinConfidence).
		Interface("rule_tags", rule.ThreatTags).
		Int("detection_severity", detection.Severity).
		Float64("detection_confidence", detection.Confidence).
		Interface("detection_tags", detection.Tags).
		Msg("Checking rule match")

	// Check severity range
	if detection.Severity < rule.MinSeverity {
		log.Debug().Str("rule", rule.Name).Msg("Rule rejected: severity too low")
		return false
	}
	if rule.MaxSeverity > 0 && detection.Severity > rule.MaxSeverity {
		log.Debug().Str("rule", rule.Name).Msg("Rule rejected: severity too high")
		return false
	}

	// Check confidence range
	if detection.Confidence < rule.MinConfidence {
		log.Debug().Str("rule", rule.Name).Msg("Rule rejected: confidence too low")
		return false
	}
	if rule.MaxConfidence > 0 && detection.Confidence > rule.MaxConfidence {
		log.Debug().Str("rule", rule.Name).Msg("Rule rejected: confidence too high")
		return false
	}

	// Check threat tags if specified
	if len(rule.ThreatTags) > 0 {
		if rule.RequireAllTags {
			// All threat tags must be present
			for _, requiredTag := range rule.ThreatTags {
				found := false
				for _, detectionTag := range detection.Tags {
					if detectionTag == requiredTag {
						found = true
						break
					}
				}
				if !found {
					log.Debug().Str("rule", rule.Name).Str("missing_tag", requiredTag).Msg("Rule rejected: required tag missing")
					return false
				}
			}
		} else {
			// At least one threat tag must be present
			found := false
			for _, requiredTag := range rule.ThreatTags {
				for _, detectionTag := range detection.Tags {
					if detectionTag == requiredTag {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				log.Debug().Str("rule", rule.Name).Interface("required_tags", rule.ThreatTags).Msg("Rule rejected: no matching tags")
				return false
			}
		}
	}

	// Check exclude tags if specified
	if len(rule.ExcludeTags) > 0 {
		for _, excludeTag := range rule.ExcludeTags {
			for _, detectionTag := range detection.Tags {
				if detectionTag == excludeTag {
					log.Debug().Str("rule", rule.Name).Str("exclude_tag", excludeTag).Msg("Rule rejected: exclude tag found")
					return false // Exclude this detection
				}
			}
		}
	}

	log.Debug().Str("rule", rule.Name).Msg("Rule matched!")
	return true
}

// executeAction executes a specific action plugin
func (re *RuleEngine) executeAction(ctx context.Context, actionName string, reqCtx *plugins.RequestContext, detections []plugins.DetectionResult) error {
	action, exists := re.registry.GetAction(actionName)
	if !exists {
		return fmt.Errorf("action plugin %s not found", actionName)
	}

	// Create a rule result from the highest severity detection
	var ruleResult plugins.RuleResult
	for _, detection := range detections {
		if detection.Threat && detection.Severity > ruleResult.Severity {
			ruleResult = plugins.RuleResult{
				Triggered:  true,
				Action:     actionName,
				Confidence: detection.Confidence,
				Details:    detection.Details,
				RuleName:   fmt.Sprintf("detection_%s", actionName),
				Severity:   detection.Severity,
				Metadata:   detection.Metadata,
			}
		}
	}

	return action.Execute(ctx, reqCtx, ruleResult)
}

// shouldAllowRequest determines if a request should be allowed based on detections and actions
func (re *RuleEngine) shouldAllowRequest(detections []plugins.DetectionResult, actions []string) bool {
	// Define blocking actions that should deny the request
	blockingActions := map[string]bool{
		"block_action":             true,
		"incremental_block_action": true,
		"captcha_action":           true,
		"multiple_signup_action":   true,
		"suspension_action":        true,
		"account_suspend_action":   true,
	}

	// Check if any blocking actions were executed
	for _, action := range actions {
		if blockingActions[action] {
			return false
		}
	}

	// Check for high-severity threats
	for _, detection := range detections {
		if detection.Threat && detection.Severity >= 9 && detection.Confidence >= 0.9 {
			return false
		}
	}

	return true
}

// generateEvents creates security events based on processing results
func (re *RuleEngine) generateEvents(reqCtx *plugins.RequestContext, detections []plugins.DetectionResult, actions []string, allowed bool) []plugins.SecurityEvent {
	eve := make([]plugins.SecurityEvent, 0)

	// Create threat detection events
	for _, detection := range detections {
		if detection.Threat {
			event := re.eventFactory.CreateThreatDetectedEvent(
				reqCtx.IP,
				reqCtx.UserID,
				"threat_detection",
				detection.Severity,
				map[string]any{
					"detection_details": detection.Details,
					"confidence":        detection.Confidence,
					"tags":              detection.Tags,
					"metadata":          detection.Metadata,
				},
			)
			eve = append(eve, event)
		}
	}

	// Create action execution events
	for _, action := range actions {
		event := re.eventFactory.CreateActionExecutedEvent(
			reqCtx.IP,
			reqCtx.UserID,
			action,
			5, // Medium severity for action events
			map[string]any{
				"allowed": allowed,
				"path":    reqCtx.Path,
				"method":  reqCtx.Method,
			},
		)
		eve = append(eve, event)
	}

	return eve
}

// updateProcessingMetrics updates processing time metrics
func (re *RuleEngine) updateProcessingMetrics(processTime time.Duration) {
	re.mu.Lock()
	defer re.mu.Unlock()

	// Simple moving average for processing time
	if re.metrics.AverageProcessTime == 0 {
		re.metrics.AverageProcessTime = processTime
	} else {
		re.metrics.AverageProcessTime = (re.metrics.AverageProcessTime + processTime) / 2
	}
}

// GetMetrics returns engine metrics
func (re *RuleEngine) GetMetrics() Metrics {
	re.mu.RLock()
	defer re.mu.RUnlock()
	return re.metrics
}

// UpdateConfig updates the engine configuration
func (re *RuleEngine) UpdateConfig(config Config) {
	re.mu.Lock()
	defer re.mu.Unlock()

	oldRuleCount := len(re.config.ActionRules)
	re.config = config
	newRuleCount := len(re.config.ActionRules)

	log.Info().Int("old_rule_count", oldRuleCount).Int("new_rule_count", newRuleCount).Msg("Engine configuration updated")
}

// AddActionRule adds a new action rule at runtime
func (re *RuleEngine) AddActionRule(rule config.ActionRule) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	// Check if rule with same name already exists
	for _, existingRule := range re.config.ActionRules {
		if existingRule.Name == rule.Name {
			return fmt.Errorf("action rule with name '%s' already exists", rule.Name)
		}
	}

	re.config.ActionRules = append(re.config.ActionRules, rule)
	log.Info().Str("rule", rule.Name).Int("priority", rule.Priority).Msg("Added new action rule")
	return nil
}

// UpdateActionRule updates an existing action rule at runtime
func (re *RuleEngine) UpdateActionRule(ruleName string, updatedRule config.ActionRule) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	for i, rule := range re.config.ActionRules {
		if rule.Name == ruleName {
			// Preserve the original name if not specified in update
			if updatedRule.Name == "" {
				updatedRule.Name = ruleName
			}

			re.config.ActionRules[i] = updatedRule
			log.Info().Str("rule", ruleName).Msg("Updated action rule")
			return nil
		}
	}

	return fmt.Errorf("action rule with name '%s' not found", ruleName)
}

// RemoveActionRule removes an action rule at runtime
func (re *RuleEngine) RemoveActionRule(ruleName string) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	for i, rule := range re.config.ActionRules {
		if rule.Name == ruleName {
			// Remove the rule by slicing
			re.config.ActionRules = append(re.config.ActionRules[:i], re.config.ActionRules[i+1:]...)
			log.Info().Str("rule", ruleName).Msgf("Removed action rule")
			return nil
		}
	}

	return fmt.Errorf("action rule with name '%s' not found", ruleName)
}

// EnableActionRule enables or disables an action rule at runtime
func (re *RuleEngine) EnableActionRule(ruleName string, enabled bool) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	for i, rule := range re.config.ActionRules {
		if rule.Name == ruleName {
			re.config.ActionRules[i].Enabled = enabled
			status := "disabled"
			if enabled {
				status = "enabled"
			}
			log.Info().Str("rule", ruleName).Str("status", status).Msg("Action rule status changed")
			return nil
		}
	}

	return fmt.Errorf("action rule with name '%s' not found", ruleName)
}

// GetActionRules returns a copy of current action rules
func (re *RuleEngine) GetActionRules() []config.ActionRule {
	re.mu.RLock()
	defer re.mu.RUnlock()

	// Return a copy to prevent external modifications
	rules := make([]config.ActionRule, len(re.config.ActionRules))
	copy(rules, re.config.ActionRules)
	return rules
}

// GetActionRule returns a specific action rule by name
func (re *RuleEngine) GetActionRule(ruleName string) (*config.ActionRule, error) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	for _, rule := range re.config.ActionRules {
		if rule.Name == ruleName {
			// Return a copy
			ruleCopy := rule
			return &ruleCopy, nil
		}
	}

	return nil, fmt.Errorf("action rule with name '%s' not found", ruleName)
}

// ValidateActionRule validates an action rule
func (re *RuleEngine) ValidateActionRule(rule config.ActionRule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule name cannot be empty")
	}

	if rule.MinSeverity < 1 || rule.MinSeverity > 10 {
		return fmt.Errorf("min_severity must be between 1 and 10")
	}

	if rule.MaxSeverity > 0 && rule.MaxSeverity < rule.MinSeverity {
		return fmt.Errorf("max_severity cannot be less than min_severity")
	}

	if rule.MinConfidence < 0.0 || rule.MinConfidence > 1.0 {
		return fmt.Errorf("min_confidence must be between 0.0 and 1.0")
	}

	if rule.MaxConfidence > 0.0 && rule.MaxConfidence < rule.MinConfidence {
		return fmt.Errorf("max_confidence cannot be less than min_confidence")
	}

	if len(rule.Actions) == 0 {
		return fmt.Errorf("rule must have at least one action")
	}

	// Validate that actions exist in the registry
	for _, actionName := range rule.Actions {
		if _, exists := re.registry.GetAction(actionName); !exists {
			return fmt.Errorf("action '%s' not found in registry", actionName)
		}
	}

	return nil
}

// Health checks the health of the rule engine
func (re *RuleEngine) Health() error {
	// Check plugin registry health
	healthResults := re.registry.HealthCheck(context.Background())
	for name, err := range healthResults {
		if err != nil {
			return fmt.Errorf("plugin %s is unhealthy: %w", name, err)
		}
	}

	// Check store health
	if err := re.store.Health(); err != nil {
		return fmt.Errorf("state store is unhealthy: %w", err)
	}

	return nil
}

// isIPBlocked checks if an IP is currently blocked (endpoint-specific or global)
func (re *RuleEngine) isIPBlocked(ctx context.Context, ip, path string) (bool, map[string]any) {
	// Try to get the block action plugin to use its endpoint-aware blocking logic
	if blockAction, exists := re.registry.GetAction("block_action"); exists {
		// Type assert to get the specific block action interface
		if ba, ok := blockAction.(interface {
			IsBlockedForPath(ctx context.Context, ip, path string) (bool, map[string]any, error)
		}); ok {
			if blocked, blockInfo, err := ba.IsBlockedForPath(ctx, ip, path); err == nil {
				return blocked, blockInfo
			}
		}
	}

	// Fallback to direct store check for backward compatibility
	blockKey := fmt.Sprintf("block:%s", ip)
	blockInfo, err := re.store.Get(ctx, blockKey)
	if err != nil {
		// IP is not blocked if key doesn't exist
		return false, nil
	}

	if info, ok := blockInfo.(map[string]any); ok {
		return true, info
	}

	return true, map[string]any{"reason": "blocked"}
}

// Shutdown gracefully shuts down the rule engine
func (re *RuleEngine) Shutdown() error {
	log.Info().Msg("Shutting down rule engine...")

	// Shutdown plugin registry
	if err := re.registry.Shutdown(); err != nil {
		log.Error().Err(err).Msg("Error shutting down plugin registry")
	}

	// Shutdown event bus
	if err := re.eventBus.Shutdown(); err != nil {
		log.Error().Err(err).Msg("Error shutting down event bus")
	}

	// Close state store
	if err := re.store.Close(); err != nil {
		log.Error().Err(err).Msg("Error closing state store")
	}

	return nil
}
