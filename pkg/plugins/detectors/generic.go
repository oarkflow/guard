package detectors

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/filters"
	"github.com/oarkflow/guard/pkg/plugins"
)

// GenericDetector implements a configurable detector that can handle multiple detection rules
type GenericDetector struct {
	name        string
	version     string
	description string
	rules       []GenericRule
	stateStore  plugins.StateStore
	metrics     struct {
		totalChecks    int64
		threatsFound   int64
		falsePositives int64
	}
	mu sync.RWMutex
}

// GenericRule defines a configurable detection rule
type GenericRule struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Enabled     bool            `json:"enabled"`
	Type        string          `json:"type"` // "pattern", "rate_limit", "threshold", etc.
	Severity    int             `json:"severity"`
	Confidence  float64         `json:"confidence"`
	Priority    int             `json:"priority"`
	Parameters  map[string]any  `json:"parameters"`
	Conditions  []RuleCondition `json:"conditions"`
	Actions     []string        `json:"actions"`
	Tags        []string        `json:"tags"`
	Metadata    map[string]any  `json:"metadata"`
}

// RuleCondition defines a condition for a rule
type RuleCondition struct {
	Field    string          `json:"field"`              // "path", "header", "query_param", "ip", "user_agent", etc.
	Key      string          `json:"key,omitempty"`      // Key for header/query_param lookups (e.g., "User-Agent", "id")
	Operator string          `json:"operator"`           // "contains", "equals", "regex", "greater_than", etc.
	Value    any             `json:"value"`              // Value to compare against
	Negate   bool            `json:"negate"`             // Negate the result
	Children []RuleCondition `json:"children,omitempty"` // For nested conditions (AND/OR)
	Logical  string          `json:"logical,omitempty"`  // "and", "or" for combining children
}

// GenericConfig holds configuration for the generic detector
type GenericConfig struct {
	Rules []GenericRule `json:"rules"`
}

// NewGenericDetector creates a new generic detector plugin
func NewGenericDetector() *GenericDetector {
	return &GenericDetector{
		name:        "generic_detector",
		version:     "1.0.0",
		description: "Configurable generic detector for multiple detection rules",
		rules:       make([]GenericRule, 0),
	}
}

// Name returns the plugin name
func (d *GenericDetector) Name() string {
	return d.name
}

// Version returns the plugin version
func (d *GenericDetector) Version() string {
	return d.version
}

// Description returns the plugin description
func (d *GenericDetector) Description() string {
	return d.description
}

// Initialize initializes the plugin with configuration
func (d *GenericDetector) Initialize(config map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Get state store if provided
	if stateStore, ok := config["state_store"].(plugins.StateStore); ok {
		d.stateStore = stateStore
	}

	var rules []GenericRule
	bt, _ := json.Marshal(config["rules"])
	err := json.Unmarshal(bt, &rules)
	if err != nil {
		return err
	}
	d.rules = rules
	return nil
}

// Detect performs detection based on configurable rules
func (d *GenericDetector) Detect(ctx context.Context, reqCtx *plugins.RequestContext) plugins.DetectionResult {
	d.mu.RLock()
	rules := make([]GenericRule, len(d.rules))
	copy(rules, d.rules)
	d.mu.RUnlock()

	d.metrics.totalChecks++

	var matchedRules []GenericRule

	// Process each rule and collect all matches
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// Check if rule conditions are met
		if d.evaluateRule(rule, reqCtx) {
			matchedRules = append(matchedRules, rule)
		}
	}

	// If no rules matched, return no threat
	if len(matchedRules) == 0 {
		return plugins.DetectionResult{
			Threat:     false,
			Confidence: 0,
			Details:    "No rules matched",
			Severity:   0,
			Tags:       []string{},
			Metadata:   map[string]any{},
		}
	}

	// Find the highest priority rule (highest priority number wins)
	highestPriorityRule := matchedRules[0]
	for _, rule := range matchedRules[1:] {
		if rule.Priority > highestPriorityRule.Priority {
			highestPriorityRule = rule
		}
	}

	d.metrics.threatsFound++

	return plugins.DetectionResult{
		Threat:     true,
		Confidence: highestPriorityRule.Confidence,
		Details:    fmt.Sprintf("Rule '%s' matched: %s", highestPriorityRule.Name, highestPriorityRule.Description),
		Severity:   highestPriorityRule.Severity,
		Tags:       highestPriorityRule.Tags,
		Metadata: map[string]any{
			"rule_id":   highestPriorityRule.ID,
			"rule_name": highestPriorityRule.Name,
			"rule_type": highestPriorityRule.Type,
			"metadata":  highestPriorityRule.Metadata,
		},
	}
}

// evaluateRule checks if a rule's conditions are met
func (d *GenericDetector) evaluateRule(rule GenericRule, reqCtx *plugins.RequestContext) bool {
	// Handle rate limiting rules specially
	if rule.Type == "rate_limit" {
		return d.evaluateRateLimitRule(rule, reqCtx)
	}

	// For other rule types, evaluate conditions normally
	for _, condition := range rule.Conditions {
		if !d.evaluateCondition(condition, reqCtx) {
			return false
		}
	}
	return true
}

// evaluateRateLimitRule handles rate limiting logic
func (d *GenericDetector) evaluateRateLimitRule(rule GenericRule, reqCtx *plugins.RequestContext) bool {
	if d.stateStore == nil {
		return false
	}

	// First check if basic conditions are met (if any)
	for _, condition := range rule.Conditions {
		if !d.evaluateCondition(condition, reqCtx) {
			return false
		}
	}

	// Extract rate limiting parameters
	windowSeconds, ok := rule.Parameters["window_seconds"]
	if !ok {
		return false
	}
	maxRequests, ok := rule.Parameters["max_requests"]
	if !ok {
		return false
	}

	// Convert parameters to proper types
	window := time.Duration(0)
	maxReq := int64(0)

	switch v := windowSeconds.(type) {
	case float64:
		window = time.Duration(v) * time.Second
	case int:
		window = time.Duration(v) * time.Second
	case int64:
		window = time.Duration(v) * time.Second
	default:
		return false
	}

	switch v := maxRequests.(type) {
	case float64:
		maxReq = int64(v)
	case int:
		maxReq = int64(v)
	case int64:
		maxReq = v
	default:
		return false
	}

	// Create rate limiting key based on IP and rule ID
	key := fmt.Sprintf("rate_limit:%s:%s", rule.ID, reqCtx.IP)

	// Increment counter with TTL
	ctx := context.Background()
	count, err := d.stateStore.IncrementWithTTL(ctx, key, 1, window)
	if err != nil {
		return false
	}

	// Check if rate limit exceeded
	return count > maxReq
}

// evaluateCondition checks if a single condition is met
func (d *GenericDetector) evaluateCondition(condition RuleCondition, reqCtx *plugins.RequestContext) bool {
	result := false

	// Handle nested conditions first
	if len(condition.Children) > 0 {
		if condition.Logical == "or" {
			result = false
			for _, child := range condition.Children {
				if d.evaluateCondition(child, reqCtx) {
					result = true
					break
				}
			}
		} else { // default to "and"
			result = true
			for _, child := range condition.Children {
				if !d.evaluateCondition(child, reqCtx) {
					result = false
					break
				}
			}
		}
	} else {
		// Build data map for filter evaluation
		data := d.buildDataMap(reqCtx)
		result = d.match(condition, data)
	}

	// Apply negation if needed
	if condition.Negate {
		result = !result
	}

	return result
}

// buildDataMap creates a comprehensive data map from RequestContext for filter evaluation
func (d *GenericDetector) buildDataMap(reqCtx *plugins.RequestContext) map[string]any {
	// Start with country from RequestContext
	country := reqCtx.Country

	// Override with X-Country header if present (for testing)
	if xCountry, exists := reqCtx.Headers["X-Country"]; exists {
		country = xCountry
	}

	data := map[string]any{
		"ip":             reqCtx.IP,
		"user_agent":     reqCtx.UserAgent,
		"method":         reqCtx.Method,
		"path":           reqCtx.Path,
		"content_length": reqCtx.ContentLength,
		"country":        country,
		"asn":            reqCtx.ASN,
		"user_id":        reqCtx.UserID,
		"session_id":     reqCtx.SessionID,
		"timestamp":      reqCtx.Timestamp,
	}

	// Add headers with proper field names
	for key, value := range reqCtx.Headers {
		data["header."+key] = value
	}

	// Add query parameters with proper field names
	for key, value := range reqCtx.QueryParams {
		data["query."+key] = value
	}

	// Handle body based on its type
	if reqCtx.Body != nil {
		switch body := reqCtx.Body.(type) {
		case string:
			data["body"] = body
		case map[string]any:
			// Add body fields with proper field names
			for key, value := range body {
				data["body."+key] = value
			}
			data["body"] = body
		case []map[string]any:
			data["body"] = body
			// For arrays, we can add indexed access if needed
			for i, item := range body {
				for key, value := range item {
					data[fmt.Sprintf("body[%d].%s", i, key)] = value
				}
			}
		default:
			data["body"] = body
		}
	}

	// Add metadata
	for key, value := range reqCtx.Metadata {
		data["metadata."+key] = value
	}

	return data
}

func (d *GenericDetector) match(condition RuleCondition, data map[string]any) bool {
	// Handle specific field access with key
	fieldName := condition.Field
	if condition.Key != "" {
		fieldName = condition.Field + "." + condition.Key
	}

	filter := filters.NewFilter(fieldName, filters.Operator(condition.Operator), condition.Value)
	return filter.Match(data)
}

// Cleanup cleans up plugin resources
func (d *GenericDetector) Cleanup() error {
	return nil
}

// Health checks plugin health
func (d *GenericDetector) Health() error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.rules) == 0 {
		return fmt.Errorf("no rules loaded")
	}

	// Check if any rules are enabled
	enabledCount := 0
	for _, rule := range d.rules {
		if rule.Enabled {
			enabledCount++
		}
	}

	if enabledCount == 0 {
		return fmt.Errorf("no rules enabled")
	}

	return nil
}

// GetMetrics returns plugin metrics
func (d *GenericDetector) GetMetrics() map[string]any {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return map[string]any{
		"total_checks":    d.metrics.totalChecks,
		"threats_found":   d.metrics.threatsFound,
		"false_positives": d.metrics.falsePositives,
		"rules_count":     len(d.rules),
		"detection_rate":  float64(d.metrics.threatsFound) / float64(d.metrics.totalChecks+1),
	}
}

// AddRule adds a new rule at runtime
func (d *GenericDetector) AddRule(rule GenericRule) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Check if rule with same ID already exists
	for _, existingRule := range d.rules {
		if existingRule.ID == rule.ID {
			return fmt.Errorf("rule with ID '%s' already exists", rule.ID)
		}
	}

	d.rules = append(d.rules, rule)
	return nil
}

// UpdateRule updates an existing rule at runtime
func (d *GenericDetector) UpdateRule(ruleID string, updatedRule GenericRule) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for i, rule := range d.rules {
		if rule.ID == ruleID {
			d.rules[i] = updatedRule
			return nil
		}
	}

	return fmt.Errorf("rule with ID '%s' not found", ruleID)
}

// RemoveRule removes a rule at runtime
func (d *GenericDetector) RemoveRule(ruleID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for i, rule := range d.rules {
		if rule.ID == ruleID {
			// Remove the rule by slicing
			d.rules = append(d.rules[:i], d.rules[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("rule with ID '%s' not found", ruleID)
}

// EnableRule enables or disables a rule at runtime
func (d *GenericDetector) EnableRule(ruleID string, enabled bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for i, rule := range d.rules {
		if rule.ID == ruleID {
			d.rules[i].Enabled = enabled
			return nil
		}
	}

	return fmt.Errorf("rule with ID '%s' not found", ruleID)
}

// GetRules returns a copy of current rules
func (d *GenericDetector) GetRules() []GenericRule {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Return a copy to prevent external modifications
	rules := make([]GenericRule, len(d.rules))
	copy(rules, d.rules)
	return rules
}
