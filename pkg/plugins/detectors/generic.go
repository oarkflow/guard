package detectors

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/oarkflow/guard/pkg/plugins"
)

// GenericDetector implements a configurable detector that can handle multiple detection rules
type GenericDetector struct {
	name        string
	version     string
	description string
	rules       []GenericRule
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
	Field    string          `json:"field"`    // "path", "header", "query_param", "ip", "user_agent", etc.
	Operator string          `json:"operator"` // "contains", "equals", "regex", "greater_than", etc.
	Value    any             `json:"value"`
	Negate   bool            `json:"negate"`
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

	// Parse rules from configuration
	if rules, ok := config["rules"].([]any); ok {
		d.rules = make([]GenericRule, 0, len(rules))
		for _, rule := range rules {
			if ruleMap, ok := rule.(map[string]any); ok {
				genericRule := GenericRule{
					Parameters: make(map[string]any),
					Conditions: make([]RuleCondition, 0),
					Actions:    make([]string, 0),
					Tags:       make([]string, 0),
					Metadata:   make(map[string]any),
				}

				// Parse basic rule fields
				if id, ok := ruleMap["id"].(string); ok {
					genericRule.ID = id
				}
				if name, ok := ruleMap["name"].(string); ok {
					genericRule.Name = name
				}
				if description, ok := ruleMap["description"].(string); ok {
					genericRule.Description = description
				}
				if enabled, ok := ruleMap["enabled"].(bool); ok {
					genericRule.Enabled = enabled
				} else {
					genericRule.Enabled = true // Default to enabled
				}
				if ruleType, ok := ruleMap["type"].(string); ok {
					genericRule.Type = ruleType
				}
				if severity, ok := ruleMap["severity"].(float64); ok {
					genericRule.Severity = int(severity)
				}
				if confidence, ok := ruleMap["confidence"].(float64); ok {
					genericRule.Confidence = confidence
				}
				if priority, ok := ruleMap["priority"].(float64); ok {
					genericRule.Priority = int(priority)
				}

				// Parse parameters
				if params, ok := ruleMap["parameters"].(map[string]any); ok {
					genericRule.Parameters = params
				}

				// Parse conditions
				if conditions, ok := ruleMap["conditions"].([]any); ok {
					for _, condition := range conditions {
						if condMap, ok := condition.(map[string]any); ok {
							ruleCondition := RuleCondition{}
							if field, ok := condMap["field"].(string); ok {
								ruleCondition.Field = field
							}
							if operator, ok := condMap["operator"].(string); ok {
								ruleCondition.Operator = operator
							}
							if value, ok := condMap["value"]; ok {
								ruleCondition.Value = value
							}
							if negate, ok := condMap["negate"].(bool); ok {
								ruleCondition.Negate = negate
							}
							if children, ok := condMap["children"].([]any); ok {
								ruleCondition.Children = make([]RuleCondition, 0, len(children))
								for _, child := range children {
									if childMap, ok := child.(map[string]any); ok {
										childCondition := RuleCondition{}
										if field, ok := childMap["field"].(string); ok {
											childCondition.Field = field
										}
										if operator, ok := childMap["operator"].(string); ok {
											childCondition.Operator = operator
										}
										if value, ok := childMap["value"]; ok {
											childCondition.Value = value
										}
										if negate, ok := childMap["negate"].(bool); ok {
											childCondition.Negate = negate
										}
										ruleCondition.Children = append(ruleCondition.Children, childCondition)
									}
								}
							}
							if logical, ok := condMap["logical"].(string); ok {
								ruleCondition.Logical = logical
							}
							genericRule.Conditions = append(genericRule.Conditions, ruleCondition)
						}
					}
				}

				// Parse actions
				if actions, ok := ruleMap["actions"].([]any); ok {
					for _, action := range actions {
						if actionStr, ok := action.(string); ok {
							genericRule.Actions = append(genericRule.Actions, actionStr)
						}
					}
				}

				// Parse tags
				if tags, ok := ruleMap["tags"].([]any); ok {
					for _, tag := range tags {
						if tagStr, ok := tag.(string); ok {
							genericRule.Tags = append(genericRule.Tags, tagStr)
						}
					}
				}

				// Parse metadata
				if metadata, ok := ruleMap["metadata"].(map[string]any); ok {
					genericRule.Metadata = metadata
				}

				d.rules = append(d.rules, genericRule)
			}
		}
	}

	return nil
}

// Detect performs detection based on configurable rules
func (d *GenericDetector) Detect(ctx context.Context, reqCtx *plugins.RequestContext) plugins.DetectionResult {
	d.mu.RLock()
	rules := make([]GenericRule, len(d.rules))
	copy(rules, d.rules)
	d.mu.RUnlock()

	d.metrics.totalChecks++

	// Process each rule
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// Check if rule conditions are met
		if d.evaluateRule(rule, reqCtx) {
			d.metrics.threatsFound++

			return plugins.DetectionResult{
				Threat:     true,
				Confidence: rule.Confidence,
				Details:    fmt.Sprintf("Rule '%s' matched: %s", rule.Name, rule.Description),
				Severity:   rule.Severity,
				Tags:       rule.Tags,
				Metadata: map[string]any{
					"rule_id":   rule.ID,
					"rule_name": rule.Name,
					"rule_type": rule.Type,
					"metadata":  rule.Metadata,
				},
			}
		}
	}

	return plugins.DetectionResult{
		Threat:     false,
		Confidence: 0,
		Details:    "No rules matched",
		Severity:   0,
		Tags:       []string{},
		Metadata:   map[string]any{},
	}
}

// evaluateRule checks if a rule's conditions are met
func (d *GenericDetector) evaluateRule(rule GenericRule, reqCtx *plugins.RequestContext) bool {
	// For each condition in the rule
	for _, condition := range rule.Conditions {
		if !d.evaluateCondition(condition, reqCtx) {
			return false
		}
	}
	return true
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
		// Evaluate simple condition
		switch condition.Field {
		case "path":
			result = d.evaluateStringCondition(condition, reqCtx.Path)
		case "method":
			result = d.evaluateStringCondition(condition, reqCtx.Method)
		case "ip":
			result = d.evaluateStringCondition(condition, reqCtx.IP)
		case "user_agent":
			result = d.evaluateStringCondition(condition, reqCtx.Headers["User-Agent"])
		case "header":
			// For header, we need to know which header to check
			if headerName, ok := condition.Value.(string); ok {
				if headerValue, exists := reqCtx.Headers[headerName]; exists {
					result = d.evaluateStringCondition(condition, headerValue)
				}
			}
		case "query_param":
			// For query_param, we need to know which parameter to check
			if paramName, ok := condition.Value.(string); ok {
				if paramValue, exists := reqCtx.QueryParams[paramName]; exists {
					result = d.evaluateStringCondition(condition, paramValue)
				}
			}
		case "body":
			// This would require access to the request body
			// For now, we'll skip this
		default:
			// Custom field handling
			result = d.evaluateCustomCondition(condition, reqCtx)
		}
	}

	// Apply negation if needed
	if condition.Negate {
		result = !result
	}

	return result
}

// evaluateStringCondition evaluates a condition against a string value
func (d *GenericDetector) evaluateStringCondition(condition RuleCondition, value string) bool {
	if value == "" {
		return false
	}

	switch condition.Operator {
	case "equals", "eq":
		if strValue, ok := condition.Value.(string); ok {
			return value == strValue
		}
	case "contains":
		if strValue, ok := condition.Value.(string); ok {
			return strings.Contains(value, strValue)
		}
	case "starts_with":
		if strValue, ok := condition.Value.(string); ok {
			return strings.HasPrefix(value, strValue)
		}
	case "ends_with":
		if strValue, ok := condition.Value.(string); ok {
			return strings.HasSuffix(value, strValue)
		}
	case "regex":
		if strValue, ok := condition.Value.(string); ok {
			if regex, err := regexp.Compile(strValue); err == nil {
				return regex.MatchString(value)
			}
		}
	case "length_greater_than":
		if intValue, ok := condition.Value.(float64); ok {
			return len(value) > int(intValue)
		}
	case "length_less_than":
		if intValue, ok := condition.Value.(float64); ok {
			return len(value) < int(intValue)
		}
	}

	return false
}

// evaluateCustomCondition handles custom field evaluations
func (d *GenericDetector) evaluateCustomCondition(condition RuleCondition, reqCtx *plugins.RequestContext) bool {
	// Check if the condition field exists in the request context metadata
	if metadataValue, exists := reqCtx.Metadata[condition.Field]; exists {
		// Convert metadata value to string for comparison
		if strValue, ok := metadataValue.(string); ok {
			return d.evaluateStringCondition(condition, strValue)
		}
	}

	return false
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
