# Configurable Action Rules System

## Overview

The DDoS Protection System now features a fully configurable action selection system that allows you to define custom rules for when specific actions should be triggered based on threat severity, confidence levels, and threat tags.

## Key Features

- **Priority-Based Evaluation**: Rules are evaluated in priority order (highest first)
- **Flexible Severity/Confidence Ranges**: Support for both minimum and maximum thresholds
- **Tag-Based Filtering**: Target specific threat types or exclude certain categories
- **Multiple Actions per Rule**: Each rule can trigger multiple actions simultaneously
- **Runtime Configuration**: Rules can be updated without system restart
- **Comprehensive Rule Matching**: Support for complex matching logic

## Configuration Structure

### ActionRule Schema

```json
{
  "name": "Rule Name",
  "description": "Human-readable description",
  "min_severity": 1,
  "max_severity": 10,
  "min_confidence": 0.0,
  "max_confidence": 1.0,
  "actions": ["action1", "action2"],
  "threat_tags": ["tag1", "tag2"],
  "exclude_tags": ["exclude1"],
  "priority": 100,
  "enabled": true,
  "require_all_tags": false
}
```

### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique identifier for the rule |
| `description` | string | No | Human-readable description |
| `min_severity` | int | Yes | Minimum severity level (1-10) |
| `max_severity` | int | No | Maximum severity level (0 = no limit) |
| `min_confidence` | float | Yes | Minimum confidence level (0.0-1.0) |
| `max_confidence` | float | No | Maximum confidence level (0.0 = no limit) |
| `actions` | []string | Yes | List of actions to execute |
| `threat_tags` | []string | No | Required threat tags |
| `exclude_tags` | []string | No | Tags that exclude this rule |
| `priority` | int | Yes | Rule priority (higher = evaluated first) |
| `enabled` | bool | Yes | Whether the rule is active |
| `require_all_tags` | bool | No | If true, all threat_tags must match |

## Available Actions

| Action | Description |
|--------|-------------|
| `block_action` | Temporarily block IP addresses |
| `incremental_block_action` | Progressive blocking with escalating durations |
| `suspension_action` | Temporary account suspension |
| `account_suspend_action` | Account-level suspension with appeal process |
| `warning_action` | Issue warnings to users |

## Default Rules

The system comes with 7 default rules:

1. **Critical Account Suspension** (Priority: 100)
   - Severity: 9+, Confidence: 0.9+
   - Action: Account suspension

2. **SQL Injection Block** (Priority: 95)
   - Severity: 1+, Confidence: 0.7+
   - Tags: `sql_injection`
   - Action: Block

3. **XSS Attack Block** (Priority: 94)
   - Severity: 1+, Confidence: 0.6+
   - Tags: `xss`
   - Action: Block

4. **High Severity Suspension** (Priority: 90)
   - Severity: 8+, Confidence: 0.8+
   - Action: Temporary suspension

5. **Rate Limit Incremental Block** (Priority: 85)
   - Severity: 1+, Confidence: 0.8+
   - Tags: `rate_limit`, `ddos`
   - Action: Incremental blocking

6. **Medium Severity Block** (Priority: 80)
   - Severity: 5+, Confidence: 0.6+
   - Action: Block

7. **Low Severity Warning** (Priority: 70)
   - Severity: 3+, Confidence: 0.3+
   - Action: Warning

## Configuration Examples

### Example 1: Zero-Tolerance SQL Injection

```json
{
  "name": "SQL Injection Zero Tolerance",
  "description": "Block any SQL injection attempt regardless of severity",
  "min_severity": 1,
  "min_confidence": 0.5,
  "actions": ["block_action"],
  "threat_tags": ["sql_injection"],
  "priority": 150,
  "enabled": true
}
```

### Example 2: High-Volume DDoS Protection

```json
{
  "name": "High Volume DDoS Protection",
  "description": "Incremental blocking for high-volume attacks",
  "min_severity": 6,
  "min_confidence": 0.7,
  "actions": ["incremental_block_action"],
  "threat_tags": ["rate_limit", "ddos"],
  "priority": 140,
  "enabled": true
}
```

### Example 3: Suspicious Activity Warning

```json
{
  "name": "Suspicious Activity Warning",
  "description": "Warn for low-confidence but potentially suspicious activity",
  "min_severity": 2,
  "max_severity": 4,
  "min_confidence": 0.3,
  "max_confidence": 0.6,
  "actions": ["warning_action"],
  "priority": 50,
  "enabled": true
}
```

### Example 4: Multi-Action Emergency Response

```json
{
  "name": "Emergency Account Lockdown",
  "description": "Immediately suspend accounts for critical threats",
  "min_severity": 10,
  "min_confidence": 0.95,
  "actions": ["account_suspend_action", "block_action"],
  "priority": 200,
  "enabled": true
}
```

## Rule Evaluation Logic

1. **Filtering**: Only threat detections are considered
2. **Sorting**: Rules are sorted by priority (highest first)
3. **Matching**: Each rule is evaluated against all detections
4. **Execution**: All matching rules execute their actions
5. **Deduplication**: Duplicate actions are automatically removed

### Matching Criteria

A detection matches a rule if ALL of the following are true:

- Severity is >= `min_severity`
- Severity is <= `max_severity` (if specified)
- Confidence is >= `min_confidence`
- Confidence is <= `max_confidence` (if specified)
- At least one `threat_tag` matches (if specified)
- No `exclude_tags` match (if specified)
- Rule is `enabled`

## Runtime Configuration

### Loading Custom Rules

```go
// Load configuration from file
cfg, err := config.LoadConfig("custom_rules.json")
if err != nil {
    log.Fatal(err)
}

// Update rule engine
ruleEngine.UpdateConfig(cfg.Engine)
```

### Programmatic Rule Creation

```go
customRule := config.ActionRule{
    Name:          "Custom Rule",
    Description:   "My custom security rule",
    MinSeverity:   5,
    MinConfidence: 0.8,
    Actions:       []string{"block_action"},
    Priority:      120,
    Enabled:       true,
}

// Add to configuration
cfg.Engine.ActionRules = append(cfg.Engine.ActionRules, customRule)
ruleEngine.UpdateConfig(cfg.Engine)
```

## Best Practices

### Rule Design

1. **Use Descriptive Names**: Make rules easy to identify and understand
2. **Set Appropriate Priorities**: Higher priority for more specific/critical rules
3. **Avoid Overlapping Rules**: Prevent conflicting actions
4. **Test Thoroughly**: Validate rules with various threat scenarios

### Performance Considerations

1. **Limit Rule Count**: Too many rules can impact performance
2. **Optimize Tag Usage**: Use specific tags to reduce unnecessary evaluations
3. **Monitor Metrics**: Track rule execution frequency and effectiveness

### Security Guidelines

1. **Principle of Least Privilege**: Start with warnings, escalate to blocks
2. **False Positive Mitigation**: Use confidence thresholds appropriately
3. **Regular Review**: Periodically audit and update rules
4. **Logging**: Enable comprehensive logging for rule evaluation

## Monitoring and Debugging

### Rule Execution Metrics

The system provides detailed metrics for rule evaluation:

```go
metrics := ruleEngine.GetMetrics()
fmt.Printf("Actions Executed: %d\n", metrics.ActionsExecuted)
```

### Debug Logging

Enable debug logging to see rule evaluation details:

```json
{
  "logging": {
    "level": "DEBUG"
  }
}
```

## Migration from Hardcoded Rules

If you're upgrading from a system with hardcoded rules:

1. **Identify Current Logic**: Document existing severity/confidence thresholds
2. **Create Equivalent Rules**: Convert hardcoded logic to ActionRule structures
3. **Test Compatibility**: Ensure new rules produce similar results
4. **Gradual Migration**: Deploy with conservative rules, then optimize

## Troubleshooting

### Common Issues

1. **Rules Not Triggering**
   - Check rule priority and enabled status
   - Verify severity/confidence thresholds
   - Confirm threat tags match detection tags

2. **Unexpected Actions**
   - Review rule evaluation order (priority)
   - Check for overlapping rule conditions
   - Verify action plugin registration

3. **Performance Issues**
   - Reduce number of active rules
   - Optimize tag-based filtering
   - Monitor rule evaluation metrics

### Debug Commands

```bash
# Test configuration loading
go run demo.go

# Validate JSON configuration
cat custom_rules.json | jq .

# Check rule engine metrics
curl http://localhost:8080/metrics
```

## Future Enhancements

Planned improvements to the rule system:

- **Stop-on-Match**: Option to stop evaluating rules after first match
- **Time-Based Rules**: Rules that activate during specific time periods
- **Rate-Limited Actions**: Prevent action spam with built-in rate limiting
- **Rule Templates**: Pre-defined rule templates for common scenarios
- **A/B Testing**: Support for testing different rule configurations
- **Machine Learning Integration**: Dynamic rule adjustment based on effectiveness
