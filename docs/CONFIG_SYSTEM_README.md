# DDoS Protection System - Configuration & Hot Reload

## Overview

The DDoS Protection System now features a comprehensive configuration system with hot-reload capabilities, allowing you to modify security rules, detection parameters, and system settings without restarting the application.

## Key Features

### ✅ Fixed Issues
- **Rate Limit Window Expiration**: Stats now properly reset after window expiration
- **Enhanced Block Responses**: Detailed API responses with retry information
- **TTL Handling**: Proper time-to-live management for all stored data

### 🔥 New Features
- **Hot Configuration Reload**: Changes to config files are automatically detected and applied
- **Comprehensive Rule System**: Flexible action rules based on severity, confidence, and threat tags
- **Multiple Environment Configs**: Pre-configured setups for development, staging, and production
- **Enhanced API Responses**: Detailed block information with retry times

## Configuration Files

### Main Configuration
- [`complete_security_config.json`](../testdata/complete_security_config.json) - Full-featured configuration with all options
- [`system_config.json`](../testdata/system_config.json) - Current system configuration

### Environment-Specific Configurations
- [`configs/development.json`](../configs/development.json) - Development environment (lenient rules, debug logging)
- [`configs/production.json`](../configs/production.json) - Production environment (strict security, optimized performance)

## Configuration Structure

```json
{
  "server": {
    "address": "0.0.0.0",
    "port": 8080,
    "read_timeout": 10000000000,
    "write_timeout": 10000000000,
    "idle_timeout": 60000000000,
    "max_connections": 10000,
    "body_limit": 10485760
  },
  "engine": {
    "max_concurrent_requests": 1000,
    "request_timeout": 30000000000,
    "enable_metrics": true,
    "enable_events": true,
    "default_action": "allow",
    "failure_mode": "allow",
    "action_rules": [...]
  },
  "plugins": {
    "detectors": {...},
    "actions": {...},
    "handlers": {...}
  }
}
```

## Action Rules System

Action rules determine what actions to take based on threat characteristics:

```json
{
  "name": "Rate Limit Block",
  "description": "Block IPs that exceed rate limits",
  "min_severity": 5,
  "min_confidence": 0.8,
  "actions": ["block_action"],
  "threat_tags": ["rate_limit", "ddos"],
  "priority": 85,
  "enabled": true
}
```

### Rule Parameters
- `min_severity` / `max_severity`: Threat severity range (1-10)
- `min_confidence` / `max_confidence`: Detection confidence range (0.0-1.0)
- `actions`: List of actions to execute
- `threat_tags`: Required threat tags (OR logic by default)
- `exclude_tags`: Tags that exclude this rule
- `require_all_tags`: If true, ALL threat_tags must match
- `priority`: Rule evaluation priority (higher = first)
- `enabled`: Whether the rule is active

## Detector Configurations

### Rate Limit Detector
```json
"rate_limit_detector": {
  "enabled": true,
  "priority": 90,
  "parameters": {
    "window_size": "1m",
    "max_requests": 100,
    "key_template": "rate_limit:{ip}",
    "burst_allowed": 10,
    "cleanup_period": "5m"
  }
}
```

### SQL Injection Detector
```json
"sql_injection_detector": {
  "enabled": true,
  "priority": 100,
  "parameters": {
    "custom_patterns": [
      "(?i)(union|select|insert|update|delete)\\s+",
      "(?i)'\\s*(or|and)\\s*'"
    ],
    "check_headers": true,
    "check_query_params": true,
    "check_body": true,
    "max_body_size": 1048576
  }
}
```

## Action Configurations

### Block Action
```json
"block_action": {
  "enabled": true,
  "priority": 100,
  "parameters": {
    "default_duration": "5m",
    "max_duration": "24h",
    "block_message": "Access denied due to security policy violation",
    "log_blocks": true,
    "escalation_rules": [
      {
        "violation_count": 1,
        "duration": "5m",
        "permanent": false
      },
      {
        "violation_count": 20,
        "duration": "0",
        "permanent": true
      }
    ]
  }
}
```

## Enhanced API Responses

When a request is blocked, the API now returns detailed information:

```json
{
  "error": "Access denied",
  "message": "Your access is temporarily blocked due to Rate limit exceeded: 105 requests in window (limit: 100). Please try again in 4 minutes.",
  "request_id": "req-123",
  "blocked": true,
  "permanent": false,
  "reason": "Rate limit exceeded: 105 requests in window (limit: 100)",
  "blocked_at": "2025-08-17T12:41:55Z",
  "retry_after": "2025-08-17T12:46:55Z",
  "retry_in_seconds": 300,
  "violation_count": 2
}
```

## Hot Reload System

### How It Works
1. **File Monitoring**: The system watches the configuration file for changes every 2 seconds
2. **Validation**: New configurations are validated before applying
3. **Safe Updates**: Changes are applied atomically with rollback on failure
4. **Plugin Reloading**: Detector and action plugins are reconfigured with new parameters
5. **Rule Engine Updates**: Action rules are updated in the rule engine

### Triggering Reloads
- **Automatic**: Edit and save the configuration file
- **Programmatic**: Use the config manager's `UpdateConfig()` method
- **Manual**: Call `ForceReload()` on the config manager

### Monitoring Reloads
Check the application logs for reload events:
```
2025/08/17 12:42:14 Config file system_config.json has been modified, reloading...
2025/08/17 12:42:14 Action rules count changed: 7 -> 9
2025/08/17 12:42:14 New action rule added: 'Strict Rate Limiting'
2025/08/17 12:42:14 Reloaded detector: rate_limit_detector
2025/08/17 12:42:14 Config reloaded successfully
```

## Usage Examples

### Starting with Different Configurations
```bash
# Development mode
./github.com/oarkflow/guard configs/development.json

# Production mode
./github.com/oarkflow/guard configs/production.json

# Custom configuration
./github.com/oarkflow/guard my-custom-config.json
```

### Runtime Configuration Updates
The system automatically detects and applies configuration changes. Simply edit the config file and save it.

### Testing Configuration Changes
Use the provided test files to verify configuration behavior:
```bash
go test -v config_hot_reload_test.go -run TestConfigHotReload
go test -v rate_limit_fix_test.go -run TestProductionRateLimitConfiguration
```

## Configuration Best Practices

### Development Environment
- Use lenient rate limits (high `max_requests`)
- Enable debug logging
- Use warning actions instead of blocking
- Disable security headers for easier testing

### Production Environment
- Use strict rate limits and security rules
- Enable all security headers
- Use escalating block durations
- Configure proper logging and monitoring
- Set `failure_mode` to "deny" for security

### Security Considerations
- Regularly review and update action rules
- Monitor false positive rates
- Use appropriate confidence thresholds
- Implement proper logging and alerting
- Test configuration changes in staging first

## Troubleshooting

### Configuration Not Reloading
1. Check file permissions
2. Verify JSON syntax
3. Check application logs for errors
4. Ensure the config file path is correct

### High False Positives
1. Lower confidence thresholds
2. Adjust severity requirements
3. Review custom patterns
4. Use warning actions for testing

### Performance Issues
1. Reduce concurrent request limits
2. Optimize cleanup periods
3. Adjust buffer sizes
4. Monitor memory usage

## API Endpoints

- `GET /health` - System health check
- `GET /metrics` - System and plugin metrics
- `GET /admin/plugins` - Plugin information
- `POST /admin/config/reload` - Force configuration reload (if admin API enabled)

The system is now fully configurable and supports hot-reloading for maximum flexibility and minimal downtime during configuration updates.
