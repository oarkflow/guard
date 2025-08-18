# Modular Configuration System

The Guard application now supports a modular configuration system that allows you to organize your configuration into separate files for better maintainability and team collaboration.

## Overview

The new modular configuration system provides:

- **Hierarchical Organization**: Separate files for different components
- **Hot Reload**: Independent watching and reloading of configuration files
- **Validation**: Individual file validation with detailed error reporting
- **Migration**: Automatic migration from single-file to modular configuration
- **Backward Compatibility**: Existing single-file configurations continue to work

## Configuration Structure

```
config/
├── server.json                    # Server configuration
├── global.json                    # Global system settings
├── detectors/                     # Detection rule configurations
│   ├── sql-injection-rules.json
│   ├── xss-rules.json
│   ├── rate-limit-rules.json
│   ├── brute-force-rules.json
│   └── ...
├── actions/                       # Action rule configurations
│   ├── block-action-rules.json
│   ├── captcha-action-rules.json
│   └── ...
├── handlers/                      # Event handler configurations
│   ├── security-logger-rules.json
│   └── ...
├── tcp-protection/               # TCP-level protection rules
│   └── tcp-config.json
└── security/                     # Security policies and headers
    └── security-config.json
```

## Configuration Files

### Server Configuration (`config/server.json`)

Contains server-specific settings:

```json
{
  "address": "0.0.0.0",
  "port": 8080,
  "tls_port": 8443,
  "tls_cert_file": "",
  "tls_key_file": "",
  "read_timeout": "10s",
  "write_timeout": "10s",
  "idle_timeout": "60s",
  "max_connections": 10000,
  "enable_prefork": false,
  "body_limit": 10485760,
  "trusted_proxies": ["127.0.0.1", "::1"]
}
```

### Global Configuration (`config/global.json`)

Contains global system settings:

```json
{
  "engine": {
    "max_concurrent_requests": 1000,
    "request_timeout": "30s",
    "enable_metrics": true,
    "enable_events": true,
    "default_action": "allow",
    "failure_mode": "allow"
  },
  "store": {
    "type": "memory",
    "timeout": "5s",
    "max_retries": 3
  },
  "events": {
    "buffer_size": 1000,
    "worker_count": 4,
    "enable_async": true,
    "retry_attempts": 3
  },
  "logging": {
    "level": "INFO",
    "format": "json",
    "output": "stdout"
  }
}
```

### Detector Rules (`config/detectors/*.json`)

Each detector has its own configuration file:

```json
{
  "detector": {
    "name": "sql_injection_detector",
    "enabled": true,
    "priority": 100,
    "parameters": {
      "custom_patterns": [
        "(?i)(union|select|insert|update|delete|drop|create|alter)\\s+",
        "(?i)'\\s*(or|and)\\s*'"
      ],
      "check_headers": true,
      "check_query_params": true,
      "check_body": true
    }
  },
  "action_rules": [
    {
      "name": "SQL Injection Block",
      "description": "Block SQL injection attempts immediately",
      "min_severity": 1,
      "min_confidence": 0.7,
      "actions": ["block_action"],
      "threat_tags": ["sql_injection"],
      "priority": 95,
      "enabled": true
    }
  ]
}
```

### Action Rules (`config/actions/*.json`)

Each action has its own configuration file:

```json
{
  "action": {
    "name": "block_action",
    "enabled": true,
    "priority": 100,
    "parameters": {
      "default_duration": "5m",
      "max_duration": "24h",
      "block_message": "Access denied due to security policy violation",
      "log_blocks": true
    }
  }
}
```

## Usage

### Auto-Detection

The application automatically detects the configuration format:

1. **Modular Configuration**: If `config/` directory exists with `server.json` or `global.json`
2. **Single File**: Falls back to traditional single-file configuration
3. **Default**: Creates default configuration if none found

```bash
# Uses modular config if config/ directory exists
./guard -config config

# Uses single file configuration (backward compatibility)
./guard -config system_config.json
```

### Migration

Use the migration tool to convert existing single-file configurations:

```bash
# Build migration tool
go build -o migrate ./cmd/migrate

# Migrate configuration
./migrate -source system_config.json -target config -validate

# Help
./migrate -help
```

### Validation

Validate configuration files:

```go
import "github.com/oarkflow/guard/pkg/config"

validator := config.NewValidationManager()
err := validator.ValidateConfigDirectory("config")
if err != nil {
    log.Fatal("Configuration validation failed:", err)
}
```

## Hot Reload

The modular configuration system supports hot reload:

- **Individual Files**: Changes to specific files trigger targeted reloads
- **Directory Watching**: New files are automatically detected
- **Debounced**: Rapid changes are debounced to prevent excessive reloads
- **Validation**: Invalid configurations are rejected with detailed errors

## Benefits

### Maintainability
- **Single Responsibility**: Each file focuses on one aspect
- **Easier Navigation**: Find specific configurations quickly
- **Reduced Conflicts**: Team members can work on different rule sets

### Deployment
- **Selective Updates**: Deploy only changed rule sets
- **Rollback**: Easy to rollback specific rule changes
- **Environment-Specific**: Different environments can have different rule sets

### Development
- **Better Diffs**: Version control shows precise changes
- **Modular Testing**: Test individual rule sets
- **Documentation**: Each file can be documented separately

## Migration Guide

### From Single File

1. **Backup**: Always backup your existing configuration
2. **Migrate**: Use the migration tool to convert your configuration
3. **Validate**: Ensure the migrated configuration is valid
4. **Test**: Test the application with the new configuration
5. **Deploy**: Deploy the new modular configuration

```bash
# Step 1: Backup
cp system_config.json system_config.json.backup

# Step 2: Migrate
./migrate -source system_config.json -target config -validate

# Step 3: Test
./guard -config config

# Step 4: Remove old file (after testing)
rm system_config.json
```

### Custom Rules

Add new detector rules:

```bash
# Create new detector rule file
cat > config/detectors/custom-detector-rules.json << EOF
{
  "detector": {
    "name": "custom_detector",
    "enabled": true,
    "priority": 80,
    "parameters": {
      "custom_setting": "value"
    }
  },
  "action_rules": [
    {
      "name": "Custom Rule",
      "description": "Custom detection rule",
      "min_severity": 3,
      "min_confidence": 0.6,
      "actions": ["warning_action"],
      "priority": 75,
      "enabled": true
    }
  ]
}
EOF
```

The application will automatically detect and load the new rule file.

## Troubleshooting

### Configuration Not Loading

1. **Check Directory Structure**: Ensure `config/` directory exists
2. **Validate JSON**: Use `json.tool` to validate JSON syntax
3. **Check Permissions**: Ensure files are readable
4. **Review Logs**: Check application logs for detailed errors

### Validation Errors

1. **Required Fields**: Ensure all required fields are present
2. **Data Types**: Check that values match expected types
3. **Ranges**: Verify numeric values are within valid ranges
4. **Dependencies**: Ensure referenced actions/detectors exist

### Hot Reload Issues

1. **File Permissions**: Ensure files are writable for hot reload
2. **File Locks**: Check if files are locked by other processes
3. **Syntax Errors**: Invalid JSON will prevent reload
4. **Validation Failures**: Failed validation prevents configuration update

## API Reference

### Configuration Loader Interface

```go
type ConfigLoader interface {
    LoadConfig(source string) (*SystemConfig, error)
    SupportsSource(source string) bool
    GetSourceType() string
}
```

### Validation Interface

```go
type ConfigValidator interface {
    ValidateFile(filePath string, content []byte) error
    GetSupportedFileTypes() []string
}
```

### Migration Interface

```go
type ConfigMigrator struct {
    sourceFile string
    targetDir  string
}

func (m *ConfigMigrator) MigrateToModular() error
```

## Best Practices

1. **File Naming**: Use descriptive names with `-rules.json` suffix
2. **Organization**: Group related rules in the same file
3. **Documentation**: Add descriptions to all rules
4. **Validation**: Always validate after changes
5. **Testing**: Test configuration changes in development first
6. **Backup**: Keep backups of working configurations
7. **Version Control**: Track configuration changes in git
8. **Environment Separation**: Use different configurations for different environments
