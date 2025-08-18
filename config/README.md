# Guard Security System Configuration

This directory contains the complete configuration for the Guard Security System, organized into logical modules for easy management and maintenance.

## Configuration Structure

### Core Configuration Files
- **global.json** - Global system settings and defaults
- **server.json** - Server-specific configuration (ports, timeouts, etc.)

### Security Modules

#### Detectors (`detectors/`)
Security rule definitions for threat detection:
- **authentication-security-rules.json** - Login protection, bot detection, credential stuffing
- **behavioral-detection-rules.json** - DDoS, API abuse, rate limiting
- **sql-injection-rules.json** - SQL injection attack detection
- **xss-protection-rules.json** - Cross-site scripting protection
- **web-security-rules.json** - General web security rules
- **temporal-geolocation-rules.json** - Time and location-based security

#### Actions (`actions/`)
Response actions when threats are detected:
- **block-action-rules.json** - IP blocking and request blocking
- **captcha-action-rules.json** - CAPTCHA challenge configuration
- **multiple-signup-action-rules.json** - Multiple signup prevention

#### Handlers (`handlers/`)
Event handling and logging:
- **security-logger-rules.json** - Security event logging configuration

#### Specialized Protection (`security/`, `tcp-protection/`)
- **security/security-config.json** - Advanced security settings
- **tcp-protection/tcp-config.json** - TCP-level protection rules

## Configuration Features

### Modular Design
- Each security domain has its own configuration file
- Easy to enable/disable specific security features
- Hot-reload support for configuration changes

### Rule-Based System
- JSON-defined security rules
- Configurable thresholds and parameters
- Flexible condition matching

### Comprehensive Coverage
- **33 total security rules** across all modules
- Authentication and authorization protection
- Injection attack prevention
- Behavioral anomaly detection
- Network-level protection

## Usage

### Starting with Default Configuration
```bash
go run demo/server.go
```

### Configuration Hot-Reload
The system automatically detects configuration file changes and reloads rules without restart.

### Customizing Rules
1. Edit the appropriate JSON file in the relevant directory
2. Modify thresholds, conditions, or actions as needed
3. Save the file - changes are applied automatically

## Security Rules Summary

### Authentication Security (6 rules)
- Bot login detection
- Login rate limiting
- Multiple account detection
- Credential stuffing protection
- Business hours access control
- Geolocation anomaly detection

### Behavioral Detection (6 rules)
- DDoS attack detection
- API abuse monitoring
- High-frequency request detection
- Concurrent session limits
- Geographic inconsistency detection
- Suspicious activity patterns

### Injection Protection (18 rules)
- SQL injection detection (5 rules)
- XSS protection (6 rules)
- Web security (7 rules)

### Temporal & Geolocation (3 rules)
- Time-based access control
- Geographic restrictions
- Location anomaly detection

## Best Practices

1. **Start with defaults** - The provided configuration is production-ready
2. **Test changes** - Use the demo interface to verify rule modifications
3. **Monitor metrics** - Check `/metrics` endpoint for rule performance
4. **Gradual tuning** - Adjust thresholds incrementally based on traffic patterns
5. **Backup configs** - Keep copies of working configurations before major changes

## Troubleshooting

- **Rules not triggering**: Check rule conditions and thresholds
- **Too many false positives**: Increase detection thresholds
- **Performance issues**: Review rule complexity and frequency
- **Configuration errors**: Check JSON syntax and required fields

The configuration system is designed to be both powerful and user-friendly, providing comprehensive security coverage while remaining easy to customize and maintain.
