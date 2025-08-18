# 🛡️ Advanced Security Rules System

A comprehensive, multi-layered security system with 47+ advanced security rules across four specialized categories: Authentication & Login Security, Session & Behavioral Analysis, Security & Data Protection, and Traffic & Network Analysis.

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Security Rule Categories](#security-rule-categories)
- [Configuration Files](#configuration-files)
- [Quick Start](#quick-start)
- [Testing](#testing)
- [Rule Details](#rule-details)
- [Demo Interface](#demo-interface)
- [Advanced Features](#advanced-features)
- [Troubleshooting](#troubleshooting)

## 🎯 Overview

This advanced security system provides enterprise-grade protection through intelligent rule-based detection and response mechanisms. The system operates across four specialized servers, each handling different aspects of security:

### Key Features

- **47+ Advanced Security Rules** across multiple categories
- **Multi-layered Protection** with specialized servers
- **Real-time Threat Detection** and response
- **CAPTCHA Integration** with configurable difficulty
- **Behavioral Analysis** and user profiling
- **Geolocation Intelligence** and velocity tracking
- **Traffic Pattern Analysis** and anomaly detection
- **Comprehensive Logging** and metrics collection

### System Statistics

| Metric | Count |
|--------|-------|
| Total Security Rules | 47+ |
| Detector Plugins | 25+ |
| Action Plugins | 20+ |
| Specialized Servers | 4 |
| Configuration Files | 4 |

## 🏗️ Architecture

The system is built on a modular architecture with four specialized security servers:

```
┌─────────────────────────────────────────────────────────────┐
│                    Advanced Security System                 │
├─────────────────────────────────────────────────────────────┤
│  🔐 Auth Server     👤 Session Server                      │
│  Port 8085          Port 8086                              │
│  - Login Security   - Behavioral Analysis                  │
│  - MFA Protection   - Session Management                   │
│  - Access Control   - User Profiling                       │
├─────────────────────────────────────────────────────────────┤
│  🛡️ Security Server  🌐 Traffic Server                     │
│  Port 8087          Port 8088                              │
│  - Data Protection  - Network Analysis                     │
│  - Injection Guard  - IP Intelligence                      │
│  - Permission Ctrl  - Geo Tracking                         │
└─────────────────────────────────────────────────────────────┘
```

## 🔒 Security Rule Categories

### 1. Authentication & Login Security (Port 8085)

**Focus**: Login protection, authentication security, and access control

| Rule Name | Description | Priority |
|-----------|-------------|----------|
| `LoginFailureRule` | Detects brute force attacks and multiple failed login attempts | 95 |
| `AfterHoursRule` | Monitors access attempts outside business hours | 85 |
| `FailedAccessRule` | Tracks failed access attempts to protected resources | 80 |
| `MFABypassRule` | Detects attempts to bypass multi-factor authentication | 90 |
| `SuccessfulLoginAfterFailuresRule` | Monitors successful logins after multiple failures | 85 |
| `PasswordResetSpikeRule` | Detects unusual spikes in password reset requests | 75 |

### 2. Session & Behavioral Analysis (Port 8086)

**Focus**: Session management, behavioral patterns, and user profiling

| Rule Name | Description | Priority |
|-----------|-------------|----------|
| `SessionHighFrequencyRule` | Detects unusually high session activity frequency | 85 |
| `SessionGeoInconsistencyRule` | Identifies sessions from inconsistent geographic locations | 88 |
| `SessionDurationOutlierRule` | Monitors sessions with unusual duration patterns | 75 |
| `ConcurrentSessionsRule` | Tracks multiple concurrent sessions for single user | 80 |
| `DeviceFingerprintChangeRule` | Detects changes in device fingerprinting | 82 |
| `UserBehaviorBaselineDeviationRule` | Identifies deviations from user behavioral baselines | 90 |
| `BehavioralPatternDeviationRule` | Analyzes deviations in behavioral patterns | 88 |
| `IdleSessionResumptionRule` | Monitors resumption of idle sessions | 70 |

### 3. Security & Data Protection (Port 8087)

**Focus**: Data security, injection attacks, and permission management

| Rule Name | Description | Priority |
|-----------|-------------|----------|
| `DataExfiltrationRule` | Detects potential data exfiltration attempts | 95 |
| `InjectionDetectionRule` | Identifies SQL injection and code injection attacks | 98 |
| `PermissionEscalationAttemptRule` | Monitors attempts to escalate user permissions | 92 |
| `SensitiveDataAccessRule` | Tracks access to sensitive data resources | 88 |
| `UnauthorizedConfigChangeRule` | Detects unauthorized configuration changes | 85 |
| `AuditLogIntegrityRule` | Monitors audit log integrity and tampering | 90 |
| `TokenReuseRule` | Detects reuse of authentication tokens | 85 |
| `VulnerableAuthMethodRule` | Identifies use of vulnerable authentication methods | 80 |

### 4. Traffic & Network Analysis (Port 8088)

**Focus**: Network security, traffic analysis, and geolocation intelligence

| Rule Name | Description | Priority |
|-----------|-------------|----------|
| `IPBlackListRule` | Blocks requests from blacklisted IP addresses and ranges | 100 |
| `UnusualGeolocationRule` | Detects access from unusual geographic locations | 85 |
| `GeoVelocityRule` | Identifies impossible travel patterns | 88 |
| `TrafficVolumeSpikeRule` | Monitors unusual spikes in traffic volume | 90 |
| `AnomalousRequestFrequencyRule` | Detects anomalous request frequency patterns | 80 |
| `TorProxyVPNAccessRule` | Handles access through Tor, proxies, and VPNs | 85 |
| `UnusualIPRangeRule` | Detects access from unusual IP ranges or ASNs | 75 |
| `AbnormalReferrerRule` | Identifies abnormal referrer patterns | 70 |
| `SuspiciousPayloadSizeRule` | Monitors suspicious payload sizes | 78 |

## 📁 Configuration Files

The system uses four specialized configuration files:

| File | Server | Port | Purpose |
|------|--------|------|---------|
| [`testdata/advanced_auth_rules_config.json`](testdata/advanced_auth_rules_config.json) | Auth Server | 8085 | Authentication and login security |
| [`testdata/session_behavioral_rules_config.json`](testdata/session_behavioral_rules_config.json) | Session Server | 8086 | Session and behavioral analysis |
| [`testdata/security_data_protection_rules_config.json`](testdata/security_data_protection_rules_config.json) | Security Server | 8087 | Security and data protection |
| [`testdata/traffic_network_analysis_rules_config.json`](testdata/traffic_network_analysis_rules_config.json) | Traffic Server | 8088 | Traffic and network analysis |

## 🚀 Quick Start

### Prerequisites

- Go 1.19+ installed
- Guard binary built (`go build -o guard`)
- All configuration files in place

### 1. Build the Guard Binary

```bash
go build -o guard
```

### 2. Start Individual Servers

```bash
# Authentication & Login Security Server
./guard -config=testdata/advanced_auth_rules_config.json

# Session & Behavioral Analysis Server
./guard -config=testdata/session_behavioral_rules_config.json

# Security & Data Protection Server
./guard -config=testdata/security_data_protection_rules_config.json

# Traffic & Network Analysis Server
./guard -config=testdata/traffic_network_analysis_rules_config.json
```

### 3. Access the Demo Interface

Open [`demo/advanced_security_demo.html`](demo/advanced_security_demo.html) in your browser to access the comprehensive demo interface.

### 4. Run Automated Tests

```bash
cd scripts
./test_advanced_security.sh
```

## 🧪 Testing

### Automated Test Suite

The [`scripts/test_advanced_security.sh`](scripts/test_advanced_security.sh) script provides comprehensive testing:

```bash
# Make script executable (if not already)
chmod +x scripts/test_advanced_security.sh

# Run all tests
cd scripts
./test_advanced_security.sh
```

### Test Categories

1. **Authentication Tests**: Login failures, after-hours access, MFA bypass
2. **Session Tests**: High frequency, geo inconsistency, concurrent sessions
3. **Security Tests**: SQL injection, data exfiltration, permission escalation
4. **Traffic Tests**: IP blacklisting, traffic spikes, geolocation anomalies
5. **CAPTCHA Tests**: Challenge generation and verification

### Manual Testing Examples

#### Test Login Failure Detection
```bash
# Trigger multiple failed logins
for i in {1..5}; do
  curl -X POST http://localhost:8085/login \
       -H "Content-Type: application/json" \
       -d '{"username":"test","password":"wrong"}'
done
```

#### Test SQL Injection Detection
```bash
# Attempt SQL injection
curl "http://localhost:8087/search?q='; DROP TABLE users; --"
```

#### Test Traffic Volume Spike
```bash
# Generate traffic spike
for i in {1..50}; do
  curl http://localhost:8088/api/test &
done
```

## 📖 Rule Details

### Detection Methods

- **Statistical Analysis**: Baseline deviation detection
- **Machine Learning**: Pattern recognition and anomaly detection
- **Behavioral Profiling**: User behavior analysis
- **Geolocation Intelligence**: Location-based threat detection
- **Traffic Analysis**: Volume and frequency pattern analysis
- **Signature Matching**: Known attack pattern detection

### Action Types

- **Block**: Immediate request blocking
- **Rate Limit**: Request frequency limitation
- **CAPTCHA**: Challenge-response verification
- **Warning**: Logging and alerting
- **Session Verification**: Additional authentication required
- **Account Suspension**: Temporary account lockout
- **Geo Blocking**: Location-based access restriction

### Severity Levels

| Level | Description | Typical Actions |
|-------|-------------|-----------------|
| 1-2 | Low | Warning, Logging |
| 3-4 | Medium | Rate Limiting, CAPTCHA |
| 5-6 | High | Blocking, Session Verification |
| 7-8 | Critical | Account Suspension, Geo Blocking |
| 9-10 | Emergency | Immediate Block, Security Alert |

## 🎨 Demo Interface

The [`demo/advanced_security_demo.html`](demo/advanced_security_demo.html) provides:

- **Visual Rule Overview**: All 47+ rules categorized and explained
- **Server Status**: Real-time server monitoring
- **Interactive Controls**: Direct links to each security server
- **Statistics Dashboard**: System metrics and performance data
- **Test Instructions**: Step-by-step testing guide

### Demo Features

- 🎯 **Rule Categories**: Visual organization of security rules
- 📊 **Live Statistics**: Real-time system metrics
- 🔗 **Server Links**: Direct access to each security layer
- 📱 **Responsive Design**: Mobile-friendly interface
- ⚡ **Interactive Elements**: Hover effects and animations

## 🔧 Advanced Features

### Plugin Architecture

The system supports modular plugins for:

- **Custom Detectors**: Implement specialized detection logic
- **Custom Actions**: Define custom response actions
- **Event Handlers**: Process security events
- **Metrics Collectors**: Gather performance data

### Configuration Options

Each rule supports extensive configuration:

```json
{
  "name": "CustomRule",
  "type": "custom_detection",
  "detectors": [{
    "name": "custom_detector",
    "parameters": {
      "threshold": 5.0,
      "window": "10m",
      "sensitivity": "high"
    }
  }],
  "actions": [{
    "name": "custom_action",
    "condition": {
      "min_severity": 5,
      "min_confidence": 0.8
    }
  }]
}
```

### State Management

- **Memory Store**: Fast in-memory state tracking
- **Redis Support**: Distributed state management
- **Cleanup Policies**: Automatic state cleanup
- **Persistence Options**: State persistence across restarts

### Monitoring & Metrics

- **Prometheus Integration**: Metrics export
- **Custom Dashboards**: Grafana-compatible metrics
- **Event Logging**: Comprehensive security event logs
- **Performance Monitoring**: System performance tracking

## 🔍 Troubleshooting

### Common Issues

#### Server Won't Start
```bash
# Check if port is already in use
lsof -i :8085

# Check configuration file syntax
./guard -config=testdata/advanced_auth_rules_config.json -validate
```

#### Rules Not Triggering
```bash
# Check rule priority and conditions
# Verify detector parameters
# Review action thresholds
```

#### High Memory Usage
```bash
# Adjust cleanup intervals in config
# Reduce state retention periods
# Monitor memory usage patterns
```

### Debug Mode

Enable debug logging:

```json
{
  "logging": {
    "level": "DEBUG",
    "format": "json"
  }
}
```

### Performance Tuning

Optimize for high traffic:

```json
{
  "server": {
    "max_connections": 10000,
    "enable_prefork": true
  },
  "engine": {
    "max_concurrent_requests": 1000
  }
}
```

## 📚 Additional Resources

- **Configuration Reference**: Detailed parameter documentation
- **Plugin Development Guide**: Custom plugin creation
- **Security Best Practices**: Implementation recommendations
- **Performance Optimization**: Tuning guidelines
- **Integration Examples**: Third-party integrations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add comprehensive tests
4. Update documentation
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**🛡️ Stay Secure!** This advanced security system provides enterprise-grade protection through intelligent, multi-layered security rules. For questions or support, please refer to the documentation or create an issue.
