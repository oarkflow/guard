# Guard Security System - Comprehensive Web Application Protection

A robust, plugin-based security system with comprehensive threat detection, event-driven architecture, and distributed state management. Provides complete protection against DDoS attacks, injection attacks, authentication threats, and behavioral anomalies.

## 🏗️ Architecture Overview

The system has been completely re-architected with the following key improvements:

### 1. Plugin System
- **Modular Design**: Detectors, actions, and event handlers are now plugins
- **Dynamic Loading**: Plugins can be loaded and configured at runtime
- **Extensible**: Easy to add new detection algorithms and response actions
- **Hot-swappable**: Plugins can be enabled/disabled without system restart

### 2. Event-Driven Architecture
- **Asynchronous Processing**: Events are processed in background workers
- **Scalable**: Multiple event workers handle high-throughput scenarios
- **Decoupled**: Components communicate through events, not direct calls
- **Reliable**: Event buffering and retry mechanisms ensure delivery

### 3. Distributed State Store
- **Multiple Backends**: Memory, Redis, etcd support
- **Consistent**: Atomic operations for rate limiting and state management
- **Scalable**: Horizontal scaling across multiple instances
- **Fault-tolerant**: Health checks and automatic failover

## 📦 Components

### Core Components

#### Plugin Registry (`plugins/registry.go`)
- Manages all registered plugins
- Handles plugin lifecycle (initialize, health checks, cleanup)
- Provides plugin discovery and configuration

#### Event Bus (`events/bus.go`)
- Publishes and routes security events
- Manages event handlers with priority-based execution
- Provides buffering and worker pool management

#### Rule Engine (`engine/rule_engine.go`)
- Orchestrates detection and response workflow
- Processes requests through all enabled plugins
- Generates events and executes actions based on results

#### State Store (`store/`)
- Abstraction layer for distributed state management
- Implementations for memory, Redis, and etcd
- Atomic operations for counters and TTL-based expiration

### Plugin Types

#### Detector Plugins
- **SQL Injection Detector**: Pattern-based SQL injection detection
- **Rate Limit Detector**: Configurable rate limiting with time windows
- **XSS Detector**: Cross-site scripting pattern detection
- **Path Traversal Detector**: Directory traversal attempt detection

#### Action Plugins
- **Block Action**: IP blocking with escalation rules
- **Rate Limit Action**: Request throttling and delays
- **Challenge Action**: CAPTCHA or proof-of-work challenges
- **Alert Action**: Notification and alerting systems

#### Event Handler Plugins
- **Security Logger**: Structured logging of security events
- **Metrics Collector**: Performance and security metrics
- **Alert Manager**: Real-time alerting and notifications
- **Audit Trail**: Compliance and forensic logging

## 🚀 Quick Start

### Running the Demo

```bash
# Start the comprehensive security demo
./start-demo.sh

# Or run directly
go run demo/server.go
```

**Demo Features:**
- **Interactive Web Interface** at http://localhost:8080
- **33 Security Rules** across all threat categories
- **Real-time Testing** of all security features
- **Live Metrics Dashboard** with threat statistics
- **Hot-reload Configuration** for rule adjustments

**Available Tests:**
- Authentication Security (bot detection, rate limiting, credential stuffing)
- Injection Attack Detection (SQL injection, XSS, command injection)
- Behavioral Security (DDoS, API abuse, data exfiltration)
- Geolocation & Time-based Security
- Real-time Security Metrics

### Demo Guides
- **Demo Usage**: See [`demo/README.md`](demo/README.md)
- **Configuration**: See [`config/README.md`](config/README.md)

### Configuration

The system supports both **modular** and **single-file** configuration formats:

#### Modular Configuration (Recommended)

Organize your configuration into separate files for better maintainability:

```
config/
├── server.json                    # Server configuration
├── global.json                    # Global system settings
├── detectors/                     # Detection rules
│   ├── sql-injection-rules.json
│   ├── rate-limit-rules.json
│   └── xss-rules.json
├── actions/                       # Action rules
│   ├── block-action-rules.json
│   └── captcha-action-rules.json
├── handlers/                      # Event handlers
│   └── security-logger-rules.json
├── tcp-protection/               # TCP protection
│   └── tcp-config.json
└── security/                     # Security policies
    └── security-config.json
```

**Benefits:**
- 🔧 **Maintainable**: Each file focuses on one aspect
- 🚀 **Hot Reload**: Independent file watching and reloading
- 👥 **Team-Friendly**: Multiple developers can work on different rule sets
- 🔍 **Better Diffs**: Version control shows precise changes
- 📦 **Selective Deployment**: Deploy only changed configurations

#### Single-File Configuration (Legacy)

Traditional single-file configuration is still supported for backward compatibility:

```json
{
  "server": {
    "address": "0.0.0.0",
    "port": 8080,
    "max_connections": 10000
  },
  "engine": {
    "max_concurrent_requests": 1000,
    "request_timeout": "30s",
    "enable_events": true
  },
  "plugins": {
    "detectors": {
      "sql_injection_detector": {
        "enabled": true,
        "priority": 100,
        "parameters": {
          "custom_patterns": []
        }
      }
    }
  }
}
```

#### Migration Tool

Convert existing single-file configurations to modular format:

```bash
# Build migration tool
go build -o migrate ./cmd/migrate

# Migrate configuration with validation
./migrate -source system_config.json -target config -validate

# View help
./migrate -help
```

#### Auto-Detection

The application automatically detects your configuration format:

```bash
# Uses modular config if config/ directory exists
./guard -config config

# Uses single-file config (backward compatibility)
./guard -config system_config.json
```

For detailed information, see [Modular Configuration System Documentation](docs/MODULAR_CONFIG_SYSTEM.md).

## 🔧 Plugin Development

### Creating a Detector Plugin

```go
type MyDetector struct {
    name string
    // ... other fields
}

func (d *MyDetector) Name() string {
    return d.name
}

func (d *MyDetector) Detect(ctx context.Context, reqCtx *plugins.RequestContext) plugins.DetectionResult {
    // Detection logic here
    return plugins.DetectionResult{
        Threat:     false,
        Confidence: 0.0,
        Details:    "No threat detected",
        Severity:   0,
    }
}

// Implement other required methods...
```

### Creating an Action Plugin

```go
type MyAction struct {
    name string
    // ... other fields
}

func (a *MyAction) Execute(ctx context.Context, reqCtx *plugins.RequestContext, result plugins.RuleResult) error {
    // Action execution logic here
    return nil
}

// Implement other required methods...
```

## 📊 Monitoring and Metrics

The system provides comprehensive metrics:

### Rule Engine Metrics
- Total requests processed
- Threats detected
- Actions executed
- Average processing time

### Plugin Metrics
- Detection rates and accuracy
- Action execution success rates
- Performance metrics per plugin

### Store Metrics
- Hit/miss ratios
- Operation latencies
- Connection health

### Event Metrics
- Events published/processed
- Handler execution times
- Buffer utilization

## 🔒 Security Features

### Comprehensive Threat Detection (33 Active Rules)

#### Authentication Security (6 rules)
- **Bot Login Detection**: Identifies automated login attempts
- **Login Rate Limiting**: Prevents brute force attacks
- **Multiple Account Detection**: Detects suspicious account usage patterns
- **Credential Stuffing Protection**: Blocks common password attacks
- **Business Hours Access Control**: Time-based access restrictions
- **Geolocation Anomaly Detection**: Unusual location-based access

#### Injection Attack Prevention (18 rules)
- **SQL Injection Detection** (5 rules): Comprehensive SQL injection patterns
- **XSS Protection** (6 rules): Cross-site scripting prevention
- **Web Security Rules** (7 rules): General web attack patterns
- **Command Injection Prevention**: System command execution blocking
- **Path Traversal Protection**: Directory traversal attack prevention

#### Behavioral Security (6 rules)
- **DDoS Attack Detection**: Distributed denial of service protection
- **API Abuse Monitoring**: Excessive API usage detection
- **High-frequency Request Detection**: Rapid request pattern analysis
- **Concurrent Session Limits**: Multiple session abuse prevention
- **Geographic Inconsistency Detection**: Location-based anomalies
- **Suspicious Activity Patterns**: Behavioral analysis

#### Temporal & Geolocation (3 rules)
- **Time-based Access Control**: Business hours enforcement
- **Geographic Restrictions**: Location-based access control
- **Location Anomaly Detection**: Unusual geographic patterns

### Advanced Response Actions
- **Graduated Response**: Escalating actions based on threat level
- **IP Blocking**: Temporary and permanent blocking strategies
- **Rate Limiting**: Sophisticated request throttling
- **CAPTCHA Challenges**: Human verification systems
- **Real-time Alerting**: Immediate threat notifications

### Monitoring & Analytics
- **Live Security Dashboard**: Real-time threat visualization
- **Comprehensive Metrics**: Detailed security statistics
- **Event Tracking**: Complete audit trail
- **Performance Monitoring**: System health and performance metrics

## 🚀 Performance

### Scalability
- **Horizontal Scaling**: Multiple instances with shared state
- **Async Processing**: Non-blocking event processing
- **Connection Pooling**: Efficient resource utilization
- **Load Balancing**: Distributed request processing

### Optimization
- **Memory Efficient**: Optimized data structures
- **CPU Efficient**: Minimal processing overhead
- **Network Efficient**: Compressed state synchronization
- **Storage Efficient**: TTL-based cleanup and compression

## 🛠️ Development

### Project Structure
```
├── config/          # Configuration management
├── engine/          # Rule engine implementation
├── events/          # Event bus and handlers
├── plugins/         # Plugin system
│   ├── actions/     # Action plugins
│   ├── detectors/   # Detector plugins
│   └── handlers/    # Event handler plugins
├── store/           # State store implementations
└── example/         # Demo and examples
```

### Building
```bash
go mod tidy
go build -o github.com/oarkflow/guard
```

### Testing
```bash
go test ./...
```

## 📈 Roadmap

### Phase 1 (Current)
- ✅ Plugin system architecture
- ✅ Event-driven processing
- ✅ Distributed state store
- ✅ Core detector plugins
- ✅ Basic action plugins

### Phase 2 (Next)
- [ ] Machine learning integration
- [ ] Advanced behavioral analysis
- [ ] Distributed coordination
- [ ] Performance optimizations
- [ ] Enhanced monitoring

### Phase 3 (Future)
- [ ] Cloud-native deployment
- [ ] Kubernetes integration
- [ ] Advanced analytics
- [ ] Threat intelligence feeds
- [ ] API gateway integration

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests and documentation
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the example implementations
