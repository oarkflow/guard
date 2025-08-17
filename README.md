# DDoS Protection System v2.0 - Enhanced Architecture

A robust, plugin-based DDoS protection system with event-driven architecture and distributed state management.

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
# Run the architecture demonstration
go run example/demo.go
```

This will demonstrate:
- Plugin registration and initialization
- Request processing through the rule engine
- Event generation and handling
- Rate limiting in action
- System metrics and monitoring

### Configuration

The system uses a comprehensive JSON configuration:

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
  "store": {
    "type": "memory",
    "timeout": "5s"
  },
  "events": {
    "buffer_size": 1000,
    "worker_count": 4
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

### Advanced Detection
- **Multi-layer Detection**: Multiple detectors run in parallel
- **Confidence Scoring**: Weighted threat assessment
- **Pattern Learning**: Adaptive detection algorithms
- **False Positive Reduction**: Smart filtering and validation

### Response Actions
- **Graduated Response**: Escalating actions based on threat level
- **Temporary/Permanent Blocking**: Flexible blocking strategies
- **Rate Limiting**: Sophisticated throttling mechanisms
- **Challenge Systems**: CAPTCHA and proof-of-work challenges

### Event Tracking
- **Comprehensive Logging**: All security events are logged
- **Real-time Alerting**: Immediate notification of threats
- **Audit Trail**: Complete forensic logging
- **Compliance Support**: Structured logging for compliance

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
