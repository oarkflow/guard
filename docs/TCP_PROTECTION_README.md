# TCP-Level DDoS Protection System

## Overview

The TCP-level DDoS protection system provides comprehensive network-layer security that operates before HTTP processing. It implements multiple protection mechanisms including silent drops, tarpit mode, IP tracking, and rule-based actions.

## Features

### Core Protection Mechanisms

1. **Silent Drop**: Silently drops connections from suspicious IPs without any response
2. **Tarpit Mode**: Slows down suspicious connections to waste attacker resources
3. **IP Tracking**: Tracks connection rates and brute force attempts at TCP level
4. **Rule-Based Actions**: Configurable actions based on connection patterns
5. **Whitelist/Blacklist**: IP-based allow/deny lists with dynamic management

### Protection Actions

- **Allow**: Normal connection processing
- **Drop**: Silent connection termination
- **Tarpit**: Delayed connection processing
- **Block**: Connection rejection with error response

## Architecture

### Components

1. **TCPProtection**: Core protection engine
2. **TCPMiddleware**: HTTP middleware integration
3. **TCPListener**: Raw TCP connection wrapper
4. **TCPServer**: Complete TCP server with protection
5. **TCPProtectionHandler**: HTTP API endpoints for management

### Configuration

```json
{
  "tcp_protection": {
    "enable_tcp_protection": true,
    "connection_rate_limit": 100,
    "connection_window": "60s",
    "silent_drop_threshold": 50,
    "tarpit_threshold": 75,
    "tarpit_delay": "5s",
    "max_tarpit_connections": 10,
    "brute_force_threshold": 10,
    "brute_force_window": "300s",
    "cleanup_interval": "60s",
    "whitelisted_ips": ["127.0.0.1", "::1"],
    "blacklisted_ips": []
  }
}
```

### Configuration Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `enable_tcp_protection` | Enable/disable TCP protection | `true` |
| `connection_rate_limit` | Max connections per IP per window | `100` |
| `connection_window` | Time window for rate limiting | `60s` |
| `silent_drop_threshold` | Connections before silent drop | `50` |
| `tarpit_threshold` | Connections before tarpit mode | `75` |
| `tarpit_delay` | Delay for tarpit connections | `5s` |
| `max_tarpit_connections` | Max concurrent tarpit connections | `10` |
| `brute_force_threshold` | Failed attempts before blocking | `10` |
| `brute_force_window` | Time window for brute force detection | `300s` |
| `cleanup_interval` | Cleanup interval for expired entries | `60s` |
| `whitelisted_ips` | IPs to never block | `["127.0.0.1", "::1"]` |
| `blacklisted_ips` | IPs to always block | `[]` |

## Usage

### Basic Integration

```go
import "github.com/oarkflow/guard/tcp"

// Create TCP protection config
config := tcp.TCPProtectionConfig{
    EnableTCPProtection:   true,
    ConnectionRateLimit:   100,
    ConnectionWindow:      60 * time.Second,
    SilentDropThreshold:   50,
    TarpitThreshold:       75,
    TarpitDelay:           5 * time.Second,
    MaxTarpitConnections:  10,
    BruteForceThreshold:   10,
    BruteForceWindow:      300 * time.Second,
    CleanupInterval:       60 * time.Second,
    WhitelistedIPs:        []string{"127.0.0.1", "::1"},
    BlacklistedIPs:        []string{},
}

// Create TCP protection
protection := tcp.NewTCPProtection(config, stateStore)
defer protection.Shutdown()
```

### HTTP Middleware Integration

```go
// Create TCP middleware
tcpMiddleware := tcp.NewTCPMiddleware(config, stateStore, nil)

// Use with Fiber
app.Use(func(c *fiber.Ctx) error {
    // TCP protection logic here
    return c.Next()
})
```

### Raw TCP Server

```go
// Create TCP server with protection
server, err := tcp.NewTCPServer("127.0.0.1:8080", config, stateStore, handler)
if err != nil {
    log.Fatal(err)
}
defer server.Shutdown()

// Start serving
go server.Serve()
```

## Protection Flow

### Connection Evaluation Process

1. **IP Check**: Verify against whitelist/blacklist
2. **Rate Limiting**: Check connection count within window
3. **Brute Force Detection**: Check failed attempt count
4. **Action Determination**: Apply appropriate protection action
5. **Metrics Update**: Record connection statistics

### Decision Matrix

| Condition | Action |
|-----------|--------|
| IP in whitelist | Allow |
| IP in blacklist | Block |
| Failed attempts ≥ brute_force_threshold | Block |
| Connections ≥ connection_rate_limit | Block |
| Connections ≥ tarpit_threshold | Tarpit (if capacity) or Drop |
| Connections ≥ silent_drop_threshold | Drop |
| Otherwise | Allow |

## API Endpoints

### Metrics

```
GET /admin/tcp/metrics
```

Returns TCP protection metrics:

```json
{
  "total_connections": 1000,
  "allowed_connections": 800,
  "dropped_connections": 100,
  "tarpit_connections": 50,
  "blocked_connections": 50,
  "active_tarpits": 5,
  "brute_force_detections": 10
}
```

### Active Connections

```
GET /admin/tcp/connections
```

Returns active connection information:

```json
{
  "active_connections": [
    {
      "address": "192.168.1.100:12345",
      "ip": "192.168.1.100",
      "port": 12345,
      "connected_at": "2023-01-01T12:00:00Z",
      "last_activity": "2023-01-01T12:01:00Z",
      "connection_count": 5,
      "failed_attempts": 0,
      "action": "allow",
      "is_whitelisted": false,
      "is_blacklisted": false
    }
  ]
}
```

### Whitelist Management

```
POST /admin/tcp/whitelist?ip=192.168.1.100
DELETE /admin/tcp/whitelist?ip=192.168.1.100
```

### Blacklist Management

```
POST /admin/tcp/blacklist?ip=192.168.1.100
DELETE /admin/tcp/blacklist?ip=192.168.1.100
```

## Performance

### Benchmarks

- **Connection Check**: ~1,876 ns/op (620,162 ops/sec)
- **Memory Usage**: Minimal overhead with TTL-based cleanup
- **Concurrency**: Thread-safe with read-write mutexes

### Optimization Features

1. **TTL-based Cleanup**: Automatic expiration of old entries
2. **Efficient Data Structures**: Optimized maps and counters
3. **Minimal Allocations**: Reuse of connection info objects
4. **Concurrent Processing**: Parallel connection handling

## Environment Configurations

### Development

```json
{
  "tcp_protection": {
    "enable_tcp_protection": true,
    "connection_rate_limit": 1000,
    "connection_window": "60s",
    "silent_drop_threshold": 500,
    "tarpit_threshold": 750,
    "tarpit_delay": "1s",
    "max_tarpit_connections": 50,
    "brute_force_threshold": 50,
    "brute_force_window": "300s"
  }
}
```

### Production

```json
{
  "tcp_protection": {
    "enable_tcp_protection": true,
    "connection_rate_limit": 50,
    "connection_window": "60s",
    "silent_drop_threshold": 25,
    "tarpit_threshold": 35,
    "tarpit_delay": "10s",
    "max_tarpit_connections": 5,
    "brute_force_threshold": 5,
    "brute_force_window": "300s"
  }
}
```

### Testing

```json
{
  "tcp_protection": {
    "enable_tcp_protection": false,
    "connection_rate_limit": 10000,
    "whitelisted_ips": ["0.0.0.0/0", "::/0"]
  }
}
```

## Monitoring and Alerting

### Key Metrics to Monitor

1. **Total Connections**: Overall connection volume
2. **Block Rate**: Percentage of blocked connections
3. **Tarpit Usage**: Active tarpit connection count
4. **Brute Force Detections**: Failed attempt patterns
5. **Response Times**: Impact on legitimate traffic

### Alert Thresholds

- **High Block Rate**: >10% of connections blocked
- **Tarpit Saturation**: Max tarpit connections reached
- **Brute Force Spike**: >100 detections per minute
- **Memory Usage**: >1GB for connection tracking

## Security Considerations

### Best Practices

1. **Regular Whitelist Review**: Audit whitelisted IPs periodically
2. **Threshold Tuning**: Adjust thresholds based on traffic patterns
3. **Log Analysis**: Monitor blocked connections for attack patterns
4. **Backup Protection**: Combine with application-layer protection

### Attack Mitigation

1. **DDoS Attacks**: Rate limiting and silent drops
2. **Brute Force**: Failed attempt tracking and blocking
3. **Slow Loris**: Tarpit mode to exhaust attacker resources
4. **Connection Flooding**: Connection count limits per IP

## Troubleshooting

### Common Issues

1. **Legitimate Traffic Blocked**: Adjust thresholds or add to whitelist
2. **High Memory Usage**: Reduce cleanup interval or connection limits
3. **Performance Impact**: Optimize thresholds and enable metrics monitoring
4. **False Positives**: Review brute force detection settings

### Debug Commands

```bash
# Test TCP protection
go test -v tcp_protection_test.go -run TestTCPProtection

# Benchmark performance
go test -v tcp_protection_test.go -bench=BenchmarkTCPProtection

# Check metrics
curl http://localhost:8080/admin/tcp/metrics

# View active connections
curl http://localhost:8080/admin/tcp/connections
```

## Integration Examples

### With Existing HTTP Server

```go
// Add TCP protection to existing Fiber app
tcpMiddleware := tcp.NewTCPMiddleware(config, stateStore, nil)
app.Use(createTCPProtectionMiddleware(tcpMiddleware))

func createTCPProtectionMiddleware(tm *tcp.TCPMiddleware) fiber.Handler {
    return func(c *fiber.Ctx) error {
        // TCP protection logic
        action, connInfo, err := tm.GetProtection().CheckConnection(c.Context(), remoteAddr)

        switch action {
        case tcp.ActionAllow:
            return c.Next()
        case tcp.ActionDrop:
            return c.SendStatus(fiber.StatusNoContent)
        case tcp.ActionTarpit:
            time.Sleep(config.TarpitDelay)
            return c.Next()
        case tcp.ActionBlock:
            return c.Status(fiber.StatusTooManyRequests).JSON(blockResponse)
        }

        return c.Next()
    }
}
```

### With Load Balancer

```go
// Configure TCP protection behind load balancer
config.WhitelistedIPs = []string{
    "10.0.0.0/8",      // Internal network
    "172.16.0.0/12",   // Private network
    "192.168.0.0/16",  // Local network
}

// Trust proxy headers for real IP detection
app.Use(func(c *fiber.Ctx) error {
    realIP := c.Get("X-Forwarded-For")
    if realIP == "" {
        realIP = c.Get("X-Real-IP")
    }
    if realIP == "" {
        realIP = c.IP()
    }
    // Use realIP for TCP protection
    return c.Next()
})
```

## Conclusion

The TCP-level DDoS protection system provides comprehensive network-layer security with minimal performance impact. It effectively mitigates various attack vectors while maintaining flexibility through configuration and dynamic management capabilities.

For production deployments, carefully tune the thresholds based on your traffic patterns and monitor the metrics to ensure optimal protection without impacting legitimate users.
