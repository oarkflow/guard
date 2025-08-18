# Guard Security System Demo

This directory contains a comprehensive demo of the Guard Security System.

## Files

- **server.go** - Complete demo server with all security features
- **index.html** - Interactive web interface for testing security rules

## Running the Demo

1. Start the demo server:
   ```bash
   go run demo/server.go
   ```

2. Open your browser to: http://localhost:8080

3. Use the interactive interface to test various security features:
   - Authentication Security (bot detection, rate limiting, etc.)
   - Injection Attack Detection (SQL injection, XSS, etc.)
   - Behavioral Security (DDoS, API abuse, etc.)
   - Real-time Security Metrics

## Features Demonstrated

### Authentication Security
- Bot login detection
- Login rate limiting
- Multiple account detection
- Credential stuffing protection
- Business hours access control
- Geolocation anomaly detection

### Injection Attack Protection
- SQL injection detection
- XSS (Cross-Site Scripting) protection
- Command injection prevention
- Path traversal blocking

### Behavioral Security
- DDoS attack detection
- API abuse monitoring
- Data exfiltration prevention
- Privilege escalation detection
- Reconnaissance activity monitoring
- Session hijacking detection

### Real-time Monitoring
- Security metrics dashboard
- Live threat detection statistics
- Rule engine performance metrics
- Automated security testing suite

The demo server includes comprehensive API endpoints and a fully functional web interface for testing all security features.
