# 🛡️ Advanced Security Features Documentation

## Overview

This document describes the comprehensive advanced security features implemented in the Guard Protection System. The system now includes 33+ security rules covering authentication, behavioral detection, injection attacks, and more.

## 🔐 Authentication Security Features

### 1. Bot Login Detection
- **Rule ID**: `bot_login_detection`
- **Description**: Detects automated bot login attempts based on user agent patterns
- **Detection Method**: Analyzes User-Agent headers for bot signatures
- **Triggers On**:
  - User agents containing: `bot`, `crawler`, `spider`, `scraper`, `automated`, `python`, `curl`, `wget`, `postman`, `insomnia`
  - Empty User-Agent headers
- **Action**: CAPTCHA challenge
- **Severity**: 7/10

### 2. Login Rate Limiting
- **Rule ID**: `login_rate_limit`
- **Description**: Prevents brute force attacks by limiting login attempts
- **Detection Method**: Tracks login attempts per IP address
- **Parameters**:
  - Window: 300 seconds (5 minutes)
  - Max attempts: 5
  - Block duration: 900 seconds (15 minutes)
- **Action**: Incremental blocking
- **Severity**: 8/10

### 3. Multiple Login Username Detection
- **Rule ID**: `multiple_login_usernames`
- **Description**: Detects attempts to login with multiple different usernames from same IP
- **Detection Method**: Tracks unique usernames per IP in time window
- **Parameters**:
  - Window: 600 seconds (10 minutes)
  - Max unique usernames: 3
- **Action**: Warning
- **Severity**: 7/10

### 4. Multiple Signup Detection
- **Rule ID**: `multiple_signup_usernames`
- **Description**: Detects attempts to create multiple accounts from same IP
- **Detection Method**: Tracks signup attempts per IP
- **Parameters**:
  - Window: 3600 seconds (1 hour)
  - Max signups: 2
- **Action**: Multiple signup action
- **Severity**: 6/10

### 5. Credential Stuffing Detection
- **Rule ID**: `credential_stuffing`
- **Description**: Detects credential stuffing attacks using common passwords
- **Detection Method**: Identifies common weak passwords in login attempts
- **Common Passwords**: `123456`, `password`, `admin`, `qwerty`, `letmein`, `welcome`, `monkey`, `dragon`
- **Action**: Block
- **Severity**: 8/10

## 🌍 Geolocation & Time-based Security

### 6. Business Hours Access Control
- **Rule ID**: `business_hours_access`
- **Description**: Monitors access to admin areas outside business hours
- **Detection Method**: Checks request time against business hours
- **Parameters**:
  - Business hours: 9 AM - 6 PM UTC
  - Applies to: `/admin`, `/dashboard`, `/management`, `/control` paths
- **Action**: Warning
- **Severity**: 4/10

### 7. Login Business Hours Control
- **Rule ID**: `login_business_hours`
- **Description**: Monitors login attempts outside business hours
- **Detection Method**: Checks login time against extended business hours
- **Parameters**:
  - Extended hours: 6 AM - 10 PM UTC
  - Applies to: All login endpoints
- **Action**: Warning
- **Severity**: 5/10

### 8. Geolocation Anomaly Detection
- **Rule ID**: `geolocation_anomaly`
- **Description**: Detects login attempts from unexpected geographical regions
- **Detection Method**: Checks country code against allowed list
- **Parameters**:
  - Allowed countries: US, CA, GB, DE, FR, AU, JP
  - Block high-risk countries: Enabled
- **Action**: CAPTCHA challenge
- **Severity**: 6/10

## 💉 Injection Attack Protection

### 9. SQL Injection Detection (Path)
- **Rule ID**: `sql_injection_union_select`, `sql_injection_or_and`, `sql_injection_exec`, `sql_injection_comments`
- **Description**: Comprehensive SQL injection detection in URL paths
- **Detection Patterns**:
  - UNION SELECT statements
  - OR/AND conditions with quotes
  - EXEC/stored procedure calls
  - SQL comment injection
- **Action**: Block
- **Severity**: 7-9/10

### 10. SQL Injection Detection (Body)
- **Rule ID**: `body_sql_injection`
- **Description**: Detects SQL injection patterns in request body content
- **Detection Patterns**: UNION SELECT, DROP TABLE, INSERT INTO, DELETE FROM, UPDATE SET, EXEC
- **Action**: Block
- **Severity**: 9/10

### 11. XSS Protection (Path & Body)
- **Rule IDs**: `xss_script_tag`, `xss_javascript_protocol`, `xss_event_handlers`, `xss_dangerous_tags`, `body_xss_detection`
- **Description**: Comprehensive XSS attack detection
- **Detection Patterns**:
  - Script tags
  - JavaScript protocol
  - HTML event handlers
  - Dangerous HTML tags (iframe, object, embed)
  - JavaScript functions (eval, alert, confirm, prompt)
- **Action**: Block
- **Severity**: 6-8/10

### 12. Command Injection Protection
- **Rule IDs**: `command_injection`, `body_command_injection`
- **Description**: Detects command injection attempts in paths and body
- **Detection Patterns**: Semicolons, pipes, backticks, command substitution
- **Action**: Block
- **Severity**: 9/10

### 13. Path Traversal Protection
- **Rule IDs**: `path_traversal`, `body_path_traversal`
- **Description**: Prevents directory traversal attacks
- **Detection Patterns**: `../`, `..\`, URL-encoded variants
- **Action**: Block
- **Severity**: 7/10

## 🕵️ Behavioral Security Detection

### 14. DDoS Attack Detection
- **Rule ID**: `ddos_detection`
- **Description**: Detects distributed denial of service attacks
- **Detection Method**: High-volume request detection
- **Parameters**:
  - Window: 60 seconds
  - Max requests: 100
  - Block duration: 3600 seconds (1 hour)
- **Action**: Block
- **Severity**: 9/10

### 15. API Abuse Detection
- **Rule ID**: `api_abuse`
- **Description**: Detects excessive API usage patterns
- **Detection Method**: Monitors API endpoint usage
- **Parameters**:
  - Window: 300 seconds (5 minutes)
  - Max requests: 200
  - Warning threshold: 150
- **Action**: Warning
- **Severity**: 6/10

### 16. Data Exfiltration Detection
- **Rule ID**: `data_exfiltration`
- **Description**: Detects potential data exfiltration attempts
- **Detection Method**: Monitors large data export requests
- **Detection Patterns**: Large limit/count/size parameters in export/download endpoints
- **Action**: Warning
- **Severity**: 8/10

### 17. Privilege Escalation Detection
- **Rule ID**: `privilege_escalation`
- **Description**: Detects attempts to access privileged resources
- **Detection Patterns**:
  - Admin/root/sudo paths
  - Role/permission elevation in request body
- **Action**: Block
- **Severity**: 9/10

### 18. Session Hijacking Detection
- **Rule ID**: `session_hijacking`
- **Description**: Detects potential session hijacking attempts
- **Detection Patterns**:
  - Suspicious User-Agent headers (curl, wget, python, java, go-http)
  - Private IP addresses in X-Forwarded-For headers
- **Action**: Warning
- **Severity**: 8/10

### 19. Reconnaissance Detection
- **Rule ID**: `reconnaissance_scan`
- **Description**: Detects reconnaissance and scanning activities
- **Detection Patterns**:
  - Common reconnaissance files (robots.txt, sitemap.xml, .well-known)
  - Security scanning tool user agents (nmap, nikto, burp, etc.)
- **Action**: Warning
- **Severity**: 5/10

## 🔒 Additional Security Features

### 20. Sensitive File Access Protection
- **Rule ID**: `sensitive_file_access`
- **Description**: Blocks access to sensitive files
- **File Extensions**: `.env`, `.config`, `.ini`, `.conf`, `.log`, `.bak`, `.backup`, `.sql`, `.db`
- **Action**: Block
- **Severity**: 8/10

### 21. Admin Path Protection
- **Rule ID**: `admin_path_access`
- **Description**: Blocks unauthorized access to admin paths
- **Protected Paths**: `/admin/*`
- **Action**: Block
- **Severity**: 6/10

### 22. Sensitive Data Detection
- **Rule ID**: `body_sensitive_data`
- **Description**: Detects potential sensitive data patterns in request body
- **Detection Patterns**: Passwords, secrets, tokens, API keys, private keys
- **Action**: Warning
- **Severity**: 6/10

## 📊 Security Metrics & Monitoring

The system provides comprehensive metrics including:

- **Total Security Checks**: Number of requests analyzed
- **Threats Detected**: Number of security threats identified
- **Detection Rate**: Percentage of requests flagged as threats
- **Active Rules**: Number of security rules currently enabled
- **Requests Processed**: Total requests handled by rule engine
- **Requests Blocked**: Number of requests blocked by security rules

## 🚀 Demo & Testing

### Quick Start
```bash
# Run the comprehensive demo
./run_advanced_demo.sh

# Access the web interface
open http://localhost:8080/advanced_security_demo.html

# View real-time metrics
open http://localhost:8080/metrics
```

### Manual Testing Examples

#### Bot Detection Test
```bash
curl -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: python-requests/2.28.1' \
  -d '{"username":"admin","password":"test"}'
```

#### SQL Injection Test
```bash
curl "http://localhost:8080/api/users?id=1' UNION SELECT * FROM users--"
```

#### XSS Test
```bash
curl "http://localhost:8080/test/xss?comment=<script>alert('xss')</script>"
```

#### DDoS Simulation
```bash
for i in {1..20}; do curl http://localhost:8080/test/ddos & done
```

#### Rate Limiting Test
```bash
for i in {1..10}; do
  curl -X POST http://localhost:8080/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"user'$i'","password":"wrong"}'
  sleep 0.1
done
```

## 🔧 Configuration

All security rules are configured in `config/detectors/generic-rules.json`. Each rule includes:

- **ID**: Unique identifier
- **Name**: Human-readable name
- **Description**: Detailed description
- **Enabled**: Whether the rule is active
- **Type**: Rule category (pattern, behavioral, rate_limit, etc.)
- **Severity**: Risk level (1-10)
- **Confidence**: Detection confidence (0.0-1.0)
- **Priority**: Processing priority
- **Conditions**: Detection logic
- **Actions**: Response actions
- **Tags**: Classification tags
- **Parameters**: Rule-specific settings

## 📈 Performance Impact

The advanced security system is designed for minimal performance impact:

- **Rule Evaluation**: O(n) complexity where n is number of active rules
- **Memory Usage**: Minimal state storage for rate limiting and behavioral analysis
- **CPU Overhead**: < 5% for typical workloads
- **Latency Impact**: < 10ms additional processing time per request

## 🛠️ Customization

Security rules can be customized by:

1. **Modifying Existing Rules**: Edit parameters in `config/detectors/generic-rules.json`
2. **Adding New Rules**: Create new rule definitions following the schema
3. **Adjusting Thresholds**: Tune severity, confidence, and timing parameters
4. **Custom Actions**: Implement additional response actions
5. **Integration**: Connect with external security systems and SIEM tools

## 🔍 Troubleshooting

### Common Issues

1. **High False Positives**: Adjust confidence thresholds and rule parameters
2. **Performance Issues**: Disable non-critical rules or increase processing limits
3. **Configuration Errors**: Validate JSON syntax and rule schema
4. **Missing Detections**: Review rule conditions and test patterns

### Debug Mode

Enable debug logging to troubleshoot rule execution:

```json
{
  "logging": {
    "level": "debug",
    "security_events": true
  }
}
```

## 📚 Additional Resources

- [Configuration System Documentation](docs/CONFIG_SYSTEM_README.md)
- [Rule Engine Architecture](docs/ARCHITECTURE_SUMMARY.md)
- [TCP Protection Features](docs/TCP_PROTECTION_README.md)
- [API Documentation](web/config-dashboard.html)

---

**Note**: This advanced security system provides comprehensive protection against modern web application threats. Regular updates and monitoring are recommended to maintain optimal security posture.
