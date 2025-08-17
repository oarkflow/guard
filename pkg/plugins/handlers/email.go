package handlers

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/guard/pkg/plugins"
)

// EmailHandler implements EventHandler for sending security events via email
type EmailHandler struct {
	name    string
	config  EmailConfig
	metrics struct {
		emailsSent     int64
		eventsFiltered int64
		errors         int64
		rateLimited    int64
	}
	lastSent map[string]time.Time // Rate limiting per event type
	mu       sync.RWMutex
}

// EmailConfig holds configuration for the email handler
type EmailConfig struct {
	SMTPHost          string        `json:"smtp_host"`
	SMTPPort          int           `json:"smtp_port"`
	Username          string        `json:"username"`
	Password          string        `json:"password"`
	From              string        `json:"from"`
	To                []string      `json:"to"`
	CC                []string      `json:"cc"`
	BCC               []string      `json:"bcc"`
	SubjectTemplate   string        `json:"subject_template"`
	BodyTemplate      string        `json:"body_template"`
	SeverityThreshold int           `json:"severity_threshold"`
	RateLimit         string        `json:"rate_limit"` // e.g., "1/5m" = 1 email per 5 minutes
	EventTypes        []string      `json:"event_types"`
	EnableHTML        bool          `json:"enable_html"`
	EnableTLS         bool          `json:"enable_tls"`
	Timeout           time.Duration `json:"timeout"`
}

// NewEmailHandler creates a new email handler
func NewEmailHandler() *EmailHandler {
	return &EmailHandler{
		name: "email_handler",
		config: EmailConfig{
			SMTPHost:          "smtp.example.com",
			SMTPPort:          587,
			From:              "security@example.com",
			To:                []string{"admin@example.com"},
			SubjectTemplate:   "Security Alert: {{.Type}}",
			BodyTemplate:      defaultEmailTemplate,
			SeverityThreshold: 7,
			RateLimit:         "1/5m",
			EventTypes:        []string{"*"},
			EnableHTML:        true,
			EnableTLS:         true,
			Timeout:           30 * time.Second,
		},
		lastSent: make(map[string]time.Time),
	}
}

// Default email template
const defaultEmailTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Security Alert</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f44336; color: white; padding: 10px; }
        .content { padding: 20px; border: 1px solid #ddd; }
        .severity-high { color: #f44336; font-weight: bold; }
        .severity-medium { color: #ff9800; font-weight: bold; }
        .severity-low { color: #4caf50; }
        .metadata { background-color: #f5f5f5; padding: 10px; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h2>Security Alert: {{.Type}}</h2>
    </div>
    <div class="content">
        <p><strong>Event ID:</strong> {{.ID}}</p>
        <p><strong>Timestamp:</strong> {{.Timestamp.Format "2006-01-02 15:04:05 UTC"}}</p>
        <p><strong>Source IP:</strong> {{.IP}}</p>
        {{if .UserID}}<p><strong>User ID:</strong> {{.UserID}}</p>{{end}}
        <p><strong>Severity:</strong>
            {{if ge .Severity 8}}<span class="severity-high">{{.Severity}} (High)</span>
            {{else if ge .Severity 5}}<span class="severity-medium">{{.Severity}} (Medium)</span>
            {{else}}<span class="severity-low">{{.Severity}} (Low)</span>{{end}}
        </p>
        <p><strong>Source:</strong> {{.Source}}</p>
        {{if .Tags}}<p><strong>Tags:</strong> {{range .Tags}}{{.}} {{end}}</p>{{end}}

        <h3>Details</h3>
        <div class="metadata">
            {{range $key, $value := .Details}}
            <p><strong>{{$key}}:</strong> {{$value}}</p>
            {{end}}
        </div>

        {{if .Metadata}}
        <h3>Additional Information</h3>
        <div class="metadata">
            {{range $key, $value := .Metadata}}
            <p><strong>{{$key}}:</strong> {{$value}}</p>
            {{end}}
        </div>
        {{end}}
    </div>
    <div style="margin-top: 20px; font-size: 12px; color: #666;">
        <p>This is an automated security alert from Guard Security System v2.0.0</p>
        <p>Generated at: {{.Timestamp.Format "2006-01-02 15:04:05 UTC"}}</p>
    </div>
</body>
</html>
`

// Name returns the handler name
func (h *EmailHandler) Name() string {
	return h.name
}

// Handle processes a security event
func (h *EmailHandler) Handle(ctx context.Context, event plugins.SecurityEvent) error {
	h.mu.RLock()
	config := h.config
	h.mu.RUnlock()

	// Check if we should handle this event type
	if !h.shouldHandleEvent(event.Type, config.EventTypes) {
		h.metrics.eventsFiltered++
		return nil
	}

	// Check severity threshold
	if event.Severity < config.SeverityThreshold {
		h.metrics.eventsFiltered++
		return nil
	}

	// Check rate limiting
	if h.isRateLimited(event.Type, config.RateLimit) {
		h.metrics.rateLimited++
		return nil
	}

	// Send email
	return h.sendEmail(ctx, event, config)
}

// sendEmail sends an email for the security event
func (h *EmailHandler) sendEmail(ctx context.Context, event plugins.SecurityEvent, config EmailConfig) error {
	// Generate subject
	subject := h.generateSubject(event, config.SubjectTemplate)

	// Generate body
	body := h.generateBody(event, config.BodyTemplate, config.EnableHTML)

	// Create email message
	message := h.createEmailMessage(config, subject, body)

	// Send via SMTP
	err := h.sendSMTP(config, message)
	if err != nil {
		h.metrics.errors++
		return fmt.Errorf("failed to send email: %w", err)
	}

	// Update rate limiting
	h.mu.Lock()
	h.lastSent[event.Type] = time.Now()
	h.mu.Unlock()

	h.metrics.emailsSent++
	return nil
}

// generateSubject generates the email subject from template
func (h *EmailHandler) generateSubject(event plugins.SecurityEvent, template string) string {
	subject := template

	// Simple template replacement
	replacements := map[string]string{
		"{{.Type}}":     event.Type,
		"{{.Severity}}": fmt.Sprintf("%d", event.Severity),
		"{{.IP}}":       event.IP,
		"{{.UserID}}":   event.UserID,
		"{{.Source}}":   event.Source,
		"{{.ID}}":       event.ID,
	}

	for placeholder, value := range replacements {
		subject = strings.ReplaceAll(subject, placeholder, value)
	}

	return subject
}

// generateBody generates the email body from template
func (h *EmailHandler) generateBody(event plugins.SecurityEvent, template string, enableHTML bool) string {
	if !enableHTML {
		// Generate plain text version
		return h.generatePlainTextBody(event)
	}

	// For HTML, we'll use the template as-is for now
	// In a real implementation, you'd use a proper template engine
	body := template

	// Simple replacements for basic template variables
	replacements := map[string]string{
		"{{.Type}}":     event.Type,
		"{{.ID}}":       event.ID,
		"{{.IP}}":       event.IP,
		"{{.UserID}}":   event.UserID,
		"{{.Source}}":   event.Source,
		"{{.Severity}}": fmt.Sprintf("%d", event.Severity),
		"{{.Timestamp.Format \"2006-01-02 15:04:05 UTC\"}}": event.Timestamp.Format("2006-01-02 15:04:05 UTC"),
	}

	for placeholder, value := range replacements {
		body = strings.ReplaceAll(body, placeholder, value)
	}

	return body
}

// generatePlainTextBody generates a plain text email body
func (h *EmailHandler) generatePlainTextBody(event plugins.SecurityEvent) string {
	var body strings.Builder

	body.WriteString("SECURITY ALERT\n")
	body.WriteString("==============\n\n")
	body.WriteString(fmt.Sprintf("Event Type: %s\n", event.Type))
	body.WriteString(fmt.Sprintf("Event ID: %s\n", event.ID))
	body.WriteString(fmt.Sprintf("Timestamp: %s\n", event.Timestamp.Format("2006-01-02 15:04:05 UTC")))
	body.WriteString(fmt.Sprintf("Source IP: %s\n", event.IP))

	if event.UserID != "" {
		body.WriteString(fmt.Sprintf("User ID: %s\n", event.UserID))
	}

	body.WriteString(fmt.Sprintf("Severity: %d\n", event.Severity))
	body.WriteString(fmt.Sprintf("Source: %s\n", event.Source))

	if len(event.Tags) > 0 {
		body.WriteString(fmt.Sprintf("Tags: %s\n", strings.Join(event.Tags, ", ")))
	}

	body.WriteString("\nDetails:\n")
	body.WriteString("--------\n")
	for key, value := range event.Details {
		body.WriteString(fmt.Sprintf("%s: %v\n", key, value))
	}

	if len(event.Metadata) > 0 {
		body.WriteString("\nAdditional Information:\n")
		body.WriteString("-----------------------\n")
		for key, value := range event.Metadata {
			body.WriteString(fmt.Sprintf("%s: %v\n", key, value))
		}
	}

	body.WriteString("\n---\n")
	body.WriteString("This is an automated security alert from Guard Security System v2.0.0\n")
	body.WriteString(fmt.Sprintf("Generated at: %s\n", time.Now().Format("2006-01-02 15:04:05 UTC")))

	return body.String()
}

// createEmailMessage creates the complete email message
func (h *EmailHandler) createEmailMessage(config EmailConfig, subject, body string) string {
	var message strings.Builder

	// Headers
	message.WriteString(fmt.Sprintf("From: %s\r\n", config.From))
	message.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(config.To, ", ")))

	if len(config.CC) > 0 {
		message.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(config.CC, ", ")))
	}

	if len(config.BCC) > 0 {
		message.WriteString(fmt.Sprintf("Bcc: %s\r\n", strings.Join(config.BCC, ", ")))
	}

	message.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))

	if config.EnableHTML {
		message.WriteString("MIME-Version: 1.0\r\n")
		message.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	} else {
		message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	}

	message.WriteString("\r\n")
	message.WriteString(body)

	return message.String()
}

// sendSMTP sends the email via SMTP
func (h *EmailHandler) sendSMTP(config EmailConfig, message string) error {
	// Create all recipients list
	var recipients []string
	recipients = append(recipients, config.To...)
	recipients = append(recipients, config.CC...)
	recipients = append(recipients, config.BCC...)

	// Connect to SMTP server
	addr := fmt.Sprintf("%s:%d", config.SMTPHost, config.SMTPPort)

	var auth smtp.Auth
	if config.Username != "" && config.Password != "" {
		auth = smtp.PlainAuth("", config.Username, config.Password, config.SMTPHost)
	}

	// Send email
	err := smtp.SendMail(addr, auth, config.From, recipients, []byte(message))
	if err != nil {
		return fmt.Errorf("SMTP send failed: %w", err)
	}

	return nil
}

// shouldHandleEvent checks if this handler should handle the given event type
func (h *EmailHandler) shouldHandleEvent(eventType string, eventTypes []string) bool {
	for _, supportedType := range eventTypes {
		if supportedType == "*" || supportedType == eventType {
			return true
		}
	}
	return false
}

// isRateLimited checks if the event type is rate limited
func (h *EmailHandler) isRateLimited(eventType, rateLimit string) bool {
	if rateLimit == "" {
		return false
	}

	h.mu.RLock()
	lastSent, exists := h.lastSent[eventType]
	h.mu.RUnlock()

	if !exists {
		return false
	}

	// Parse rate limit (e.g., "1/5m")
	parts := strings.Split(rateLimit, "/")
	if len(parts) != 2 {
		return false
	}

	duration, err := time.ParseDuration(parts[1])
	if err != nil {
		return false
	}

	return time.Since(lastSent) < duration
}

// CanHandle checks if this handler can handle the given event type
func (h *EmailHandler) CanHandle(eventType string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.shouldHandleEvent(eventType, h.config.EventTypes)
}

// Priority returns the handler priority
func (h *EmailHandler) Priority() int {
	return 80 // Medium-high priority
}

// Initialize initializes the handler with configuration
func (h *EmailHandler) Initialize(config map[string]interface{}) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Parse SMTP host
	if smtpHost, ok := config["smtp_host"].(string); ok {
		h.config.SMTPHost = smtpHost
	}

	// Parse SMTP port
	if smtpPort, ok := config["smtp_port"].(float64); ok {
		h.config.SMTPPort = int(smtpPort)
	}

	// Parse username
	if username, ok := config["username"].(string); ok {
		h.config.Username = username
	}

	// Parse password
	if password, ok := config["password"].(string); ok {
		h.config.Password = password
	}

	// Parse from
	if from, ok := config["from"].(string); ok {
		h.config.From = from
	}

	// Parse to addresses
	if to, ok := config["to"].([]interface{}); ok {
		h.config.To = make([]string, len(to))
		for i, addr := range to {
			if addrStr, ok := addr.(string); ok {
				h.config.To[i] = addrStr
			}
		}
	}

	// Parse subject template
	if subjectTemplate, ok := config["subject_template"].(string); ok {
		h.config.SubjectTemplate = subjectTemplate
	}

	// Parse severity threshold
	if severityThreshold, ok := config["severity_threshold"].(float64); ok {
		h.config.SeverityThreshold = int(severityThreshold)
	}

	// Parse rate limit
	if rateLimit, ok := config["rate_limit"].(string); ok {
		h.config.RateLimit = rateLimit
	}

	// Parse event types
	if eventTypes, ok := config["event_types"].([]interface{}); ok {
		h.config.EventTypes = make([]string, len(eventTypes))
		for i, et := range eventTypes {
			if etStr, ok := et.(string); ok {
				h.config.EventTypes[i] = etStr
			}
		}
	}

	// Parse enable HTML
	if enableHTML, ok := config["enable_html"].(bool); ok {
		h.config.EnableHTML = enableHTML
	}

	return nil
}

// Cleanup cleans up handler resources
func (h *EmailHandler) Cleanup() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Clear rate limiting cache
	h.lastSent = make(map[string]time.Time)
	return nil
}

// GetMetrics returns handler metrics
func (h *EmailHandler) GetMetrics() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	successRate := float64(0)
	totalAttempts := h.metrics.emailsSent + h.metrics.errors
	if totalAttempts > 0 {
		successRate = float64(h.metrics.emailsSent) / float64(totalAttempts)
	}

	return map[string]interface{}{
		"emails_sent":        h.metrics.emailsSent,
		"events_filtered":    h.metrics.eventsFiltered,
		"errors":             h.metrics.errors,
		"rate_limited":       h.metrics.rateLimited,
		"success_rate":       successRate,
		"smtp_host":          h.config.SMTPHost,
		"smtp_port":          h.config.SMTPPort,
		"recipients":         len(h.config.To),
		"severity_threshold": h.config.SeverityThreshold,
		"rate_limit":         h.config.RateLimit,
		"event_types":        h.config.EventTypes,
	}
}
