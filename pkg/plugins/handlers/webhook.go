package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/oarkflow/guard/pkg/plugins"
)

// WebhookHandler implements EventHandler for sending events to webhooks
type WebhookHandler struct {
	name       string
	httpClient *http.Client
	config     WebhookConfig
	metrics    struct {
		eventsSent     int64
		eventsFiltered int64
		errors         int64
		retries        int64
	}
	mu sync.RWMutex
}

// WebhookConfig holds configuration for the webhook handler
type WebhookConfig struct {
	WebhookURL      string            `json:"webhook_url"`
	Timeout         time.Duration     `json:"timeout"`
	RetryAttempts   int               `json:"retry_attempts"`
	EventTypes      []string          `json:"event_types"`
	IncludeMetadata bool              `json:"include_metadata"`
	Authentication  AuthConfig        `json:"authentication"`
	Headers         map[string]string `json:"headers"`
	PayloadTemplate string            `json:"payload_template"`
	BatchSize       int               `json:"batch_size"`
	BatchTimeout    time.Duration     `json:"batch_timeout"`
	EnableBatching  bool              `json:"enable_batching"`
	SeverityFilter  int               `json:"severity_filter"` // Minimum severity to send
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Type   string `json:"type"`    // "bearer", "basic", "api_key", "none"
	Token  string `json:"token"`   // For bearer token
	APIKey string `json:"api_key"` // For API key auth
	Header string `json:"header"`  // Header name for API key
}

// WebhookPayload represents the payload sent to webhook
type WebhookPayload struct {
	Events    []plugins.SecurityEvent `json:"events"`
	Timestamp time.Time               `json:"timestamp"`
	Source    string                  `json:"source"`
	Version   string                  `json:"version"`
	Metadata  map[string]interface{}  `json:"metadata,omitempty"`
}

// NewWebhookHandler creates a new webhook handler
func NewWebhookHandler() *WebhookHandler {
	return &WebhookHandler{
		name: "webhook_handler",
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		config: WebhookConfig{
			WebhookURL:      "",
			Timeout:         10 * time.Second,
			RetryAttempts:   3,
			EventTypes:      []string{"*"},
			IncludeMetadata: true,
			Authentication: AuthConfig{
				Type: "none",
			},
			Headers:        make(map[string]string),
			BatchSize:      10,
			BatchTimeout:   30 * time.Second,
			EnableBatching: false,
			SeverityFilter: 0, // Send all severities by default
		},
	}
}

// Name returns the handler name
func (h *WebhookHandler) Name() string {
	return h.name
}

// Handle processes a security event
func (h *WebhookHandler) Handle(ctx context.Context, event plugins.SecurityEvent) error {
	h.mu.RLock()
	config := h.config
	h.mu.RUnlock()

	// Check if we should handle this event type
	if !h.shouldHandleEvent(event.Type, config.EventTypes) {
		h.metrics.eventsFiltered++
		return nil
	}

	// Check severity filter
	if event.Severity < config.SeverityFilter {
		h.metrics.eventsFiltered++
		return nil
	}

	// For now, send individual events (batching could be implemented later)
	return h.sendEvent(ctx, event, config)
}

// sendEvent sends a single event to the webhook
func (h *WebhookHandler) sendEvent(ctx context.Context, event plugins.SecurityEvent, config WebhookConfig) error {
	if config.WebhookURL == "" {
		return fmt.Errorf("webhook URL not configured")
	}

	// Create payload
	payload := WebhookPayload{
		Events:    []plugins.SecurityEvent{event},
		Timestamp: time.Now(),
		Source:    "guard-security-system",
		Version:   "2.0.0",
	}

	if config.IncludeMetadata {
		payload.Metadata = map[string]interface{}{
			"handler": h.name,
			"config":  "webhook",
		}
	}

	// Convert to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		h.metrics.errors++
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Send with retries
	var lastErr error
	for attempt := 0; attempt <= config.RetryAttempts; attempt++ {
		if attempt > 0 {
			h.metrics.retries++
			// Exponential backoff
			backoff := time.Duration(attempt*attempt) * time.Second
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}

		err := h.sendHTTPRequest(ctx, config, jsonData)
		if err == nil {
			h.metrics.eventsSent++
			return nil
		}
		lastErr = err
	}

	h.metrics.errors++
	return fmt.Errorf("failed to send webhook after %d attempts: %w", config.RetryAttempts+1, lastErr)
}

// sendHTTPRequest sends the HTTP request to the webhook
func (h *WebhookHandler) sendHTTPRequest(ctx context.Context, config WebhookConfig, jsonData []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", config.WebhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type
	req.Header.Set("Content-Type", "application/json")

	// Set custom headers
	for key, value := range config.Headers {
		req.Header.Set(key, value)
	}

	// Set authentication
	switch config.Authentication.Type {
	case "bearer":
		if config.Authentication.Token != "" {
			req.Header.Set("Authorization", "Bearer "+config.Authentication.Token)
		}
	case "basic":
		// For basic auth, token should be base64 encoded username:password
		if config.Authentication.Token != "" {
			req.Header.Set("Authorization", "Basic "+config.Authentication.Token)
		}
	case "api_key":
		if config.Authentication.APIKey != "" && config.Authentication.Header != "" {
			req.Header.Set(config.Authentication.Header, config.Authentication.APIKey)
		}
	}

	// Set user agent
	req.Header.Set("User-Agent", "Guard-Security-System/2.0.0")

	// Send request
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for debugging
	body, _ := io.ReadAll(resp.Body)

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// shouldHandleEvent checks if this handler should handle the given event type
func (h *WebhookHandler) shouldHandleEvent(eventType string, eventTypes []string) bool {
	for _, supportedType := range eventTypes {
		if supportedType == "*" || supportedType == eventType {
			return true
		}
	}
	return false
}

// CanHandle checks if this handler can handle the given event type
func (h *WebhookHandler) CanHandle(eventType string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.shouldHandleEvent(eventType, h.config.EventTypes)
}

// Priority returns the handler priority
func (h *WebhookHandler) Priority() int {
	return 90 // High priority
}

// Initialize initializes the handler with configuration
func (h *WebhookHandler) Initialize(config map[string]interface{}) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Parse webhook URL
	if webhookURL, ok := config["webhook_url"].(string); ok {
		h.config.WebhookURL = webhookURL
	}

	// Parse timeout
	if timeoutStr, ok := config["timeout"].(string); ok {
		if timeout, err := time.ParseDuration(timeoutStr); err == nil {
			h.config.Timeout = timeout
			h.httpClient.Timeout = timeout
		}
	}

	// Parse retry attempts
	if retryAttempts, ok := config["retry_attempts"].(float64); ok {
		h.config.RetryAttempts = int(retryAttempts)
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

	// Parse include metadata
	if includeMetadata, ok := config["include_metadata"].(bool); ok {
		h.config.IncludeMetadata = includeMetadata
	}

	// Parse authentication
	if auth, ok := config["authentication"].(map[string]interface{}); ok {
		if authType, ok := auth["type"].(string); ok {
			h.config.Authentication.Type = authType
		}
		if token, ok := auth["token"].(string); ok {
			h.config.Authentication.Token = token
		}
		if apiKey, ok := auth["api_key"].(string); ok {
			h.config.Authentication.APIKey = apiKey
		}
		if header, ok := auth["header"].(string); ok {
			h.config.Authentication.Header = header
		}
	}

	// Parse custom headers
	if headers, ok := config["headers"].(map[string]interface{}); ok {
		h.config.Headers = make(map[string]string)
		for key, value := range headers {
			if valueStr, ok := value.(string); ok {
				h.config.Headers[key] = valueStr
			}
		}
	}

	// Parse severity filter
	if severityFilter, ok := config["severity_filter"].(float64); ok {
		h.config.SeverityFilter = int(severityFilter)
	}

	return nil
}

// Cleanup cleans up handler resources
func (h *WebhookHandler) Cleanup() error {
	// Close HTTP client if needed
	if h.httpClient != nil {
		h.httpClient.CloseIdleConnections()
	}
	return nil
}

// GetMetrics returns handler metrics
func (h *WebhookHandler) GetMetrics() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	successRate := float64(0)
	totalAttempts := h.metrics.eventsSent + h.metrics.errors
	if totalAttempts > 0 {
		successRate = float64(h.metrics.eventsSent) / float64(totalAttempts)
	}

	return map[string]interface{}{
		"events_sent":     h.metrics.eventsSent,
		"events_filtered": h.metrics.eventsFiltered,
		"errors":          h.metrics.errors,
		"retries":         h.metrics.retries,
		"success_rate":    successRate,
		"webhook_url":     h.config.WebhookURL,
		"timeout":         h.config.Timeout.String(),
		"retry_attempts":  h.config.RetryAttempts,
		"event_types":     h.config.EventTypes,
		"severity_filter": h.config.SeverityFilter,
	}
}
