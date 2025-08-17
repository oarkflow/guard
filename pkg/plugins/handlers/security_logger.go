package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/oarkflow/guard/pkg/plugins"
)

// SecurityLoggerHandler implements EventHandler for logging security events
type SecurityLoggerHandler struct {
	name    string
	logFile *os.File
	config  LoggerConfig
	closed  bool // Track if handler is closed
	metrics struct {
		eventsLogged int64
		errors       int64
	}
	mu sync.RWMutex
}

// LoggerConfig holds configuration for the security logger
type LoggerConfig struct {
	LogFile       string        `json:"log_file"`
	LogLevel      string        `json:"log_level"`
	EventTypes    []string      `json:"event_types"`    // Which event types to log
	IncludeFields []string      `json:"include_fields"` // Which fields to include
	Format        string        `json:"format"`         // "json" or "text"
	BufferSize    int           `json:"buffer_size"`
	FlushInterval time.Duration `json:"flush_interval"`
}

// NewSecurityLoggerHandler creates a new security logger handler
func NewSecurityLoggerHandler() *SecurityLoggerHandler {
	return &SecurityLoggerHandler{
		name: "security_logger_handler",
		config: LoggerConfig{
			LogFile:       "security_events.log",
			LogLevel:      "INFO",
			EventTypes:    []string{"*"}, // Log all event types by default
			IncludeFields: []string{"*"}, // Include all fields by default
			Format:        "json",
			BufferSize:    1000,
			FlushInterval: 5 * time.Second,
		},
	}
}

// Name returns the handler name
func (h *SecurityLoggerHandler) Name() string {
	return h.name
}

// Handle processes a security event
func (h *SecurityLoggerHandler) Handle(ctx context.Context, event plugins.SecurityEvent) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Check if handler is closed
	if h.closed {
		return fmt.Errorf("handler is closed")
	}

	// Check if we should log this event type
	if !h.shouldLogEvent(event.Type) {
		return nil
	}

	// Check severity level
	if !h.shouldLogSeverity(event.Severity) {
		return nil
	}

	// Format the log entry
	logEntry, err := h.formatLogEntry(event)
	if err != nil {
		h.metrics.errors++
		return fmt.Errorf("failed to format log entry: %w", err)
	}

	// Write to log file (check if file is still open)
	if h.logFile != nil && !h.closed {
		_, err = h.logFile.WriteString(logEntry + "\n")
		if err != nil {
			h.metrics.errors++
			return fmt.Errorf("failed to write to log file: %w", err)
		}
		h.logFile.Sync() // Ensure data is written to disk
	}

	h.metrics.eventsLogged++
	return nil
}

// CanHandle checks if this handler can handle the given event type
func (h *SecurityLoggerHandler) CanHandle(eventType string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Check if we handle all events or specific types
	for _, supportedType := range h.config.EventTypes {
		if supportedType == "*" || supportedType == eventType {
			return true
		}
	}
	return false
}

// Priority returns the handler priority
func (h *SecurityLoggerHandler) Priority() int {
	return 100 // High priority for logging
}

// Initialize initializes the handler with configuration
func (h *SecurityLoggerHandler) Initialize(config map[string]any) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Parse log file
	if logFile, ok := config["log_file"].(string); ok {
		h.config.LogFile = logFile
	}

	// Parse log level
	if logLevel, ok := config["log_level"].(string); ok {
		h.config.LogLevel = logLevel
	}

	// Parse event types
	if eventTypes, ok := config["event_types"].([]any); ok {
		h.config.EventTypes = make([]string, len(eventTypes))
		for i, et := range eventTypes {
			if etStr, ok := et.(string); ok {
				h.config.EventTypes[i] = etStr
			}
		}
	}

	// Parse format
	if format, ok := config["format"].(string); ok {
		h.config.Format = format
	}

	// Open log file
	var err error
	h.logFile, err = os.OpenFile(h.config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %w", h.config.LogFile, err)
	}

	return nil
}

// Cleanup cleans up handler resources
func (h *SecurityLoggerHandler) Cleanup() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Mark as closed to prevent further writes
	h.closed = true

	if h.logFile != nil {
		// Flush any remaining data
		h.logFile.Sync()
		err := h.logFile.Close()
		h.logFile = nil
		return err
	}
	return nil
}

// shouldLogEvent checks if an event type should be logged
func (h *SecurityLoggerHandler) shouldLogEvent(eventType string) bool {
	for _, supportedType := range h.config.EventTypes {
		if supportedType == "*" || supportedType == eventType {
			return true
		}
	}
	return false
}

// shouldLogSeverity checks if an event severity should be logged
func (h *SecurityLoggerHandler) shouldLogSeverity(severity int) bool {
	switch h.config.LogLevel {
	case "DEBUG":
		return true
	case "INFO":
		return severity >= 3
	case "WARN":
		return severity >= 5
	case "ERROR":
		return severity >= 7
	case "CRITICAL":
		return severity >= 9
	default:
		return true
	}
}

// formatLogEntry formats a security event for logging
func (h *SecurityLoggerHandler) formatLogEntry(event plugins.SecurityEvent) (string, error) {
	switch h.config.Format {
	case "json":
		return h.formatJSON(event)
	case "text":
		return h.formatText(event)
	default:
		return h.formatJSON(event)
	}
}

// formatJSON formats the event as JSON
func (h *SecurityLoggerHandler) formatJSON(event plugins.SecurityEvent) (string, error) {
	// Filter fields if specified
	if len(h.config.IncludeFields) > 0 && h.config.IncludeFields[0] != "*" {
		filteredEvent := make(map[string]any)
		eventMap := map[string]any{
			"id":        event.ID,
			"type":      event.Type,
			"timestamp": event.Timestamp,
			"ip":        event.IP,
			"user_id":   event.UserID,
			"severity":  event.Severity,
			"details":   event.Details,
			"source":    event.Source,
			"tags":      event.Tags,
			"metadata":  event.Metadata,
		}

		for _, field := range h.config.IncludeFields {
			if value, exists := eventMap[field]; exists {
				filteredEvent[field] = value
			}
		}

		data, err := json.Marshal(filteredEvent)
		return string(data), err
	}

	data, err := json.Marshal(event)
	return string(data), err
}

// formatText formats the event as human-readable text
func (h *SecurityLoggerHandler) formatText(event plugins.SecurityEvent) (string, error) {
	return fmt.Sprintf("[%s] %s - %s (IP: %s, Severity: %d, Source: %s) - %v",
		event.Timestamp.Format(time.RFC3339),
		event.Type,
		event.ID,
		event.IP,
		event.Severity,
		event.Source,
		event.Details,
	), nil
}

// GetMetrics returns handler metrics
func (h *SecurityLoggerHandler) GetMetrics() map[string]any {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return map[string]any{
		"events_logged": h.metrics.eventsLogged,
		"errors":        h.metrics.errors,
		"log_file":      h.config.LogFile,
		"format":        h.config.Format,
		"event_types":   h.config.EventTypes,
	}
}
