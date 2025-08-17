package handlers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/guard/pkg/plugins"
)

// MetricsHandler implements EventHandler for collecting and exposing metrics
type MetricsHandler struct {
	name    string
	config  MetricsConfig
	metrics MetricsData
	mu      sync.RWMutex
}

// MetricsConfig holds configuration for the metrics handler
type MetricsConfig struct {
	ExportInterval   time.Duration `json:"export_interval"`
	MetricsEndpoint  string        `json:"metrics_endpoint"`
	IncludeLabels    bool          `json:"include_labels"`
	HistogramBuckets []float64     `json:"histogram_buckets"`
	RetentionPeriod  time.Duration `json:"retention_period"`
	EventTypes       []string      `json:"event_types"`
	SeverityLevels   []int         `json:"severity_levels"`
	EnablePrometheus bool          `json:"enable_prometheus"`
	EnableCustom     bool          `json:"enable_custom"`
}

// MetricsData holds all collected metrics
type MetricsData struct {
	// Event counters
	TotalEvents      int64            `json:"total_events"`
	EventsByType     map[string]int64 `json:"events_by_type"`
	EventsBySeverity map[int]int64    `json:"events_by_severity"`
	EventsBySource   map[string]int64 `json:"events_by_source"`
	EventsByIP       map[string]int64 `json:"events_by_ip"`

	// Timing metrics
	ProcessingTimes []float64 `json:"processing_times"`
	AverageLatency  float64   `json:"average_latency"`
	MaxLatency      float64   `json:"max_latency"`
	MinLatency      float64   `json:"min_latency"`

	// Rate metrics
	EventsPerSecond float64 `json:"events_per_second"`
	EventsPerMinute float64 `json:"events_per_minute"`
	EventsPerHour   float64 `json:"events_per_hour"`

	// Time-based metrics
	HourlyEvents map[int]int64    `json:"hourly_events"` // Events by hour of day
	DailyEvents  map[string]int64 `json:"daily_events"`  // Events by date

	// Threat metrics
	ThreatsByTag    map[string]int64 `json:"threats_by_tag"`
	BlockedRequests int64            `json:"blocked_requests"`
	AllowedRequests int64            `json:"allowed_requests"`

	// System metrics
	StartTime     time.Time `json:"start_time"`
	LastEventTime time.Time `json:"last_event_time"`
	UptimeSeconds float64   `json:"uptime_seconds"`

	// Custom metrics
	CustomCounters map[string]int64   `json:"custom_counters"`
	CustomGauges   map[string]float64 `json:"custom_gauges"`
}

// NewMetricsHandler creates a new metrics handler
func NewMetricsHandler() *MetricsHandler {
	return &MetricsHandler{
		name: "metrics_handler",
		config: MetricsConfig{
			ExportInterval:   30 * time.Second,
			MetricsEndpoint:  "/metrics",
			IncludeLabels:    true,
			HistogramBuckets: []float64{0.1, 0.5, 1.0, 2.5, 5.0, 10.0},
			RetentionPeriod:  24 * time.Hour,
			EventTypes:       []string{"*"},
			SeverityLevels:   []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			EnablePrometheus: true,
			EnableCustom:     true,
		},
		metrics: MetricsData{
			EventsByType:     make(map[string]int64),
			EventsBySeverity: make(map[int]int64),
			EventsBySource:   make(map[string]int64),
			EventsByIP:       make(map[string]int64),
			ProcessingTimes:  make([]float64, 0),
			HourlyEvents:     make(map[int]int64),
			DailyEvents:      make(map[string]int64),
			ThreatsByTag:     make(map[string]int64),
			CustomCounters:   make(map[string]int64),
			CustomGauges:     make(map[string]float64),
			StartTime:        time.Now(),
			MinLatency:       999999, // Initialize to high value
		},
	}
}

// Name returns the handler name
func (h *MetricsHandler) Name() string {
	return h.name
}

// Handle processes a security event and updates metrics
func (h *MetricsHandler) Handle(ctx context.Context, event plugins.SecurityEvent) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	startTime := time.Now()

	// Check if we should handle this event type
	if !h.shouldHandleEvent(event.Type) {
		return nil
	}

	// Update basic counters
	h.metrics.TotalEvents++
	h.metrics.EventsByType[event.Type]++
	h.metrics.EventsBySeverity[event.Severity]++
	h.metrics.EventsBySource[event.Source]++
	h.metrics.EventsByIP[event.IP]++

	// Update time-based metrics
	now := time.Now()
	h.metrics.LastEventTime = now
	h.metrics.UptimeSeconds = now.Sub(h.metrics.StartTime).Seconds()

	// Update hourly events
	hour := now.Hour()
	h.metrics.HourlyEvents[hour]++

	// Update daily events
	date := now.Format("2006-01-02")
	h.metrics.DailyEvents[date]++

	// Update threat metrics by tags
	for _, tag := range event.Tags {
		h.metrics.ThreatsByTag[tag]++
	}

	// Update blocked/allowed counters based on event metadata
	if blocked, exists := event.Metadata["blocked"]; exists {
		if blockedBool, ok := blocked.(bool); ok && blockedBool {
			h.metrics.BlockedRequests++
		} else {
			h.metrics.AllowedRequests++
		}
	}

	// Update processing time metrics
	processingTime := time.Since(startTime).Seconds()
	h.metrics.ProcessingTimes = append(h.metrics.ProcessingTimes, processingTime)

	// Keep only recent processing times (for memory efficiency)
	if len(h.metrics.ProcessingTimes) > 1000 {
		h.metrics.ProcessingTimes = h.metrics.ProcessingTimes[len(h.metrics.ProcessingTimes)-500:]
	}

	// Update latency metrics
	if processingTime > h.metrics.MaxLatency {
		h.metrics.MaxLatency = processingTime
	}
	if processingTime < h.metrics.MinLatency {
		h.metrics.MinLatency = processingTime
	}

	// Calculate average latency
	if len(h.metrics.ProcessingTimes) > 0 {
		total := 0.0
		for _, t := range h.metrics.ProcessingTimes {
			total += t
		}
		h.metrics.AverageLatency = total / float64(len(h.metrics.ProcessingTimes))
	}

	// Update rate metrics (simplified calculation)
	h.updateRateMetrics()

	// Update custom metrics from event metadata
	h.updateCustomMetrics(event)

	return nil
}

// updateRateMetrics updates the rate-based metrics
func (h *MetricsHandler) updateRateMetrics() {
	if h.metrics.UptimeSeconds > 0 {
		h.metrics.EventsPerSecond = float64(h.metrics.TotalEvents) / h.metrics.UptimeSeconds
		h.metrics.EventsPerMinute = h.metrics.EventsPerSecond * 60
		h.metrics.EventsPerHour = h.metrics.EventsPerMinute * 60
	}
}

// updateCustomMetrics updates custom metrics from event metadata
func (h *MetricsHandler) updateCustomMetrics(event plugins.SecurityEvent) {
	// Look for custom metric keys in event metadata
	for key, value := range event.Metadata {
		if key == "custom_counter" {
			if counterName, ok := value.(string); ok {
				h.metrics.CustomCounters[counterName]++
			}
		} else if key == "custom_gauge" {
			if gaugeData, ok := value.(map[string]interface{}); ok {
				if name, nameOk := gaugeData["name"].(string); nameOk {
					if val, valOk := gaugeData["value"].(float64); valOk {
						h.metrics.CustomGauges[name] = val
					}
				}
			}
		}
	}
}

// shouldHandleEvent checks if this handler should handle the given event type
func (h *MetricsHandler) shouldHandleEvent(eventType string) bool {
	for _, supportedType := range h.config.EventTypes {
		if supportedType == "*" || supportedType == eventType {
			return true
		}
	}
	return false
}

// CanHandle checks if this handler can handle the given event type
func (h *MetricsHandler) CanHandle(eventType string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.shouldHandleEvent(eventType)
}

// Priority returns the handler priority
func (h *MetricsHandler) Priority() int {
	return 70 // Medium priority
}

// Initialize initializes the handler with configuration
func (h *MetricsHandler) Initialize(config map[string]interface{}) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Parse export interval
	if exportIntervalStr, ok := config["export_interval"].(string); ok {
		if interval, err := time.ParseDuration(exportIntervalStr); err == nil {
			h.config.ExportInterval = interval
		}
	}

	// Parse metrics endpoint
	if metricsEndpoint, ok := config["metrics_endpoint"].(string); ok {
		h.config.MetricsEndpoint = metricsEndpoint
	}

	// Parse include labels
	if includeLabels, ok := config["include_labels"].(bool); ok {
		h.config.IncludeLabels = includeLabels
	}

	// Parse histogram buckets
	if buckets, ok := config["histogram_buckets"].([]interface{}); ok {
		h.config.HistogramBuckets = make([]float64, len(buckets))
		for i, bucket := range buckets {
			if bucketFloat, ok := bucket.(float64); ok {
				h.config.HistogramBuckets[i] = bucketFloat
			}
		}
	}

	// Parse retention period
	if retentionStr, ok := config["retention_period"].(string); ok {
		if retention, err := time.ParseDuration(retentionStr); err == nil {
			h.config.RetentionPeriod = retention
		}
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

	// Parse enable prometheus
	if enablePrometheus, ok := config["enable_prometheus"].(bool); ok {
		h.config.EnablePrometheus = enablePrometheus
	}

	// Parse enable custom
	if enableCustom, ok := config["enable_custom"].(bool); ok {
		h.config.EnableCustom = enableCustom
	}

	return nil
}

// GetMetrics returns the current metrics data
func (h *MetricsHandler) GetMetrics() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Create a copy of metrics for safe access
	metricsMap := map[string]interface{}{
		"total_events":       h.metrics.TotalEvents,
		"events_by_type":     h.copyStringInt64Map(h.metrics.EventsByType),
		"events_by_severity": h.copyIntInt64Map(h.metrics.EventsBySeverity),
		"events_by_source":   h.copyStringInt64Map(h.metrics.EventsBySource),
		"events_by_ip":       h.copyStringInt64Map(h.metrics.EventsByIP),
		"average_latency":    h.metrics.AverageLatency,
		"max_latency":        h.metrics.MaxLatency,
		"min_latency":        h.metrics.MinLatency,
		"events_per_second":  h.metrics.EventsPerSecond,
		"events_per_minute":  h.metrics.EventsPerMinute,
		"events_per_hour":    h.metrics.EventsPerHour,
		"hourly_events":      h.copyIntInt64Map(h.metrics.HourlyEvents),
		"daily_events":       h.copyStringInt64Map(h.metrics.DailyEvents),
		"threats_by_tag":     h.copyStringInt64Map(h.metrics.ThreatsByTag),
		"blocked_requests":   h.metrics.BlockedRequests,
		"allowed_requests":   h.metrics.AllowedRequests,
		"start_time":         h.metrics.StartTime,
		"last_event_time":    h.metrics.LastEventTime,
		"uptime_seconds":     h.metrics.UptimeSeconds,
		"custom_counters":    h.copyStringInt64Map(h.metrics.CustomCounters),
		"custom_gauges":      h.copyStringFloat64Map(h.metrics.CustomGauges),
	}

	// Add configuration info
	metricsMap["config"] = map[string]interface{}{
		"export_interval":   h.config.ExportInterval.String(),
		"metrics_endpoint":  h.config.MetricsEndpoint,
		"include_labels":    h.config.IncludeLabels,
		"retention_period":  h.config.RetentionPeriod.String(),
		"event_types":       h.config.EventTypes,
		"enable_prometheus": h.config.EnablePrometheus,
		"enable_custom":     h.config.EnableCustom,
	}

	return metricsMap
}

// Helper functions to safely copy maps
func (h *MetricsHandler) copyStringInt64Map(original map[string]int64) map[string]int64 {
	copy := make(map[string]int64)
	for k, v := range original {
		copy[k] = v
	}
	return copy
}

func (h *MetricsHandler) copyIntInt64Map(original map[int]int64) map[int]int64 {
	copy := make(map[int]int64)
	for k, v := range original {
		copy[k] = v
	}
	return copy
}

func (h *MetricsHandler) copyStringFloat64Map(original map[string]float64) map[string]float64 {
	copy := make(map[string]float64)
	for k, v := range original {
		copy[k] = v
	}
	return copy
}

// GetPrometheusMetrics returns metrics in Prometheus format
func (h *MetricsHandler) GetPrometheusMetrics() string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if !h.config.EnablePrometheus {
		return ""
	}

	var prometheus string

	// Total events
	prometheus += fmt.Sprintf("# HELP guard_total_events Total number of security events processed\n")
	prometheus += fmt.Sprintf("# TYPE guard_total_events counter\n")
	prometheus += fmt.Sprintf("guard_total_events %d\n\n", h.metrics.TotalEvents)

	// Events by type
	prometheus += fmt.Sprintf("# HELP guard_events_by_type Number of events by type\n")
	prometheus += fmt.Sprintf("# TYPE guard_events_by_type counter\n")
	for eventType, count := range h.metrics.EventsByType {
		prometheus += fmt.Sprintf("guard_events_by_type{type=\"%s\"} %d\n", eventType, count)
	}
	prometheus += "\n"

	// Events by severity
	prometheus += fmt.Sprintf("# HELP guard_events_by_severity Number of events by severity level\n")
	prometheus += fmt.Sprintf("# TYPE guard_events_by_severity counter\n")
	for severity, count := range h.metrics.EventsBySeverity {
		prometheus += fmt.Sprintf("guard_events_by_severity{severity=\"%d\"} %d\n", severity, count)
	}
	prometheus += "\n"

	// Processing latency
	prometheus += fmt.Sprintf("# HELP guard_processing_latency_seconds Processing latency in seconds\n")
	prometheus += fmt.Sprintf("# TYPE guard_processing_latency_seconds gauge\n")
	prometheus += fmt.Sprintf("guard_processing_latency_seconds{type=\"average\"} %f\n", h.metrics.AverageLatency)
	prometheus += fmt.Sprintf("guard_processing_latency_seconds{type=\"max\"} %f\n", h.metrics.MaxLatency)
	prometheus += fmt.Sprintf("guard_processing_latency_seconds{type=\"min\"} %f\n", h.metrics.MinLatency)
	prometheus += "\n"

	// Event rates
	prometheus += fmt.Sprintf("# HELP guard_events_per_second Current events per second rate\n")
	prometheus += fmt.Sprintf("# TYPE guard_events_per_second gauge\n")
	prometheus += fmt.Sprintf("guard_events_per_second %f\n", h.metrics.EventsPerSecond)
	prometheus += "\n"

	// Blocked/Allowed requests
	prometheus += fmt.Sprintf("# HELP guard_requests_total Total number of requests by action\n")
	prometheus += fmt.Sprintf("# TYPE guard_requests_total counter\n")
	prometheus += fmt.Sprintf("guard_requests_total{action=\"blocked\"} %d\n", h.metrics.BlockedRequests)
	prometheus += fmt.Sprintf("guard_requests_total{action=\"allowed\"} %d\n", h.metrics.AllowedRequests)
	prometheus += "\n"

	// Uptime
	prometheus += fmt.Sprintf("# HELP guard_uptime_seconds System uptime in seconds\n")
	prometheus += fmt.Sprintf("# TYPE guard_uptime_seconds gauge\n")
	prometheus += fmt.Sprintf("guard_uptime_seconds %f\n", h.metrics.UptimeSeconds)
	prometheus += "\n"

	return prometheus
}

// ResetMetrics resets all metrics (useful for testing)
func (h *MetricsHandler) ResetMetrics() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.metrics = MetricsData{
		EventsByType:     make(map[string]int64),
		EventsBySeverity: make(map[int]int64),
		EventsBySource:   make(map[string]int64),
		EventsByIP:       make(map[string]int64),
		ProcessingTimes:  make([]float64, 0),
		HourlyEvents:     make(map[int]int64),
		DailyEvents:      make(map[string]int64),
		ThreatsByTag:     make(map[string]int64),
		CustomCounters:   make(map[string]int64),
		CustomGauges:     make(map[string]float64),
		StartTime:        time.Now(),
		MinLatency:       999999,
	}
}

// Cleanup cleans up handler resources
func (h *MetricsHandler) Cleanup() error {
	// No cleanup needed for metrics handler
	return nil
}
