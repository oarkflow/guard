package detectors

import (
	"context"
	"fmt"
	"regexp"

	"github.com/oarkflow/guard/pkg/plugins"
)

// SQLInjectionDetector implements DetectorPlugin for SQL injection detection
type SQLInjectionDetector struct {
	name        string
	version     string
	description string
	patterns    []*regexp.Regexp
	metrics     struct {
		totalChecks    int64
		threatsFound   int64
		falsePositives int64
	}
}

// NewSQLInjectionDetector creates a new SQL injection detector plugin
func NewSQLInjectionDetector() *SQLInjectionDetector {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|create\s+table)`),
		regexp.MustCompile(`(?i)(\s|^|;)(or|and)\s+\d+\s*=\s*\d+`),
		regexp.MustCompile(`(?i)'.*(\s|^|;)(or|and)\s+.*'`),
		regexp.MustCompile(`(?i)exec\s*\(|execute\s*\(|sp_executesql`),
		regexp.MustCompile(`(?i)(script|javascript|vbscript|onload|onerror)`),
		regexp.MustCompile(`(?i)(waitfor\s+delay|benchmark\s*\(|sleep\s*\()`),
	}

	return &SQLInjectionDetector{
		name:        "sql_injection_detector",
		version:     "1.0.0",
		description: "Detects SQL injection attempts in requests",
		patterns:    patterns,
	}
}

// Name returns the plugin name
func (d *SQLInjectionDetector) Name() string {
	return d.name
}

// Version returns the plugin version
func (d *SQLInjectionDetector) Version() string {
	return d.version
}

// Description returns the plugin description
func (d *SQLInjectionDetector) Description() string {
	return d.description
}

// Initialize initializes the plugin with configuration
func (d *SQLInjectionDetector) Initialize(config map[string]any) error {
	// Add custom patterns if provided
	if customPatterns, ok := config["custom_patterns"].([]any); ok {
		for _, pattern := range customPatterns {
			if patternStr, ok := pattern.(string); ok {
				if regex, err := regexp.Compile(patternStr); err == nil {
					d.patterns = append(d.patterns, regex)
				}
			}
		}
	}

	return nil
}

// Detect performs SQL injection detection
func (d *SQLInjectionDetector) Detect(ctx context.Context, reqCtx *plugins.RequestContext) plugins.DetectionResult {
	d.metrics.totalChecks++

	testStrings := []string{reqCtx.Path}

	// Add query parameters
	for _, v := range reqCtx.QueryParams {
		testStrings = append(testStrings, v)
	}

	// Add headers that might contain user input
	suspiciousHeaders := []string{"User-Agent", "Referer", "X-Forwarded-For", "Cookie"}
	for _, header := range suspiciousHeaders {
		if value, exists := reqCtx.Headers[header]; exists {
			testStrings = append(testStrings, value)
		}
	}

	for _, str := range testStrings {
		for i, pattern := range d.patterns {
			if pattern.MatchString(str) {
				d.metrics.threatsFound++
				confidence := 0.7 + float64(i)*0.05
				if confidence > 1.0 {
					confidence = 1.0
				}

				return plugins.DetectionResult{
					Threat:     true,
					Confidence: confidence,
					Details:    fmt.Sprintf("SQL injection pattern detected: %s in %s", pattern.String(), str),
					Severity:   8, // High severity
					Tags:       []string{"sql_injection", "web_attack", "injection"},
					Metadata: map[string]any{
						"pattern_index": i,
						"matched_text":  str,
						"pattern":       pattern.String(),
					},
				}
			}
		}
	}

	return plugins.DetectionResult{
		Threat:     false,
		Confidence: 0,
		Details:    "No SQL injection patterns detected",
		Severity:   0,
		Tags:       []string{},
		Metadata:   map[string]any{},
	}
}

// Cleanup cleans up plugin resources
func (d *SQLInjectionDetector) Cleanup() error {
	// Nothing to cleanup for this plugin
	return nil
}

// Health checks plugin health
func (d *SQLInjectionDetector) Health() error {
	if len(d.patterns) == 0 {
		return fmt.Errorf("no patterns loaded")
	}
	return nil
}

// GetMetrics returns plugin metrics
func (d *SQLInjectionDetector) GetMetrics() map[string]any {
	return map[string]any{
		"total_checks":    d.metrics.totalChecks,
		"threats_found":   d.metrics.threatsFound,
		"false_positives": d.metrics.falsePositives,
		"patterns_count":  len(d.patterns),
		"detection_rate":  float64(d.metrics.threatsFound) / float64(d.metrics.totalChecks+1),
	}
}
