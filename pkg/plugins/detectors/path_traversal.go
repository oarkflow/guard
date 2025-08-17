package detectors

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/oarkflow/guard/pkg/plugins"
)

// PathTraversalDetector implements DetectorPlugin for path traversal detection
type PathTraversalDetector struct {
	name        string
	version     string
	description string
	patterns    []*regexp.Regexp
	config      PathTraversalConfig
	metrics     struct {
		totalChecks    int64
		threatsFound   int64
		falsePositives int64
	}
}

// PathTraversalConfig holds configuration for path traversal detection
type PathTraversalConfig struct {
	CheckPath        bool     `json:"check_path"`
	CheckQueryParams bool     `json:"check_query_params"`
	NormalizePath    bool     `json:"normalize_path"`
	Patterns         []string `json:"patterns"`
}

// NewPathTraversalDetector creates a new path traversal detector plugin
func NewPathTraversalDetector() *PathTraversalDetector {
	patterns := []*regexp.Regexp{
		// Basic directory traversal patterns
		regexp.MustCompile(`\.\.\/`),
		regexp.MustCompile(`\.\.\\`),

		// URL encoded patterns
		regexp.MustCompile(`%2e%2e%2f`),
		regexp.MustCompile(`%2e%2e%5c`),
		regexp.MustCompile(`\.\.%2f`),
		regexp.MustCompile(`\.\.%5c`),

		// Double URL encoded patterns
		regexp.MustCompile(`%252e%252e%252f`),
		regexp.MustCompile(`%252e%252e%255c`),

		// Unicode encoded patterns (literal strings, not escape sequences)
		regexp.MustCompile(`\\u002e\\u002e\\u002f`),
		regexp.MustCompile(`\\u002e\\u002e\\u005c`),

		// Common sensitive files (Unix/Linux)
		regexp.MustCompile(`(?i)etc/passwd`),
		regexp.MustCompile(`(?i)etc/shadow`),
		regexp.MustCompile(`(?i)etc/hosts`),
		regexp.MustCompile(`(?i)proc/`),
		regexp.MustCompile(`(?i)var/log/`),
		regexp.MustCompile(`(?i)home/`),
		regexp.MustCompile(`(?i)root/`),
		regexp.MustCompile(`(?i)usr/bin/`),

		// Common sensitive files (Windows)
		regexp.MustCompile(`(?i)windows/system32`),
		regexp.MustCompile(`(?i)boot\.ini`),
		regexp.MustCompile(`(?i)win\.ini`),
		regexp.MustCompile(`(?i)system\.ini`),
		regexp.MustCompile(`(?i)autoexec\.bat`),
		regexp.MustCompile(`(?i)config\.sys`),
		regexp.MustCompile(`(?i)windows/repair/sam`),

		// Application specific paths
		regexp.MustCompile(`(?i)web\.config`),
		regexp.MustCompile(`(?i)\.htaccess`),
		regexp.MustCompile(`(?i)\.htpasswd`),
		regexp.MustCompile(`(?i)\.env`),
		regexp.MustCompile(`(?i)\.git/`),
		regexp.MustCompile(`(?i)\.svn/`),
		regexp.MustCompile(`(?i)backup/`),
		regexp.MustCompile(`(?i)config/`),
		regexp.MustCompile(`(?i)admin/`),

		// Null byte injection
		regexp.MustCompile(`%00`),
		regexp.MustCompile(`\x00`),
	}

	return &PathTraversalDetector{
		name:        "path_traversal_detector",
		version:     "1.0.0",
		description: "Detects path traversal attempts in requests",
		patterns:    patterns,
		config: PathTraversalConfig{
			CheckPath:        true,
			CheckQueryParams: true,
			NormalizePath:    true,
		},
	}
}

// Name returns the plugin name
func (d *PathTraversalDetector) Name() string {
	return d.name
}

// Version returns the plugin version
func (d *PathTraversalDetector) Version() string {
	return d.version
}

// Description returns the plugin description
func (d *PathTraversalDetector) Description() string {
	return d.description
}

// Initialize initializes the plugin with configuration
func (d *PathTraversalDetector) Initialize(config map[string]any) error {
	// Parse check path
	if checkPath, ok := config["check_path"].(bool); ok {
		d.config.CheckPath = checkPath
	}

	// Parse check query params
	if checkQuery, ok := config["check_query_params"].(bool); ok {
		d.config.CheckQueryParams = checkQuery
	}

	// Parse normalize path
	if normalize, ok := config["normalize_path"].(bool); ok {
		d.config.NormalizePath = normalize
	}

	// Add custom patterns if provided
	if customPatterns, ok := config["patterns"].([]any); ok {
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

// Detect performs path traversal detection
func (d *PathTraversalDetector) Detect(ctx context.Context, reqCtx *plugins.RequestContext) plugins.DetectionResult {
	d.metrics.totalChecks++

	var testStrings []string

	// Add path if configured
	if d.config.CheckPath {
		testStrings = append(testStrings, reqCtx.Path)
	}

	// Add query parameters if configured
	if d.config.CheckQueryParams {
		for _, v := range reqCtx.QueryParams {
			testStrings = append(testStrings, v)
		}
	}

	// Process each test string
	for _, str := range testStrings {
		if result := d.checkString(str); result.Threat {
			d.metrics.threatsFound++
			return result
		}
	}

	return plugins.DetectionResult{
		Threat:     false,
		Confidence: 0,
		Details:    "No path traversal patterns detected",
		Severity:   0,
		Tags:       []string{},
		Metadata:   map[string]any{},
	}
}

// checkString checks a single string for path traversal patterns
func (d *PathTraversalDetector) checkString(str string) plugins.DetectionResult {
	originalStr := str

	// URL decode the string
	if decoded, err := url.QueryUnescape(str); err == nil {
		str = decoded
	}

	// Normalize path if configured
	if d.config.NormalizePath {
		str = d.normalizePath(str)
	}

	// Convert to lowercase for case-insensitive matching
	lowerStr := strings.ToLower(str)

	// Check against patterns
	for i, pattern := range d.patterns {
		if pattern.MatchString(str) || pattern.MatchString(lowerStr) {
			confidence := 0.8
			severity := 7 // High severity

			// Increase confidence and severity for certain patterns
			if strings.Contains(lowerStr, "..") {
				confidence = 0.9
				severity = 8
			}
			if strings.Contains(lowerStr, "passwd") || strings.Contains(lowerStr, "shadow") {
				confidence = 0.95
				severity = 9
			}
			if strings.Contains(lowerStr, "%00") || strings.Contains(str, "\x00") {
				confidence = 1.0
				severity = 9
			}

			return plugins.DetectionResult{
				Threat:     true,
				Confidence: confidence,
				Details:    fmt.Sprintf("Path traversal pattern detected: %s in %s", pattern.String(), originalStr),
				Severity:   severity,
				Tags:       []string{"path_traversal", "web_attack", "file_access", "directory_traversal"},
				Metadata: map[string]any{
					"pattern_index": i,
					"matched_text":  originalStr,
					"normalized":    str,
					"pattern":       pattern.String(),
				},
			}
		}
	}

	return plugins.DetectionResult{Threat: false}
}

// normalizePath normalizes a path by resolving relative components
func (d *PathTraversalDetector) normalizePath(path string) string {
	// Replace backslashes with forward slashes
	path = strings.ReplaceAll(path, "\\", "/")

	// Clean the path using filepath.Clean (converts to OS-specific separators)
	cleaned := filepath.Clean(path)

	// Convert back to forward slashes for consistent checking
	cleaned = strings.ReplaceAll(cleaned, "\\", "/")

	return cleaned
}

// Cleanup cleans up plugin resources
func (d *PathTraversalDetector) Cleanup() error {
	return nil
}

// Health checks plugin health
func (d *PathTraversalDetector) Health() error {
	if len(d.patterns) == 0 {
		return fmt.Errorf("no patterns loaded")
	}
	return nil
}

// GetMetrics returns plugin metrics
func (d *PathTraversalDetector) GetMetrics() map[string]any {
	return map[string]any{
		"total_checks":    d.metrics.totalChecks,
		"threats_found":   d.metrics.threatsFound,
		"false_positives": d.metrics.falsePositives,
		"patterns_count":  len(d.patterns),
		"detection_rate":  float64(d.metrics.threatsFound) / float64(d.metrics.totalChecks+1),
	}
}
