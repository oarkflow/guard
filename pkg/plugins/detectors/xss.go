package detectors

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/oarkflow/guard/pkg/plugins"
)

// XSSDetector implements DetectorPlugin for XSS detection
type XSSDetector struct {
	name        string
	version     string
	description string
	patterns    []*regexp.Regexp
	config      XSSConfig
	metrics     struct {
		totalChecks    int64
		threatsFound   int64
		falsePositives int64
	}
}

// XSSConfig holds configuration for XSS detection
type XSSConfig struct {
	CheckAllParams bool     `json:"check_all_params"`
	DecodeURL      bool     `json:"decode_url"`
	DecodeHTML     bool     `json:"decode_html"`
	Patterns       []string `json:"patterns"`
}

// NewXSSDetector creates a new XSS detector plugin
func NewXSSDetector() *XSSDetector {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<\s*script[^>]*>`),
		regexp.MustCompile(`(?i)javascript\s*:`),
		regexp.MustCompile(`(?i)on\w+\s*=`),
		regexp.MustCompile(`(?i)<\s*iframe[^>]*>`),
		regexp.MustCompile(`(?i)<\s*object[^>]*>`),
		regexp.MustCompile(`(?i)<\s*embed[^>]*>`),
		regexp.MustCompile(`(?i)eval\s*\(`),
		regexp.MustCompile(`(?i)alert\s*\(`),
		regexp.MustCompile(`(?i)confirm\s*\(`),
		regexp.MustCompile(`(?i)prompt\s*\(`),
		regexp.MustCompile(`(?i)document\s*\.\s*cookie`),
		regexp.MustCompile(`(?i)document\s*\.\s*write`),
		regexp.MustCompile(`(?i)window\s*\.\s*location`),
		regexp.MustCompile(`(?i)<\s*img[^>]*src\s*=\s*["\']?\s*javascript:`),
		regexp.MustCompile(`(?i)<\s*link[^>]*href\s*=\s*["\']?\s*javascript:`),
		regexp.MustCompile(`(?i)expression\s*\(`),
		regexp.MustCompile(`(?i)vbscript\s*:`),
		regexp.MustCompile(`(?i)data\s*:\s*text/html`),
	}

	return &XSSDetector{
		name:        "xss_detector",
		version:     "1.0.0",
		description: "Detects Cross-Site Scripting (XSS) attempts in requests",
		patterns:    patterns,
		config: XSSConfig{
			CheckAllParams: true,
			DecodeURL:      true,
			DecodeHTML:     true,
		},
	}
}

// Name returns the plugin name
func (d *XSSDetector) Name() string {
	return d.name
}

// Version returns the plugin version
func (d *XSSDetector) Version() string {
	return d.version
}

// Description returns the plugin description
func (d *XSSDetector) Description() string {
	return d.description
}

// Initialize initializes the plugin with configuration
func (d *XSSDetector) Initialize(config map[string]any) error {
	// Parse check all params
	if checkAll, ok := config["check_all_params"].(bool); ok {
		d.config.CheckAllParams = checkAll
	}

	// Parse decode URL
	if decodeURL, ok := config["decode_url"].(bool); ok {
		d.config.DecodeURL = decodeURL
	}

	// Parse decode HTML
	if decodeHTML, ok := config["decode_html"].(bool); ok {
		d.config.DecodeHTML = decodeHTML
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

// Detect performs XSS detection
func (d *XSSDetector) Detect(ctx context.Context, reqCtx *plugins.RequestContext) plugins.DetectionResult {
	d.metrics.totalChecks++

	var testStrings []string

	// Add path
	testStrings = append(testStrings, reqCtx.Path)

	// Add query parameters
	if d.config.CheckAllParams {
		for _, v := range reqCtx.QueryParams {
			testStrings = append(testStrings, v)
		}
	}

	// Add headers that might contain user input
	suspiciousHeaders := []string{"User-Agent", "Referer", "Cookie", "X-Forwarded-For"}
	for _, header := range suspiciousHeaders {
		if value, exists := reqCtx.Headers[header]; exists {
			testStrings = append(testStrings, value)
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
		Details:    "No XSS patterns detected",
		Severity:   0,
		Tags:       []string{},
		Metadata:   map[string]any{},
	}
}

// checkString checks a single string for XSS patterns
func (d *XSSDetector) checkString(str string) plugins.DetectionResult {
	originalStr := str

	// Decode URL if configured
	if d.config.DecodeURL {
		if decoded, err := url.QueryUnescape(str); err == nil {
			str = decoded
		}
	}

	// Decode HTML if configured
	if d.config.DecodeHTML {
		str = html.UnescapeString(str)
	}

	// Normalize string for better detection
	str = strings.ToLower(str)
	str = strings.ReplaceAll(str, " ", "")
	str = strings.ReplaceAll(str, "\t", "")
	str = strings.ReplaceAll(str, "\n", "")
	str = strings.ReplaceAll(str, "\r", "")

	// Check against patterns
	for i, pattern := range d.patterns {
		if pattern.MatchString(str) {
			confidence := 0.6 + float64(i)*0.02
			if confidence > 1.0 {
				confidence = 1.0
			}

			severity := 7 // High severity for XSS
			if strings.Contains(str, "script") || strings.Contains(str, "javascript") {
				severity = 8 // Very high for script injection
			}

			return plugins.DetectionResult{
				Threat:     true,
				Confidence: confidence,
				Details:    fmt.Sprintf("XSS pattern detected: %s in %s", pattern.String(), originalStr),
				Severity:   severity,
				Tags:       []string{"xss", "web_attack", "injection", "client_side"},
				Metadata: map[string]any{
					"pattern_index": i,
					"matched_text":  originalStr,
					"normalized":    str,
					"pattern":       pattern.String(),
					"decoded_url":   d.config.DecodeURL,
					"decoded_html":  d.config.DecodeHTML,
				},
			}
		}
	}

	return plugins.DetectionResult{Threat: false}
}

// Cleanup cleans up plugin resources
func (d *XSSDetector) Cleanup() error {
	return nil
}

// Health checks plugin health
func (d *XSSDetector) Health() error {
	if len(d.patterns) == 0 {
		return fmt.Errorf("no patterns loaded")
	}
	return nil
}

// GetMetrics returns plugin metrics
func (d *XSSDetector) GetMetrics() map[string]any {
	return map[string]any{
		"total_checks":    d.metrics.totalChecks,
		"threats_found":   d.metrics.threatsFound,
		"false_positives": d.metrics.falsePositives,
		"patterns_count":  len(d.patterns),
		"detection_rate":  float64(d.metrics.threatsFound) / float64(d.metrics.totalChecks+1),
	}
}
