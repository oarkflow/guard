package detectors

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/oarkflow/guard/pkg/plugins"
)

// SuspiciousUserAgentDetector implements DetectorPlugin for suspicious user agent detection
type SuspiciousUserAgentDetector struct {
	name               string
	version            string
	description        string
	suspiciousPatterns []*regexp.Regexp
	whitelistPatterns  []*regexp.Regexp
	config             SuspiciousUserAgentConfig
	metrics            struct {
		totalChecks    int64
		threatsFound   int64
		whitelisted    int64
		emptyUserAgent int64
	}
}

// SuspiciousUserAgentConfig holds configuration for suspicious user agent detection
type SuspiciousUserAgentConfig struct {
	SuspiciousPatterns []string `json:"suspicious_patterns"`
	WhitelistPatterns  []string `json:"whitelist_patterns"`
	Severity           int      `json:"severity"`
	CheckEmpty         bool     `json:"check_empty"`
	CaseSensitive      bool     `json:"case_sensitive"`
}

// NewSuspiciousUserAgentDetector creates a new suspicious user agent detector plugin
func NewSuspiciousUserAgentDetector() *SuspiciousUserAgentDetector {
	// Default suspicious patterns
	suspiciousPatterns := []*regexp.Regexp{
		// Bots and crawlers (non-legitimate)
		regexp.MustCompile(`(?i)(bot|crawler|spider|scraper)`),

		// Command line tools
		regexp.MustCompile(`(?i)(curl|wget|python|java)`),
		regexp.MustCompile(`(?i)(libwww|lwp|urllib|requests)`),
		regexp.MustCompile(`(?i)(httpie|postman|insomnia)`),

		// Security scanners
		regexp.MustCompile(`(?i)(nmap|nikto|sqlmap|burp)`),
		regexp.MustCompile(`(?i)(scanner|exploit|hack|pen)`),
		regexp.MustCompile(`(?i)(vulnerability|security|audit)`),
		regexp.MustCompile(`(?i)(dirb|dirbuster|gobuster)`),
		regexp.MustCompile(`(?i)(wpscan|joomscan|droopescan)`),
		regexp.MustCompile(`(?i)(acunetix|nessus|openvas)`),

		// Suspicious keywords
		regexp.MustCompile(`(?i)(test|testing|probe|scan)`),
		regexp.MustCompile(`(?i)(attack|inject|payload)`),
		regexp.MustCompile(`(?i)(malware|virus|trojan)`),

		// Automated tools
		regexp.MustCompile(`(?i)(selenium|phantomjs|headless)`),
		regexp.MustCompile(`(?i)(automation|script|robot)`),

		// Empty or very short user agents
		regexp.MustCompile(`^$`),
		regexp.MustCompile(`^\s*$`),
		regexp.MustCompile(`^.{1,3}$`),

		// Common fake user agents
		regexp.MustCompile(`(?i)mozilla/4\.0$`),
		regexp.MustCompile(`(?i)mozilla/5\.0$`),
		regexp.MustCompile(`(?i)^user-agent$`),
		regexp.MustCompile(`(?i)^mozilla$`),

		// Suspicious characters or patterns
		regexp.MustCompile(`[<>{}|\\^~\[\]` + "`" + `]`), // Suspicious characters
		regexp.MustCompile(`\$\{.*\}`),                   // Template injection patterns
		regexp.MustCompile(`<%.*%>`),                     // ASP-style injection
		regexp.MustCompile(`<\?.*\?>`),                   // PHP-style injection
	}

	// Default whitelist patterns (legitimate bots)
	whitelistPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)googlebot`),
		regexp.MustCompile(`(?i)bingbot`),
		regexp.MustCompile(`(?i)slurp`), // Yahoo
		regexp.MustCompile(`(?i)duckduckbot`),
		regexp.MustCompile(`(?i)baiduspider`),
		regexp.MustCompile(`(?i)yandexbot`),
		regexp.MustCompile(`(?i)facebookexternalhit`),
		regexp.MustCompile(`(?i)twitterbot`),
		regexp.MustCompile(`(?i)linkedinbot`),
		regexp.MustCompile(`(?i)whatsapp`),
		regexp.MustCompile(`(?i)telegrambot`),
		regexp.MustCompile(`(?i)applebot`),
		regexp.MustCompile(`(?i)amazonbot`),
		regexp.MustCompile(`(?i)pingdom`),
		regexp.MustCompile(`(?i)uptimerobot`),
		regexp.MustCompile(`(?i)statuscake`),
		regexp.MustCompile(`(?i)newrelic`),
		regexp.MustCompile(`(?i)datadog`),
	}

	return &SuspiciousUserAgentDetector{
		name:               "suspicious_user_agent_detector",
		version:            "1.0.0",
		description:        "Detects suspicious user agents that may indicate automated attacks",
		suspiciousPatterns: suspiciousPatterns,
		whitelistPatterns:  whitelistPatterns,
		config: SuspiciousUserAgentConfig{
			Severity:      3, // Medium-low severity by default
			CheckEmpty:    true,
			CaseSensitive: false,
		},
	}
}

// Name returns the plugin name
func (d *SuspiciousUserAgentDetector) Name() string {
	return d.name
}

// Version returns the plugin version
func (d *SuspiciousUserAgentDetector) Version() string {
	return d.version
}

// Description returns the plugin description
func (d *SuspiciousUserAgentDetector) Description() string {
	return d.description
}

// Initialize initializes the plugin with configuration
func (d *SuspiciousUserAgentDetector) Initialize(config map[string]any) error {
	// Parse severity
	if severity, ok := config["severity"].(float64); ok {
		d.config.Severity = int(severity)
	}

	// Parse check empty
	if checkEmpty, ok := config["check_empty"].(bool); ok {
		d.config.CheckEmpty = checkEmpty
	}

	// Parse case sensitive
	if caseSensitive, ok := config["case_sensitive"].(bool); ok {
		d.config.CaseSensitive = caseSensitive
	}

	// Add custom suspicious patterns if provided
	if suspiciousPatterns, ok := config["suspicious_patterns"].([]any); ok {
		for _, pattern := range suspiciousPatterns {
			if patternStr, ok := pattern.(string); ok {
				var regex *regexp.Regexp
				var err error
				if d.config.CaseSensitive {
					regex, err = regexp.Compile(patternStr)
				} else {
					regex, err = regexp.Compile("(?i)" + patternStr)
				}
				if err == nil {
					d.suspiciousPatterns = append(d.suspiciousPatterns, regex)
				}
			}
		}
	}

	// Add custom whitelist patterns if provided
	if whitelistPatterns, ok := config["whitelist_patterns"].([]any); ok {
		for _, pattern := range whitelistPatterns {
			if patternStr, ok := pattern.(string); ok {
				var regex *regexp.Regexp
				var err error
				if d.config.CaseSensitive {
					regex, err = regexp.Compile(patternStr)
				} else {
					regex, err = regexp.Compile("(?i)" + patternStr)
				}
				if err == nil {
					d.whitelistPatterns = append(d.whitelistPatterns, regex)
				}
			}
		}
	}

	return nil
}

// Detect performs suspicious user agent detection
func (d *SuspiciousUserAgentDetector) Detect(ctx context.Context, reqCtx *plugins.RequestContext) plugins.DetectionResult {
	d.metrics.totalChecks++

	userAgent := reqCtx.UserAgent

	// Check for empty user agent
	if d.config.CheckEmpty && (userAgent == "" || strings.TrimSpace(userAgent) == "") {
		d.metrics.emptyUserAgent++
		d.metrics.threatsFound++

		return plugins.DetectionResult{
			Threat:     true,
			Confidence: 0.7,
			Details:    "Empty or missing User-Agent header",
			Severity:   d.config.Severity,
			Tags:       []string{"suspicious_user_agent", "empty_user_agent", "bot"},
			Metadata: map[string]any{
				"user_agent": userAgent,
				"reason":     "empty_user_agent",
			},
		}
	}

	// Check whitelist first (legitimate bots)
	for _, pattern := range d.whitelistPatterns {
		if pattern.MatchString(userAgent) {
			d.metrics.whitelisted++
			return plugins.DetectionResult{
				Threat:     false,
				Confidence: 0,
				Details:    fmt.Sprintf("User agent whitelisted: %s", userAgent),
				Severity:   0,
				Tags:       []string{},
				Metadata: map[string]any{
					"user_agent":  userAgent,
					"whitelisted": true,
					"pattern":     pattern.String(),
				},
			}
		}
	}

	// Check suspicious patterns
	for i, pattern := range d.suspiciousPatterns {
		if pattern.MatchString(userAgent) {
			d.metrics.threatsFound++

			confidence := 0.5 + float64(i)*0.01
			if confidence > 1.0 {
				confidence = 1.0
			}

			severity := d.config.Severity

			// Increase severity for certain patterns
			lowerUA := strings.ToLower(userAgent)
			if strings.Contains(lowerUA, "scan") || strings.Contains(lowerUA, "exploit") {
				severity += 2
			}
			if strings.Contains(lowerUA, "sqlmap") || strings.Contains(lowerUA, "nikto") {
				severity += 3
				confidence = 0.9
			}

			// Cap severity at 10
			if severity > 10 {
				severity = 10
			}

			return plugins.DetectionResult{
				Threat:     true,
				Confidence: confidence,
				Details:    fmt.Sprintf("Suspicious user agent detected: %s", userAgent),
				Severity:   severity,
				Tags:       []string{"suspicious_user_agent", "bot", "automated_tool"},
				Metadata: map[string]any{
					"user_agent":    userAgent,
					"pattern_index": i,
					"pattern":       pattern.String(),
					"reason":        "suspicious_pattern",
				},
			}
		}
	}

	return plugins.DetectionResult{
		Threat:     false,
		Confidence: 0,
		Details:    "User agent appears legitimate",
		Severity:   0,
		Tags:       []string{},
		Metadata: map[string]any{
			"user_agent": userAgent,
		},
	}
}

// Cleanup cleans up plugin resources
func (d *SuspiciousUserAgentDetector) Cleanup() error {
	return nil
}

// Health checks plugin health
func (d *SuspiciousUserAgentDetector) Health() error {
	if len(d.suspiciousPatterns) == 0 {
		return fmt.Errorf("no suspicious patterns loaded")
	}
	return nil
}

// GetMetrics returns plugin metrics
func (d *SuspiciousUserAgentDetector) GetMetrics() map[string]any {
	detectionRate := float64(0)
	if d.metrics.totalChecks > 0 {
		detectionRate = float64(d.metrics.threatsFound) / float64(d.metrics.totalChecks)
	}

	return map[string]any{
		"total_checks":        d.metrics.totalChecks,
		"threats_found":       d.metrics.threatsFound,
		"whitelisted":         d.metrics.whitelisted,
		"empty_user_agent":    d.metrics.emptyUserAgent,
		"detection_rate":      detectionRate,
		"suspicious_patterns": len(d.suspiciousPatterns),
		"whitelist_patterns":  len(d.whitelistPatterns),
		"configured_severity": d.config.Severity,
	}
}
