package detectors

import (
	"context"
	"fmt"
	"strings"

	"github.com/oarkflow/guard/pkg/plugins"
)

// GeoLocationDetector implements DetectorPlugin for geo-location based detection
type GeoLocationDetector struct {
	name        string
	version     string
	description string
	config      GeoLocationConfig
	metrics     struct {
		totalChecks      int64
		threatsFound     int64
		blockedCountries int64
		allowedCountries int64
	}
}

// GeoLocationConfig holds configuration for geo-location detection
type GeoLocationConfig struct {
	BlockedCountries     []string `json:"blocked_countries"`
	AllowedCountries     []string `json:"allowed_countries"`
	UseCloudflareHeaders bool     `json:"use_cloudflare_headers"`
	UseCustomHeaders     bool     `json:"use_custom_headers"`
	CustomCountryHeader  string   `json:"custom_country_header"`
	Severity             int      `json:"severity"`
	DefaultAction        string   `json:"default_action"` // "allow" or "block"
}

// NewGeoLocationDetector creates a new geo-location detector plugin
func NewGeoLocationDetector() *GeoLocationDetector {
	return &GeoLocationDetector{
		name:        "geo_location_detector",
		version:     "1.0.0",
		description: "Detects requests from blocked or suspicious geographical locations",
		config: GeoLocationConfig{
			BlockedCountries:     []string{"CN", "RU", "KP"}, // China, Russia, North Korea
			AllowedCountries:     []string{},                 // Empty means allow all except blocked
			UseCloudflareHeaders: true,
			UseCustomHeaders:     false,
			CustomCountryHeader:  "X-Country-Code",
			Severity:             4,
			DefaultAction:        "allow", // Default to allow if country cannot be determined
		},
	}
}

// Name returns the plugin name
func (d *GeoLocationDetector) Name() string {
	return d.name
}

// Version returns the plugin version
func (d *GeoLocationDetector) Version() string {
	return d.version
}

// Description returns the plugin description
func (d *GeoLocationDetector) Description() string {
	return d.description
}

// Initialize initializes the plugin with configuration
func (d *GeoLocationDetector) Initialize(config map[string]any) error {
	// Parse blocked countries
	if blockedCountries, ok := config["blocked_countries"].([]any); ok {
		d.config.BlockedCountries = make([]string, len(blockedCountries))
		for i, country := range blockedCountries {
			if countryStr, ok := country.(string); ok {
				d.config.BlockedCountries[i] = strings.ToUpper(countryStr)
			}
		}
	}

	// Parse allowed countries
	if allowedCountries, ok := config["allowed_countries"].([]any); ok {
		d.config.AllowedCountries = make([]string, len(allowedCountries))
		for i, country := range allowedCountries {
			if countryStr, ok := country.(string); ok {
				d.config.AllowedCountries[i] = strings.ToUpper(countryStr)
			}
		}
	}

	// Parse use cloudflare headers
	if useCloudflare, ok := config["use_cloudflare_headers"].(bool); ok {
		d.config.UseCloudflareHeaders = useCloudflare
	}

	// Parse use custom headers
	if useCustom, ok := config["use_custom_headers"].(bool); ok {
		d.config.UseCustomHeaders = useCustom
	}

	// Parse custom country header
	if customHeader, ok := config["custom_country_header"].(string); ok {
		d.config.CustomCountryHeader = customHeader
	}

	// Parse severity
	if severity, ok := config["severity"].(float64); ok {
		d.config.Severity = int(severity)
	}

	// Parse default action
	if defaultAction, ok := config["default_action"].(string); ok {
		d.config.DefaultAction = defaultAction
	}

	return nil
}

// Detect performs geo-location detection
func (d *GeoLocationDetector) Detect(ctx context.Context, reqCtx *plugins.RequestContext) plugins.DetectionResult {
	d.metrics.totalChecks++

	// Extract country code from various sources
	countryCode := d.extractCountryCode(reqCtx)

	// If no country code found, use default action
	if countryCode == "" {
		if d.config.DefaultAction == "block" {
			d.metrics.threatsFound++
			return plugins.DetectionResult{
				Threat:     true,
				Confidence: 0.3,
				Details:    "Country code not available, default action is block",
				Severity:   d.config.Severity,
				Tags:       []string{"geo_location", "unknown_country", "default_block"},
				Metadata: map[string]any{
					"country_code":   "",
					"reason":         "unknown_country",
					"default_action": d.config.DefaultAction,
				},
			}
		}

		return plugins.DetectionResult{
			Threat:     false,
			Confidence: 0,
			Details:    "Country code not available, default action is allow",
			Severity:   0,
			Tags:       []string{},
			Metadata: map[string]any{
				"country_code":   "",
				"default_action": d.config.DefaultAction,
			},
		}
	}

	countryCode = strings.ToUpper(countryCode)

	// Check if country is in allowed list (if specified)
	if len(d.config.AllowedCountries) > 0 {
		allowed := false
		for _, allowedCountry := range d.config.AllowedCountries {
			if countryCode == allowedCountry {
				allowed = true
				break
			}
		}

		if !allowed {
			d.metrics.threatsFound++
			return plugins.DetectionResult{
				Threat:     true,
				Confidence: 0.8,
				Details:    fmt.Sprintf("Request from country %s not in allowed list", countryCode),
				Severity:   d.config.Severity,
				Tags:       []string{"geo_location", "blocked_country", "not_allowed"},
				Metadata: map[string]any{
					"country_code":      countryCode,
					"reason":            "not_in_allowed_list",
					"allowed_countries": d.config.AllowedCountries,
				},
			}
		}

		d.metrics.allowedCountries++
		return plugins.DetectionResult{
			Threat:     false,
			Confidence: 0,
			Details:    fmt.Sprintf("Request from allowed country: %s", countryCode),
			Severity:   0,
			Tags:       []string{},
			Metadata: map[string]any{
				"country_code": countryCode,
				"allowed":      true,
			},
		}
	}

	// Check if country is in blocked list
	for _, blockedCountry := range d.config.BlockedCountries {
		if countryCode == blockedCountry {
			d.metrics.threatsFound++
			d.metrics.blockedCountries++

			// Higher confidence and severity for certain high-risk countries
			confidence := 0.7
			severity := d.config.Severity

			if countryCode == "CN" || countryCode == "RU" || countryCode == "KP" {
				confidence = 0.8
				severity += 1
			}

			return plugins.DetectionResult{
				Threat:     true,
				Confidence: confidence,
				Details:    fmt.Sprintf("Request from blocked country: %s", countryCode),
				Severity:   severity,
				Tags:       []string{"geo_location", "blocked_country", "high_risk"},
				Metadata: map[string]any{
					"country_code":      countryCode,
					"reason":            "blocked_country",
					"blocked_countries": d.config.BlockedCountries,
				},
			}
		}
	}

	// Country is not blocked
	return plugins.DetectionResult{
		Threat:     false,
		Confidence: 0,
		Details:    fmt.Sprintf("Request from allowed country: %s", countryCode),
		Severity:   0,
		Tags:       []string{},
		Metadata: map[string]any{
			"country_code": countryCode,
			"blocked":      false,
		},
	}
}

// extractCountryCode extracts country code from request headers
func (d *GeoLocationDetector) extractCountryCode(reqCtx *plugins.RequestContext) string {
	// Try Cloudflare headers first
	if d.config.UseCloudflareHeaders {
		if country, exists := reqCtx.Headers["CF-IPCountry"]; exists && country != "" {
			return country
		}
		if country, exists := reqCtx.Headers["Cf-Ipcountry"]; exists && country != "" {
			return country
		}
	}

	// Try custom header
	if d.config.UseCustomHeaders && d.config.CustomCountryHeader != "" {
		if country, exists := reqCtx.Headers[d.config.CustomCountryHeader]; exists && country != "" {
			return country
		}
	}

	// Try other common geo-location headers
	geoHeaders := []string{
		"X-Country-Code",
		"X-GeoIP-Country",
		"X-Country",
		"X-Forwarded-Country",
		"X-Real-Country",
		"Country",
		"GeoIP-Country",
	}

	for _, header := range geoHeaders {
		if country, exists := reqCtx.Headers[header]; exists && country != "" {
			return country
		}
	}

	// Try to get from request context if available
	if reqCtx.Country != "" {
		return reqCtx.Country
	}

	return ""
}

// IsCountryBlocked checks if a country code is blocked
func (d *GeoLocationDetector) IsCountryBlocked(countryCode string) bool {
	countryCode = strings.ToUpper(countryCode)

	// If allowed countries are specified, check if country is in the list
	if len(d.config.AllowedCountries) > 0 {
		for _, allowedCountry := range d.config.AllowedCountries {
			if countryCode == allowedCountry {
				return false
			}
		}
		return true // Not in allowed list, so blocked
	}

	// Check blocked countries list
	for _, blockedCountry := range d.config.BlockedCountries {
		if countryCode == blockedCountry {
			return true
		}
	}

	return false
}

// GetBlockedCountries returns the list of blocked countries
func (d *GeoLocationDetector) GetBlockedCountries() []string {
	return d.config.BlockedCountries
}

// GetAllowedCountries returns the list of allowed countries
func (d *GeoLocationDetector) GetAllowedCountries() []string {
	return d.config.AllowedCountries
}

// Cleanup cleans up plugin resources
func (d *GeoLocationDetector) Cleanup() error {
	return nil
}

// Health checks plugin health
func (d *GeoLocationDetector) Health() error {
	if len(d.config.BlockedCountries) == 0 && len(d.config.AllowedCountries) == 0 {
		return fmt.Errorf("no blocked or allowed countries configured")
	}
	return nil
}

// GetMetrics returns plugin metrics
func (d *GeoLocationDetector) GetMetrics() map[string]any {
	detectionRate := float64(0)
	if d.metrics.totalChecks > 0 {
		detectionRate = float64(d.metrics.threatsFound) / float64(d.metrics.totalChecks)
	}

	return map[string]any{
		"total_checks":       d.metrics.totalChecks,
		"threats_found":      d.metrics.threatsFound,
		"blocked_countries":  d.metrics.blockedCountries,
		"allowed_countries":  d.metrics.allowedCountries,
		"detection_rate":     detectionRate,
		"configured_blocked": len(d.config.BlockedCountries),
		"configured_allowed": len(d.config.AllowedCountries),
		"severity":           d.config.Severity,
		"default_action":     d.config.DefaultAction,
	}
}
