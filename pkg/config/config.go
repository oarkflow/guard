package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/guard/pkg/store"
)

// SystemConfig represents the complete system configuration
type SystemConfig struct {
	Server        ServerConfig        `json:"server"`
	Engine        EngineConfig        `json:"engine"`
	Store         store.StoreConfig   `json:"store"`
	Events        EventsConfig        `json:"events"`
	Plugins       PluginsConfig       `json:"plugins"`
	Security      SecurityConfig      `json:"security"`
	TCPProtection TCPProtectionConfig `json:"tcp_protection"`
	Logging       LoggingConfig       `json:"logging"`
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Address        string        `json:"address"`
	Port           int           `json:"port"`
	ReadTimeout    time.Duration `json:"read_timeout"`
	WriteTimeout   time.Duration `json:"write_timeout"`
	IdleTimeout    time.Duration `json:"idle_timeout"`
	MaxConnections int           `json:"max_connections"`
	EnablePrefork  bool          `json:"enable_prefork"`
	BodyLimit      int           `json:"body_limit"`
	TrustedProxies []string      `json:"trusted_proxies"`
}

// EngineConfig holds rule engine configuration
type EngineConfig struct {
	MaxConcurrentRequests int           `json:"max_concurrent_requests"`
	RequestTimeout        time.Duration `json:"request_timeout"`
	EnableMetrics         bool          `json:"enable_metrics"`
	EnableEvents          bool          `json:"enable_events"`
	DefaultAction         string        `json:"default_action"`
	FailureMode           string        `json:"failure_mode"`
	ActionRules           []ActionRule  `json:"action_rules"`
}

// ActionRule defines when to trigger specific actions based on severity and confidence
type ActionRule struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	MinSeverity    int      `json:"min_severity"`
	MaxSeverity    int      `json:"max_severity,omitempty"` // Optional max, 0 means no max
	MinConfidence  float64  `json:"min_confidence"`
	MaxConfidence  float64  `json:"max_confidence,omitempty"` // Optional max, 0 means no max
	Actions        []string `json:"actions"`
	ThreatTags     []string `json:"threat_tags,omitempty"`  // Optional: only trigger for specific threat types
	ExcludeTags    []string `json:"exclude_tags,omitempty"` // Optional: exclude specific threat types
	Priority       int      `json:"priority"`               // Higher priority rules are evaluated first
	Enabled        bool     `json:"enabled"`
	RequireAllTags bool     `json:"require_all_tags,omitempty"` // If true, all threat_tags must match
}

// EventsConfig holds event system configuration
type EventsConfig struct {
	BufferSize    int  `json:"buffer_size"`
	WorkerCount   int  `json:"worker_count"`
	EnableAsync   bool `json:"enable_async"`
	RetryAttempts int  `json:"retry_attempts"`
}

// PluginsConfig holds plugin system configuration
type PluginsConfig struct {
	Detectors map[string]plugins.PluginConfig `json:"detectors"`
	Actions   map[string]plugins.PluginConfig `json:"actions"`
	Handlers  map[string]plugins.PluginConfig `json:"handlers"`
	LoadPath  string                          `json:"load_path"`
	AutoLoad  bool                            `json:"auto_load"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	EnableSecurityHeaders bool     `json:"enable_security_headers"`
	AllowedOrigins        []string `json:"allowed_origins"`
	AllowedMethods        []string `json:"allowed_methods"`
	AllowedHeaders        []string `json:"allowed_headers"`
	MaxRequestSize        int64    `json:"max_request_size"`
	EnableRateLimiting    bool     `json:"enable_rate_limiting"`
}

// TCPProtectionConfig holds TCP-level DDoS protection configuration
type TCPProtectionConfig struct {
	EnableTCPProtection  bool          `json:"enable_tcp_protection"`
	ConnectionRateLimit  int64         `json:"connection_rate_limit"`  // connections per minute per IP
	ConnectionWindow     time.Duration `json:"connection_window"`      // time window for rate limiting
	SilentDropThreshold  int64         `json:"silent_drop_threshold"`  // connections before silent drop
	TarpitThreshold      int64         `json:"tarpit_threshold"`       // connections before tarpit
	TarpitDelay          time.Duration `json:"tarpit_delay"`           // delay for tarpit connections
	MaxTarpitConnections int           `json:"max_tarpit_connections"` // max concurrent tarpit connections
	BruteForceThreshold  int64         `json:"brute_force_threshold"`  // failed connections before blocking
	BruteForceWindow     time.Duration `json:"brute_force_window"`     // time window for brute force detection
	CleanupInterval      time.Duration `json:"cleanup_interval"`       // cleanup interval for expired entries
	WhitelistedIPs       []string      `json:"whitelisted_ips"`        // IPs to never block
	BlacklistedIPs       []string      `json:"blacklisted_ips"`        // IPs to always block
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level      string `json:"level"`
	Format     string `json:"format"`
	Output     string `json:"output"`
	MaxSize    int    `json:"max_size"`
	MaxBackups int    `json:"max_backups"`
	MaxAge     int    `json:"max_age"`
	Compress   bool   `json:"compress"`
}

// LoadConfig loads configuration from a file
func LoadConfig(filename string) (*SystemConfig, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config SystemConfig
	if err := json.Unmarshal(bytes, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults
	setDefaults(&config)

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// SaveConfig saves configuration to a file
func SaveConfig(config *SystemConfig, filename string) error {
	bytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile(filename, bytes, 0644)
}

// setDefaults sets default values for configuration
func setDefaults(config *SystemConfig) {
	// Server defaults
	if config.Server.Address == "" {
		config.Server.Address = "0.0.0.0"
	}
	if config.Server.Port == 0 {
		config.Server.Port = 8080
	}
	if config.Server.ReadTimeout == 0 {
		config.Server.ReadTimeout = 10 * time.Second
	}
	if config.Server.WriteTimeout == 0 {
		config.Server.WriteTimeout = 10 * time.Second
	}
	if config.Server.IdleTimeout == 0 {
		config.Server.IdleTimeout = 60 * time.Second
	}
	if config.Server.MaxConnections == 0 {
		config.Server.MaxConnections = 10000
	}
	if config.Server.BodyLimit == 0 {
		config.Server.BodyLimit = 10 * 1024 * 1024 // 10MB
	}

	// Engine defaults
	if config.Engine.MaxConcurrentRequests == 0 {
		config.Engine.MaxConcurrentRequests = 1000
	}
	if config.Engine.RequestTimeout == 0 {
		config.Engine.RequestTimeout = 30 * time.Second
	}
	if config.Engine.DefaultAction == "" {
		config.Engine.DefaultAction = "allow"
	}
	if config.Engine.FailureMode == "" {
		config.Engine.FailureMode = "allow"
	}

	// Store defaults
	if config.Store.Type == "" {
		config.Store.Type = "memory"
	}
	if config.Store.Timeout == 0 {
		config.Store.Timeout = 5 * time.Second
	}
	if config.Store.MaxRetries == 0 {
		config.Store.MaxRetries = 3
	}

	// Events defaults
	if config.Events.BufferSize == 0 {
		config.Events.BufferSize = 1000
	}
	if config.Events.WorkerCount == 0 {
		config.Events.WorkerCount = 4
	}
	if config.Events.RetryAttempts == 0 {
		config.Events.RetryAttempts = 3
	}

	// Plugins defaults
	if config.Plugins.LoadPath == "" {
		config.Plugins.LoadPath = "./plugins"
	}

	// Security defaults
	if config.Security.MaxRequestSize == 0 {
		config.Security.MaxRequestSize = 10 * 1024 * 1024 // 10MB
	}
	if len(config.Security.AllowedMethods) == 0 {
		config.Security.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	}

	// Logging defaults
	if config.Logging.Level == "" {
		config.Logging.Level = "INFO"
	}
	if config.Logging.Format == "" {
		config.Logging.Format = "json"
	}
	if config.Logging.Output == "" {
		config.Logging.Output = "stdout"
	}
	if config.Logging.MaxSize == 0 {
		config.Logging.MaxSize = 100 // MB
	}
	if config.Logging.MaxBackups == 0 {
		config.Logging.MaxBackups = 3
	}
	if config.Logging.MaxAge == 0 {
		config.Logging.MaxAge = 28 // days
	}

	// TCP Protection defaults
	if config.TCPProtection.ConnectionRateLimit == 0 {
		config.TCPProtection.ConnectionRateLimit = 100
	}
	if config.TCPProtection.ConnectionWindow == 0 {
		config.TCPProtection.ConnectionWindow = 60 * time.Second
	}
	if config.TCPProtection.SilentDropThreshold == 0 {
		config.TCPProtection.SilentDropThreshold = 50
	}
	if config.TCPProtection.TarpitThreshold == 0 {
		config.TCPProtection.TarpitThreshold = 75
	}
	if config.TCPProtection.TarpitDelay == 0 {
		config.TCPProtection.TarpitDelay = 5 * time.Second
	}
	if config.TCPProtection.MaxTarpitConnections == 0 {
		config.TCPProtection.MaxTarpitConnections = 10
	}
	if config.TCPProtection.BruteForceThreshold == 0 {
		config.TCPProtection.BruteForceThreshold = 10
	}
	if config.TCPProtection.BruteForceWindow == 0 {
		config.TCPProtection.BruteForceWindow = 300 * time.Second
	}
	if config.TCPProtection.CleanupInterval == 0 {
		config.TCPProtection.CleanupInterval = 60 * time.Second
	}
	if len(config.TCPProtection.WhitelistedIPs) == 0 {
		config.TCPProtection.WhitelistedIPs = []string{"127.0.0.1", "::1"}
	}
}

// getDefaultActionRules returns the default action rules
func getDefaultActionRules() []ActionRule {
	return []ActionRule{
		{
			Name:          "Critical Account Suspension",
			Description:   "Suspend accounts for critical severity threats",
			MinSeverity:   9,
			MinConfidence: 0.9,
			Actions:       []string{"account_suspend_action"},
			Priority:      100,
			Enabled:       true,
		},
		{
			Name:          "High Severity Suspension",
			Description:   "Temporary suspension for high severity threats",
			MinSeverity:   8,
			MinConfidence: 0.8,
			Actions:       []string{"suspension_action"},
			Priority:      90,
			Enabled:       true,
		},
		{
			Name:          "Rate Limit Incremental Block",
			Description:   "Incremental blocking for rate limit violations",
			MinSeverity:   1,
			MinConfidence: 0.8,
			Actions:       []string{"incremental_block_action"},
			ThreatTags:    []string{"rate_limit", "ddos"},
			Priority:      85,
			Enabled:       true,
		},
		{
			Name:          "Medium Severity Block",
			Description:   "Block IPs for medium severity threats",
			MinSeverity:   5,
			MinConfidence: 0.6,
			Actions:       []string{"block_action"},
			Priority:      80,
			Enabled:       true,
		},
		{
			Name:          "Low Severity Warning",
			Description:   "Show warnings for low severity threats",
			MinSeverity:   3,
			MinConfidence: 0.3,
			Actions:       []string{"warning_action"},
			Priority:      70,
			Enabled:       true,
		},
		{
			Name:          "SQL Injection Block",
			Description:   "Block SQL injection attempts regardless of severity",
			MinSeverity:   1,
			MinConfidence: 0.7,
			Actions:       []string{"block_action"},
			ThreatTags:    []string{"sql_injection"},
			Priority:      95,
			Enabled:       true,
		},
		{
			Name:          "XSS Attack Block",
			Description:   "Block XSS attacks with medium confidence",
			MinSeverity:   1,
			MinConfidence: 0.6,
			Actions:       []string{"block_action"},
			ThreatTags:    []string{"xss"},
			Priority:      94,
			Enabled:       true,
		},
	}
}

// validateConfig validates the configuration
func validateConfig(config *SystemConfig) error {
	// Validate server config
	if config.Server.Port < 1 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	// Validate engine config
	if config.Engine.MaxConcurrentRequests < 1 {
		return fmt.Errorf("max_concurrent_requests must be > 0")
	}

	// Validate store config
	supportedStoreTypes := []string{"memory", "redis", "etcd"}
	validStoreType := false
	for _, t := range supportedStoreTypes {
		if config.Store.Type == t {
			validStoreType = true
			break
		}
	}
	if !validStoreType {
		return fmt.Errorf("unsupported store type: %s", config.Store.Type)
	}

	// Validate events config
	if config.Events.BufferSize < 1 {
		return fmt.Errorf("events buffer_size must be > 0")
	}
	if config.Events.WorkerCount < 1 {
		return fmt.Errorf("events worker_count must be > 0")
	}

	return nil
}

// CreateDefaultConfig creates a default configuration
func CreateDefaultConfig() *SystemConfig {
	config := &SystemConfig{
		Server: ServerConfig{
			Address:        "0.0.0.0",
			Port:           8080,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			IdleTimeout:    60 * time.Second,
			MaxConnections: 10000,
			BodyLimit:      10 * 1024 * 1024,
			TrustedProxies: []string{},
		},
		Engine: EngineConfig{
			MaxConcurrentRequests: 1000,
			RequestTimeout:        30 * time.Second,
			EnableMetrics:         true,
			EnableEvents:          true,
			DefaultAction:         "allow",
			FailureMode:           "allow",
			ActionRules:           getDefaultActionRules(),
		},
		Store: store.StoreConfig{
			Type:       "memory",
			Timeout:    5 * time.Second,
			MaxRetries: 3,
		},
		Events: EventsConfig{
			BufferSize:    1000,
			WorkerCount:   4,
			EnableAsync:   true,
			RetryAttempts: 3,
		},
		Plugins: PluginsConfig{
			Detectors: map[string]plugins.PluginConfig{
				"sql_injection_detector": {
					Enabled:  true,
					Priority: 100,
					Parameters: map[string]any{
						"custom_patterns": []string{},
					},
				},
				"rate_limit_detector": {
					Enabled:  true,
					Priority: 90,
					Parameters: map[string]any{
						"window_size":   "1m",
						"max_requests":  100,
						"key_template":  "rate_limit:{ip}",
						"burst_allowed": 10,
					},
				},
			},
			Actions: map[string]plugins.PluginConfig{
				"block_action": {
					Enabled:  true,
					Priority: 100,
					Parameters: map[string]any{
						"default_duration": "5m",
						"max_duration":     "24h",
						"block_message":    "Access denied due to security policy violation",
						"log_blocks":       true,
					},
				},
			},
			Handlers: map[string]plugins.PluginConfig{
				"security_logger_handler": {
					Enabled:  true,
					Priority: 100,
					Parameters: map[string]any{
						"log_file":    "security_events.log",
						"log_level":   "INFO",
						"event_types": []string{"*"},
						"format":      "json",
					},
				},
			},
			LoadPath: "./plugins",
			AutoLoad: true,
		},
		Security: SecurityConfig{
			EnableSecurityHeaders: true,
			AllowedOrigins:        []string{"*"},
			AllowedMethods:        []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:        []string{"*"},
			MaxRequestSize:        10 * 1024 * 1024,
			EnableRateLimiting:    true,
		},
		TCPProtection: TCPProtectionConfig{
			EnableTCPProtection:  true,
			ConnectionRateLimit:  100,
			ConnectionWindow:     60 * time.Second,
			SilentDropThreshold:  50,
			TarpitThreshold:      75,
			TarpitDelay:          5 * time.Second,
			MaxTarpitConnections: 10,
			BruteForceThreshold:  10,
			BruteForceWindow:     300 * time.Second,
			CleanupInterval:      60 * time.Second,
			WhitelistedIPs:       []string{"127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			BlacklistedIPs:       []string{},
		},
		Logging: LoggingConfig{
			Level:      "INFO",
			Format:     "json",
			Output:     "stdout",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     28,
			Compress:   true,
		},
	}

	return config
}
