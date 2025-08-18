package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/log"
)

// ModularConfig represents the new modular configuration structure
type ModularConfig struct {
	Server    *ServerConfig                  `json:"server,omitempty"`
	Global    *GlobalConfig                  `json:"global,omitempty"`
	Detectors map[string]*DetectorRuleConfig `json:"detectors,omitempty"`
	Actions   map[string]*ActionRuleConfig   `json:"actions,omitempty"`
	Handlers  map[string]*HandlerRuleConfig  `json:"handlers,omitempty"`
	TCPRules  *TCPRuleConfig                 `json:"tcp_rules,omitempty"`
	Security  *SecurityRuleConfig            `json:"security,omitempty"`
}

// GlobalConfig holds global system settings
type GlobalConfig struct {
	Engine  EngineConfig      `json:"engine"`
	Store   GlobalStoreConfig `json:"store"`
	Events  EventsConfig      `json:"events"`
	Logging LoggingConfig     `json:"logging"`
}

// GlobalStoreConfig represents store configuration for global config
type GlobalStoreConfig struct {
	Type       string                 `json:"type"`
	Address    string                 `json:"address"`
	Password   string                 `json:"password"`
	Database   int                    `json:"database"`
	Prefix     string                 `json:"prefix"`
	MaxRetries int                    `json:"max_retries"`
	Timeout    string                 `json:"timeout"` // Duration string like "5s"
	Options    map[string]interface{} `json:"options"`
}

// DetectorRuleConfig represents a detector with its associated rules
type DetectorRuleConfig struct {
	Detector    DetectorConfig `json:"detector"`
	ActionRules []ActionRule   `json:"action_rules,omitempty"`
}

// ActionRuleConfig represents an action with its configuration
type ActionRuleConfig struct {
	Action ActionConfig `json:"action"`
}

// HandlerRuleConfig represents a handler with its configuration
type HandlerRuleConfig struct {
	Handler HandlerConfig `json:"handler"`
}

// DetectorConfig represents detector configuration with name
type DetectorConfig struct {
	Name       string         `json:"name"`
	Enabled    bool           `json:"enabled"`
	Priority   int            `json:"priority"`
	Parameters map[string]any `json:"parameters"`
}

// ActionConfig represents action configuration with name
type ActionConfig struct {
	Name       string         `json:"name"`
	Enabled    bool           `json:"enabled"`
	Priority   int            `json:"priority"`
	Parameters map[string]any `json:"parameters"`
}

// HandlerConfig represents handler configuration with name
type HandlerConfig struct {
	Name       string         `json:"name"`
	Enabled    bool           `json:"enabled"`
	Priority   int            `json:"priority"`
	Parameters map[string]any `json:"parameters"`
}

// TCPRuleConfig represents TCP protection rules
type TCPRuleConfig struct {
	TCPProtection TCPProtectionConfig `json:"tcp_protection"`
	Rules         []TCPRule           `json:"rules,omitempty"`
}

// TCPRule represents individual TCP protection rules
type TCPRule struct {
	Name      string                 `json:"name"`
	Condition map[string]interface{} `json:"condition"`
	Action    string                 `json:"action"`
	Priority  int                    `json:"priority"`
}

// SecurityRuleConfig represents security configuration
type SecurityRuleConfig struct {
	Security SecurityConfig `json:"security"`
}

// ConfigLoader interface for loading different config sources
type ConfigLoader interface {
	LoadConfig(source string) (*SystemConfig, error)
	SupportsSource(source string) bool
	GetSourceType() string
}

// ConfigSourceDetector determines the best configuration source
type ConfigSourceDetector struct {
	basePath string
}

// NewConfigSourceDetector creates a new config source detector
func NewConfigSourceDetector(basePath string) *ConfigSourceDetector {
	return &ConfigSourceDetector{basePath: basePath}
}

// DetectConfigSource determines the best configuration source
func (d *ConfigSourceDetector) DetectConfigSource() (ConfigLoader, error) {
	// Priority 1: Check for config directory structure
	configDir := filepath.Join(d.basePath, "config")
	if d.isValidConfigDirectory(configDir) {
		log.Info().Str("config_dir", configDir).Msg("Using modular configuration directory")
		return NewMultiFileLoader(configDir), nil
	}

	// Priority 2: Check for single config file (backward compatibility)
	singleConfigPaths := []string{
		filepath.Join(d.basePath, "system_config.json"),
		filepath.Join(d.basePath, "config.json"),
		filepath.Join(d.basePath, "testdata", "system_config.json"),
	}

	for _, path := range singleConfigPaths {
		if d.fileExists(path) {
			log.Info().Str("config_file", path).Msg("Using single file configuration (backward compatibility)")
			return NewSingleFileLoader(path), nil
		}
	}

	// Priority 3: Create default configuration
	log.Info().Msg("No configuration found, using default configuration")
	return NewDefaultConfigLoader(d.basePath), nil
}

// isValidConfigDirectory checks if directory contains valid config structure
func (d *ConfigSourceDetector) isValidConfigDirectory(dir string) bool {
	if !d.dirExists(dir) {
		return false
	}

	// Must have at least server.json or global.json
	serverConfig := filepath.Join(dir, "server.json")
	globalConfig := filepath.Join(dir, "global.json")

	return d.fileExists(serverConfig) || d.fileExists(globalConfig)
}

// fileExists checks if a file exists
func (d *ConfigSourceDetector) fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// dirExists checks if a directory exists
func (d *ConfigSourceDetector) dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// MultiFileLoader loads configuration from multiple files
type MultiFileLoader struct {
	configDir     string
	loadedConfigs map[string]interface{}
	mu            sync.RWMutex
}

// NewMultiFileLoader creates a new multi-file loader
func NewMultiFileLoader(configDir string) *MultiFileLoader {
	return &MultiFileLoader{
		configDir:     configDir,
		loadedConfigs: make(map[string]interface{}),
	}
}

// LoadConfig loads configuration from multiple files
func (m *MultiFileLoader) LoadConfig(source string) (*SystemConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	config := &SystemConfig{}

	// Load core configurations
	if err := m.loadServerConfig(config); err != nil {
		return nil, fmt.Errorf("failed to load server config: %w", err)
	}

	if err := m.loadGlobalConfig(config); err != nil {
		return nil, fmt.Errorf("failed to load global config: %w", err)
	}

	// Initialize plugins config if not set
	if config.Plugins.Detectors == nil {
		config.Plugins.Detectors = make(map[string]plugins.PluginConfig)
	}
	if config.Plugins.Actions == nil {
		config.Plugins.Actions = make(map[string]plugins.PluginConfig)
	}
	if config.Plugins.Handlers == nil {
		config.Plugins.Handlers = make(map[string]plugins.PluginConfig)
	}

	// Load rule configurations
	if err := m.loadDetectorRules(config); err != nil {
		return nil, fmt.Errorf("failed to load detector rules: %w", err)
	}

	if err := m.loadActionRules(config); err != nil {
		return nil, fmt.Errorf("failed to load action rules: %w", err)
	}

	if err := m.loadHandlerRules(config); err != nil {
		return nil, fmt.Errorf("failed to load handler rules: %w", err)
	}

	if err := m.loadTCPRules(config); err != nil {
		return nil, fmt.Errorf("failed to load TCP rules: %w", err)
	}

	if err := m.loadSecurityRules(config); err != nil {
		return nil, fmt.Errorf("failed to load security rules: %w", err)
	}

	// Apply defaults and validate
	setDefaults(config)
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid merged configuration: %w", err)
	}

	return config, nil
}

// loadServerConfig loads server configuration
func (m *MultiFileLoader) loadServerConfig(config *SystemConfig) error {
	serverPath := filepath.Join(m.configDir, "server.json")
	if !m.fileExists(serverPath) {
		log.Debug().Str("file", serverPath).Msg("Server config file not found, using defaults")
		return nil
	}

	// Load as raw JSON first to handle duration strings
	var rawConfig map[string]interface{}
	if err := m.loadJSONFile(serverPath, &rawConfig); err != nil {
		return fmt.Errorf("failed to load server config: %w", err)
	}

	// Convert to ServerConfig with duration parsing
	serverConfig, err := m.parseServerConfig(rawConfig)
	if err != nil {
		return fmt.Errorf("failed to parse server config: %w", err)
	}

	config.Server = *serverConfig
	return nil
}

// parseServerConfig converts raw config to ServerConfig with duration parsing
func (m *MultiFileLoader) parseServerConfig(raw map[string]interface{}) (*ServerConfig, error) {
	config := &ServerConfig{}

	if v, ok := raw["address"].(string); ok {
		config.Address = v
	}
	if v, ok := raw["port"].(float64); ok {
		config.Port = int(v)
	}
	if v, ok := raw["tls_port"].(float64); ok {
		config.TLSPort = int(v)
	}
	if v, ok := raw["tls_cert_file"].(string); ok {
		config.TLSCertFile = v
	}
	if v, ok := raw["tls_key_file"].(string); ok {
		config.TLSKeyFile = v
	}
	if v, ok := raw["max_connections"].(float64); ok {
		config.MaxConnections = int(v)
	}
	if v, ok := raw["enable_prefork"].(bool); ok {
		config.EnablePrefork = v
	}
	if v, ok := raw["body_limit"].(float64); ok {
		config.BodyLimit = int(v)
	}

	// Parse duration fields
	if v, ok := raw["read_timeout"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			config.ReadTimeout = d
		}
	}
	if v, ok := raw["write_timeout"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			config.WriteTimeout = d
		}
	}
	if v, ok := raw["idle_timeout"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			config.IdleTimeout = d
		}
	}

	// Parse trusted proxies
	if v, ok := raw["trusted_proxies"].([]interface{}); ok {
		for _, proxy := range v {
			if s, ok := proxy.(string); ok {
				config.TrustedProxies = append(config.TrustedProxies, s)
			}
		}
	}

	return config, nil
}

// loadGlobalConfig loads global configuration
func (m *MultiFileLoader) loadGlobalConfig(config *SystemConfig) error {
	globalPath := filepath.Join(m.configDir, "global.json")
	if !m.fileExists(globalPath) {
		log.Debug().Str("file", globalPath).Msg("Global config file not found, using defaults")
		return nil
	}

	// Load as raw JSON first to handle duration strings
	var rawConfig map[string]interface{}
	if err := m.loadJSONFile(globalPath, &rawConfig); err != nil {
		return fmt.Errorf("failed to load global config: %w", err)
	}

	// Convert to GlobalConfig with duration parsing
	globalConfig, err := m.parseGlobalConfig(rawConfig)
	if err != nil {
		return fmt.Errorf("failed to parse global config: %w", err)
	}

	config.Engine = globalConfig.Engine
	config.Events = globalConfig.Events
	config.Logging = globalConfig.Logging

	// Convert GlobalStoreConfig to store.StoreConfig
	config.Store.Type = globalConfig.Store.Type
	config.Store.Address = globalConfig.Store.Address
	config.Store.Password = globalConfig.Store.Password
	config.Store.Database = globalConfig.Store.Database
	config.Store.Prefix = globalConfig.Store.Prefix
	config.Store.MaxRetries = globalConfig.Store.MaxRetries

	// Parse timeout duration string
	if globalConfig.Store.Timeout != "" {
		if timeout, err := time.ParseDuration(globalConfig.Store.Timeout); err == nil {
			config.Store.Timeout = timeout
		}
	}
	config.Store.Options = globalConfig.Store.Options

	return nil
}

// parseGlobalConfig converts raw config to GlobalConfig with duration parsing
func (m *MultiFileLoader) parseGlobalConfig(raw map[string]interface{}) (*GlobalConfig, error) {
	config := &GlobalConfig{}

	// Parse engine config
	if engineRaw, ok := raw["engine"].(map[string]interface{}); ok {
		engine := &config.Engine
		if v, ok := engineRaw["max_concurrent_requests"].(float64); ok {
			engine.MaxConcurrentRequests = int(v)
		}
		if v, ok := engineRaw["request_timeout"].(string); ok {
			if d, err := time.ParseDuration(v); err == nil {
				engine.RequestTimeout = d
			}
		}
		if v, ok := engineRaw["enable_metrics"].(bool); ok {
			engine.EnableMetrics = v
		}
		if v, ok := engineRaw["enable_events"].(bool); ok {
			engine.EnableEvents = v
		}
		if v, ok := engineRaw["default_action"].(string); ok {
			engine.DefaultAction = v
		}
		if v, ok := engineRaw["failure_mode"].(string); ok {
			engine.FailureMode = v
		}
		// action_rules will be populated from detector files
		engine.ActionRules = []ActionRule{}
	}

	// Parse store config
	if storeRaw, ok := raw["store"].(map[string]interface{}); ok {
		store := &config.Store
		if v, ok := storeRaw["type"].(string); ok {
			store.Type = v
		}
		if v, ok := storeRaw["address"].(string); ok {
			store.Address = v
		}
		if v, ok := storeRaw["password"].(string); ok {
			store.Password = v
		}
		if v, ok := storeRaw["database"].(float64); ok {
			store.Database = int(v)
		}
		if v, ok := storeRaw["prefix"].(string); ok {
			store.Prefix = v
		}
		if v, ok := storeRaw["max_retries"].(float64); ok {
			store.MaxRetries = int(v)
		}
		if v, ok := storeRaw["timeout"].(string); ok {
			store.Timeout = v
		}
		if v, ok := storeRaw["options"]; ok {
			if opts, ok := v.(map[string]interface{}); ok {
				store.Options = opts
			}
		}
	}

	// Parse events config
	if eventsRaw, ok := raw["events"].(map[string]interface{}); ok {
		events := &config.Events
		if v, ok := eventsRaw["buffer_size"].(float64); ok {
			events.BufferSize = int(v)
		}
		if v, ok := eventsRaw["worker_count"].(float64); ok {
			events.WorkerCount = int(v)
		}
		if v, ok := eventsRaw["enable_async"].(bool); ok {
			events.EnableAsync = v
		}
		if v, ok := eventsRaw["retry_attempts"].(float64); ok {
			events.RetryAttempts = int(v)
		}
	}

	// Parse logging config
	if loggingRaw, ok := raw["logging"].(map[string]interface{}); ok {
		logging := &config.Logging
		if v, ok := loggingRaw["level"].(string); ok {
			logging.Level = v
		}
		if v, ok := loggingRaw["format"].(string); ok {
			logging.Format = v
		}
		if v, ok := loggingRaw["output"].(string); ok {
			logging.Output = v
		}
		if v, ok := loggingRaw["max_size"].(float64); ok {
			logging.MaxSize = int(v)
		}
		if v, ok := loggingRaw["max_backups"].(float64); ok {
			logging.MaxBackups = int(v)
		}
		if v, ok := loggingRaw["max_age"].(float64); ok {
			logging.MaxAge = int(v)
		}
		if v, ok := loggingRaw["compress"].(bool); ok {
			logging.Compress = v
		}
	}

	return config, nil
}

// loadDetectorRules loads detector rules from detectors directory
func (m *MultiFileLoader) loadDetectorRules(config *SystemConfig) error {
	detectorsDir := filepath.Join(m.configDir, "detectors")
	if !m.dirExists(detectorsDir) {
		log.Debug().Str("dir", detectorsDir).Msg("Detectors directory not found")
		return nil
	}

	files, err := filepath.Glob(filepath.Join(detectorsDir, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to glob detector files: %w", err)
	}

	for _, file := range files {
		var detectorRule DetectorRuleConfig
		if err := m.loadJSONFile(file, &detectorRule); err != nil {
			log.Warn().Str("file", file).Err(err).Msg("Failed to load detector rule file")
			continue
		}

		// Add detector to plugins config
		detectorName := detectorRule.Detector.Name
		if detectorName == "" {
			detectorName = m.getNameFromFile(file)
		}

		// Convert DetectorConfig to plugins.PluginConfig
		pluginConfig := plugins.PluginConfig{
			Enabled:    detectorRule.Detector.Enabled,
			Priority:   detectorRule.Detector.Priority,
			Parameters: detectorRule.Detector.Parameters,
		}
		config.Plugins.Detectors[detectorName] = pluginConfig

		// Add action rules to engine config
		config.Engine.ActionRules = append(config.Engine.ActionRules, detectorRule.ActionRules...)

		log.Debug().Str("detector", detectorName).Str("file", file).Msg("Loaded detector rules")
	}

	return nil
}

// loadActionRules loads action rules from actions directory
func (m *MultiFileLoader) loadActionRules(config *SystemConfig) error {
	actionsDir := filepath.Join(m.configDir, "actions")
	if !m.dirExists(actionsDir) {
		log.Debug().Str("dir", actionsDir).Msg("Actions directory not found")
		return nil
	}

	files, err := filepath.Glob(filepath.Join(actionsDir, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to glob action files: %w", err)
	}

	for _, file := range files {
		var actionRule ActionRuleConfig
		if err := m.loadJSONFile(file, &actionRule); err != nil {
			log.Warn().Str("file", file).Err(err).Msg("Failed to load action rule file")
			continue
		}

		// Add action to plugins config
		actionName := actionRule.Action.Name
		if actionName == "" {
			actionName = m.getNameFromFile(file)
		}

		// Convert ActionConfig to plugins.PluginConfig
		pluginConfig := plugins.PluginConfig{
			Enabled:    actionRule.Action.Enabled,
			Priority:   actionRule.Action.Priority,
			Parameters: actionRule.Action.Parameters,
		}
		config.Plugins.Actions[actionName] = pluginConfig

		log.Debug().Str("action", actionName).Str("file", file).Msg("Loaded action rules")
	}

	return nil
}

// loadHandlerRules loads handler rules from handlers directory
func (m *MultiFileLoader) loadHandlerRules(config *SystemConfig) error {
	handlersDir := filepath.Join(m.configDir, "handlers")
	if !m.dirExists(handlersDir) {
		log.Debug().Str("dir", handlersDir).Msg("Handlers directory not found")
		return nil
	}

	files, err := filepath.Glob(filepath.Join(handlersDir, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to glob handler files: %w", err)
	}

	for _, file := range files {
		var handlerRule HandlerRuleConfig
		if err := m.loadJSONFile(file, &handlerRule); err != nil {
			log.Warn().Str("file", file).Err(err).Msg("Failed to load handler rule file")
			continue
		}

		// Add handler to plugins config
		handlerName := handlerRule.Handler.Name
		if handlerName == "" {
			handlerName = m.getNameFromFile(file)
		}

		// Convert HandlerConfig to plugins.PluginConfig
		pluginConfig := plugins.PluginConfig{
			Enabled:    handlerRule.Handler.Enabled,
			Priority:   handlerRule.Handler.Priority,
			Parameters: handlerRule.Handler.Parameters,
		}
		config.Plugins.Handlers[handlerName] = pluginConfig

		log.Debug().Str("handler", handlerName).Str("file", file).Msg("Loaded handler rules")
	}

	return nil
}

// loadTCPRules loads TCP protection rules
func (m *MultiFileLoader) loadTCPRules(config *SystemConfig) error {
	tcpDir := filepath.Join(m.configDir, "tcp-protection")
	if !m.dirExists(tcpDir) {
		log.Debug().Str("dir", tcpDir).Msg("TCP protection directory not found")
		return nil
	}

	tcpConfigPath := filepath.Join(tcpDir, "tcp-config.json")
	if m.fileExists(tcpConfigPath) {
		// Load as raw JSON first to handle duration strings
		var rawConfig map[string]interface{}
		if err := m.loadJSONFile(tcpConfigPath, &rawConfig); err != nil {
			return fmt.Errorf("failed to load TCP config: %w", err)
		}

		// Convert to TCPRuleConfig with duration parsing
		tcpRule, err := m.parseTCPConfig(rawConfig)
		if err != nil {
			return fmt.Errorf("failed to parse TCP config: %w", err)
		}

		config.TCPProtection = tcpRule.TCPProtection
		log.Debug().Str("file", tcpConfigPath).Msg("Loaded TCP protection config")
	}

	return nil
}

// parseTCPConfig converts raw config to TCPRuleConfig with duration parsing
func (m *MultiFileLoader) parseTCPConfig(raw map[string]interface{}) (*TCPRuleConfig, error) {
	config := &TCPRuleConfig{}

	if tcpRaw, ok := raw["tcp_protection"].(map[string]interface{}); ok {
		tcp := &config.TCPProtection

		if v, ok := tcpRaw["enable_tcp_protection"].(bool); ok {
			tcp.EnableTCPProtection = v
		}
		if v, ok := tcpRaw["connection_rate_limit"].(float64); ok {
			tcp.ConnectionRateLimit = int64(v)
		}
		if v, ok := tcpRaw["connection_window"].(string); ok {
			if d, err := time.ParseDuration(v); err == nil {
				tcp.ConnectionWindow = d
			}
		}
		if v, ok := tcpRaw["silent_drop_threshold"].(float64); ok {
			tcp.SilentDropThreshold = int64(v)
		}
		if v, ok := tcpRaw["tarpit_threshold"].(float64); ok {
			tcp.TarpitThreshold = int64(v)
		}
		if v, ok := tcpRaw["tarpit_delay"].(string); ok {
			if d, err := time.ParseDuration(v); err == nil {
				tcp.TarpitDelay = d
			}
		}
		if v, ok := tcpRaw["max_tarpit_connections"].(float64); ok {
			tcp.MaxTarpitConnections = int(v)
		}
		if v, ok := tcpRaw["brute_force_threshold"].(float64); ok {
			tcp.BruteForceThreshold = int64(v)
		}
		if v, ok := tcpRaw["brute_force_window"].(string); ok {
			if d, err := time.ParseDuration(v); err == nil {
				tcp.BruteForceWindow = d
			}
		}
		if v, ok := tcpRaw["cleanup_interval"].(string); ok {
			if d, err := time.ParseDuration(v); err == nil {
				tcp.CleanupInterval = d
			}
		}

		// Parse IP lists
		if v, ok := tcpRaw["whitelisted_ips"].([]interface{}); ok {
			for _, ip := range v {
				if s, ok := ip.(string); ok {
					tcp.WhitelistedIPs = append(tcp.WhitelistedIPs, s)
				}
			}
		}
		if v, ok := tcpRaw["blacklisted_ips"].([]interface{}); ok {
			for _, ip := range v {
				if s, ok := ip.(string); ok {
					tcp.BlacklistedIPs = append(tcp.BlacklistedIPs, s)
				}
			}
		}
	}

	return config, nil
}

// loadSecurityRules loads security rules
func (m *MultiFileLoader) loadSecurityRules(config *SystemConfig) error {
	securityDir := filepath.Join(m.configDir, "security")
	if !m.dirExists(securityDir) {
		log.Debug().Str("dir", securityDir).Msg("Security directory not found")
		return nil
	}

	securityConfigPath := filepath.Join(securityDir, "security-config.json")
	if m.fileExists(securityConfigPath) {
		var securityRule SecurityRuleConfig
		if err := m.loadJSONFile(securityConfigPath, &securityRule); err != nil {
			return fmt.Errorf("failed to load security config: %w", err)
		}
		config.Security = securityRule.Security
		log.Debug().Str("file", securityConfigPath).Msg("Loaded security config")
	}

	return nil
}

// loadJSONFile loads and parses a JSON file
func (m *MultiFileLoader) loadJSONFile(path string, target interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", path, err)
	}

	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("failed to parse JSON in %s: %w", path, err)
	}

	return nil
}

// fileExists checks if a file exists
func (m *MultiFileLoader) fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// dirExists checks if a directory exists
func (m *MultiFileLoader) dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// getNameFromFile extracts name from filename
func (m *MultiFileLoader) getNameFromFile(filePath string) string {
	filename := filepath.Base(filePath)
	name := strings.TrimSuffix(filename, filepath.Ext(filename))
	return strings.ReplaceAll(name, "-", "_")
}

// SupportsSource checks if the loader supports the given source
func (m *MultiFileLoader) SupportsSource(source string) bool {
	return m.dirExists(source)
}

// GetSourceType returns the source type
func (m *MultiFileLoader) GetSourceType() string {
	return "multi-file"
}

// SingleFileLoader loads configuration from a single file (backward compatibility)
type SingleFileLoader struct {
	configFile string
}

// NewSingleFileLoader creates a new single file loader
func NewSingleFileLoader(configFile string) *SingleFileLoader {
	return &SingleFileLoader{configFile: configFile}
}

// LoadConfig loads configuration from a single file
func (s *SingleFileLoader) LoadConfig(source string) (*SystemConfig, error) {
	return LoadConfig(s.configFile)
}

// SupportsSource checks if the loader supports the given source
func (s *SingleFileLoader) SupportsSource(source string) bool {
	_, err := os.Stat(source)
	return err == nil
}

// GetSourceType returns the source type
func (s *SingleFileLoader) GetSourceType() string {
	return "single-file"
}

// DefaultConfigLoader creates default configuration
type DefaultConfigLoader struct {
	basePath string
}

// NewDefaultConfigLoader creates a new default config loader
func NewDefaultConfigLoader(basePath string) *DefaultConfigLoader {
	return &DefaultConfigLoader{basePath: basePath}
}

// LoadConfig creates and returns default configuration
func (d *DefaultConfigLoader) LoadConfig(source string) (*SystemConfig, error) {
	config := CreateDefaultConfig()

	// Save default config to file for future use
	defaultPath := filepath.Join(d.basePath, "system_config.json")
	if err := SaveConfig(config, defaultPath); err != nil {
		log.Warn().Err(err).Str("path", defaultPath).Msg("Failed to save default config")
	} else {
		log.Info().Str("path", defaultPath).Msg("Created default configuration file")
	}

	return config, nil
}

// SupportsSource always returns true for default loader
func (d *DefaultConfigLoader) SupportsSource(source string) bool {
	return true
}

// GetSourceType returns the source type
func (d *DefaultConfigLoader) GetSourceType() string {
	return "default"
}
