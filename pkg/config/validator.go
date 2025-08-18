package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ConfigValidator interface for validating individual config files
type ConfigValidator interface {
	ValidateFile(filePath string, content []byte) error
	GetSupportedFileTypes() []string
}

// DetectorRuleValidator validates detector rule files
type DetectorRuleValidator struct{}

func (v *DetectorRuleValidator) ValidateFile(filePath string, content []byte) error {
	var config DetectorRuleConfig
	if err := json.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("invalid JSON in %s: %w", filePath, err)
	}

	// Validate detector configuration
	if config.Detector.Name == "" {
		return fmt.Errorf("detector name is required in %s", filePath)
	}

	if config.Detector.Priority < 1 || config.Detector.Priority > 100 {
		return fmt.Errorf("detector priority must be between 1-100 in %s", filePath)
	}

	// Validate action rules
	for i, rule := range config.ActionRules {
		if err := v.validateActionRule(rule, fmt.Sprintf("%s[%d]", filePath, i)); err != nil {
			return err
		}
	}

	return nil
}

func (v *DetectorRuleValidator) validateActionRule(rule ActionRule, context string) error {
	if rule.Name == "" {
		return fmt.Errorf("action rule name is required in %s", context)
	}

	if rule.MinSeverity < 1 || rule.MinSeverity > 10 {
		return fmt.Errorf("min_severity must be between 1-10 in %s", context)
	}

	if rule.MinConfidence < 0 || rule.MinConfidence > 1 {
		return fmt.Errorf("min_confidence must be between 0-1 in %s", context)
	}

	if len(rule.Actions) == 0 {
		return fmt.Errorf("at least one action is required in %s", context)
	}

	return nil
}

func (v *DetectorRuleValidator) GetSupportedFileTypes() []string {
	return []string{"detectors"}
}

// ActionRuleValidator validates action rule files
type ActionRuleValidator struct{}

func (v *ActionRuleValidator) ValidateFile(filePath string, content []byte) error {
	var config ActionRuleConfig
	if err := json.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("invalid JSON in %s: %w", filePath, err)
	}

	// Validate action configuration
	if config.Action.Name == "" {
		return fmt.Errorf("action name is required in %s", filePath)
	}

	if config.Action.Priority < 1 || config.Action.Priority > 100 {
		return fmt.Errorf("action priority must be between 1-100 in %s", filePath)
	}

	return nil
}

func (v *ActionRuleValidator) GetSupportedFileTypes() []string {
	return []string{"actions"}
}

// HandlerRuleValidator validates handler rule files
type HandlerRuleValidator struct{}

func (v *HandlerRuleValidator) ValidateFile(filePath string, content []byte) error {
	var config HandlerRuleConfig
	if err := json.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("invalid JSON in %s: %w", filePath, err)
	}

	// Validate handler configuration
	if config.Handler.Name == "" {
		return fmt.Errorf("handler name is required in %s", filePath)
	}

	if config.Handler.Priority < 1 || config.Handler.Priority > 100 {
		return fmt.Errorf("handler priority must be between 1-100 in %s", filePath)
	}

	return nil
}

func (v *HandlerRuleValidator) GetSupportedFileTypes() []string {
	return []string{"handlers"}
}

// ServerConfigValidator validates server configuration files
type ServerConfigValidator struct{}

func (v *ServerConfigValidator) ValidateFile(filePath string, content []byte) error {
	var config ServerConfig
	if err := json.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("invalid JSON in %s: %w", filePath, err)
	}

	// Validate server configuration
	if config.Port < 1 || config.Port > 65535 {
		return fmt.Errorf("invalid server port %d in %s", config.Port, filePath)
	}

	if config.TLSPort != 0 && (config.TLSPort < 1 || config.TLSPort > 65535) {
		return fmt.Errorf("invalid TLS port %d in %s", config.TLSPort, filePath)
	}

	if config.MaxConnections < 1 {
		return fmt.Errorf("max_connections must be > 0 in %s", filePath)
	}

	if config.BodyLimit < 1 {
		return fmt.Errorf("body_limit must be > 0 in %s", filePath)
	}

	return nil
}

func (v *ServerConfigValidator) GetSupportedFileTypes() []string {
	return []string{"server"}
}

// GlobalConfigValidator validates global configuration files
type GlobalConfigValidator struct{}

func (v *GlobalConfigValidator) ValidateFile(filePath string, content []byte) error {
	var config GlobalConfig
	if err := json.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("invalid JSON in %s: %w", filePath, err)
	}

	// Validate engine configuration
	if config.Engine.MaxConcurrentRequests < 1 {
		return fmt.Errorf("max_concurrent_requests must be > 0 in %s", filePath)
	}

	// Validate events configuration
	if config.Events.BufferSize < 1 {
		return fmt.Errorf("events buffer_size must be > 0 in %s", filePath)
	}

	if config.Events.WorkerCount < 1 {
		return fmt.Errorf("events worker_count must be > 0 in %s", filePath)
	}

	// Validate store configuration
	supportedStoreTypes := []string{"memory", "redis", "etcd"}
	validStoreType := false
	for _, t := range supportedStoreTypes {
		if config.Store.Type == t {
			validStoreType = true
			break
		}
	}
	if !validStoreType {
		return fmt.Errorf("unsupported store type: %s in %s", config.Store.Type, filePath)
	}

	return nil
}

func (v *GlobalConfigValidator) GetSupportedFileTypes() []string {
	return []string{"global"}
}

// TCPConfigValidator validates TCP protection configuration files
type TCPConfigValidator struct{}

func (v *TCPConfigValidator) ValidateFile(filePath string, content []byte) error {
	var config TCPRuleConfig
	if err := json.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("invalid JSON in %s: %w", filePath, err)
	}

	// Validate TCP protection configuration
	if config.TCPProtection.ConnectionRateLimit < 1 {
		return fmt.Errorf("connection_rate_limit must be > 0 in %s", filePath)
	}

	if config.TCPProtection.SilentDropThreshold < 1 {
		return fmt.Errorf("silent_drop_threshold must be > 0 in %s", filePath)
	}

	if config.TCPProtection.TarpitThreshold < 1 {
		return fmt.Errorf("tarpit_threshold must be > 0 in %s", filePath)
	}

	return nil
}

func (v *TCPConfigValidator) GetSupportedFileTypes() []string {
	return []string{"tcp-protection"}
}

// SecurityConfigValidator validates security configuration files
type SecurityConfigValidator struct{}

func (v *SecurityConfigValidator) ValidateFile(filePath string, content []byte) error {
	var config SecurityRuleConfig
	if err := json.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("invalid JSON in %s: %w", filePath, err)
	}

	// Validate security configuration
	if config.Security.MaxRequestSize < 1 {
		return fmt.Errorf("max_request_size must be > 0 in %s", filePath)
	}

	return nil
}

func (v *SecurityConfigValidator) GetSupportedFileTypes() []string {
	return []string{"security"}
}

// ValidationManager coordinates all validators
type ValidationManager struct {
	validators map[string]ConfigValidator
}

// NewValidationManager creates a new validation manager
func NewValidationManager() *ValidationManager {
	return &ValidationManager{
		validators: map[string]ConfigValidator{
			"detectors":      &DetectorRuleValidator{},
			"actions":        &ActionRuleValidator{},
			"handlers":       &HandlerRuleValidator{},
			"server":         &ServerConfigValidator{},
			"global":         &GlobalConfigValidator{},
			"tcp-protection": &TCPConfigValidator{},
			"security":       &SecurityConfigValidator{},
		},
	}
}

// ValidateConfigFile validates a single configuration file
func (vm *ValidationManager) ValidateConfigFile(filePath string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %w", filePath, err)
	}

	// Determine validator based on file path
	validator := vm.getValidatorForFile(filePath)
	if validator == nil {
		return fmt.Errorf("no validator found for file %s", filePath)
	}

	return validator.ValidateFile(filePath, content)
}

// ValidateConfigDirectory validates all configuration files in a directory
func (vm *ValidationManager) ValidateConfigDirectory(configDir string) error {
	// Validate core config files
	coreFiles := []string{"server.json", "global.json"}
	for _, file := range coreFiles {
		path := filepath.Join(configDir, file)
		if _, err := os.Stat(path); err == nil {
			if err := vm.ValidateConfigFile(path); err != nil {
				return err
			}
		}
	}

	// Validate rule directories
	ruleDirs := []string{"detectors", "actions", "handlers", "tcp-protection", "security"}
	for _, dir := range ruleDirs {
		dirPath := filepath.Join(configDir, dir)
		if err := vm.validateRuleDirectory(dirPath); err != nil {
			return err
		}
	}

	return nil
}

// validateRuleDirectory validates all files in a rule directory
func (vm *ValidationManager) validateRuleDirectory(dirPath string) error {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		return nil // Directory doesn't exist, skip validation
	}

	files, err := filepath.Glob(filepath.Join(dirPath, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to glob files in %s: %w", dirPath, err)
	}

	for _, file := range files {
		if err := vm.ValidateConfigFile(file); err != nil {
			return err
		}
	}

	return nil
}

// getValidatorForFile determines the appropriate validator for a file
func (vm *ValidationManager) getValidatorForFile(filePath string) ConfigValidator {
	dir := filepath.Dir(filePath)
	baseName := filepath.Base(dir)
	fileName := filepath.Base(filePath)

	// Check if it's a core config file
	if fileName == "server.json" {
		return vm.validators["server"]
	}
	if fileName == "global.json" {
		return vm.validators["global"]
	}

	// Check directory-based validators
	if validator, exists := vm.validators[baseName]; exists {
		return validator
	}

	// Check for specific config files
	if strings.Contains(filePath, "tcp-protection") {
		return vm.validators["tcp-protection"]
	}
	if strings.Contains(filePath, "security") {
		return vm.validators["security"]
	}

	return nil
}

// ValidateAndLoadConfig validates and loads configuration from directory
func ValidateAndLoadConfig(configDir string) (*SystemConfig, error) {
	// First validate all config files
	validator := NewValidationManager()
	if err := validator.ValidateConfigDirectory(configDir); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Then load the configuration
	loader := NewMultiFileLoader(configDir)
	config, err := loader.LoadConfig("")
	if err != nil {
		return nil, fmt.Errorf("failed to load validated configuration: %w", err)
	}

	return config, nil
}
