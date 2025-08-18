package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oarkflow/log"
)

// ConfigMigrator handles migration from single file to modular configuration
type ConfigMigrator struct {
	sourceFile string
	targetDir  string
}

// NewConfigMigrator creates a new config migrator
func NewConfigMigrator(sourceFile, targetDir string) *ConfigMigrator {
	return &ConfigMigrator{
		sourceFile: sourceFile,
		targetDir:  targetDir,
	}
}

// MigrateToModular migrates single file config to modular structure
func (m *ConfigMigrator) MigrateToModular() error {
	log.Info().Str("source", m.sourceFile).Str("target", m.targetDir).Msg("Starting configuration migration")

	// Load existing single file config
	oldConfig, err := LoadConfig(m.sourceFile)
	if err != nil {
		return fmt.Errorf("failed to load source config: %w", err)
	}

	// Create target directory structure
	if err := m.createDirectoryStructure(); err != nil {
		return fmt.Errorf("failed to create directory structure: %w", err)
	}

	// Split and save configurations
	if err := m.saveServerConfig(oldConfig); err != nil {
		return fmt.Errorf("failed to save server config: %w", err)
	}

	if err := m.saveGlobalConfig(oldConfig); err != nil {
		return fmt.Errorf("failed to save global config: %w", err)
	}

	if err := m.saveDetectorRules(oldConfig); err != nil {
		return fmt.Errorf("failed to save detector rules: %w", err)
	}

	if err := m.saveActionRules(oldConfig); err != nil {
		return fmt.Errorf("failed to save action rules: %w", err)
	}

	if err := m.saveHandlerRules(oldConfig); err != nil {
		return fmt.Errorf("failed to save handler rules: %w", err)
	}

	if err := m.saveTCPRules(oldConfig); err != nil {
		return fmt.Errorf("failed to save TCP rules: %w", err)
	}

	if err := m.saveSecurityRules(oldConfig); err != nil {
		return fmt.Errorf("failed to save security rules: %w", err)
	}

	log.Info().Msg("Configuration migration completed successfully")
	return nil
}

// createDirectoryStructure creates the modular config directory structure
func (m *ConfigMigrator) createDirectoryStructure() error {
	dirs := []string{
		m.targetDir,
		filepath.Join(m.targetDir, "detectors"),
		filepath.Join(m.targetDir, "actions"),
		filepath.Join(m.targetDir, "handlers"),
		filepath.Join(m.targetDir, "tcp-protection"),
		filepath.Join(m.targetDir, "security"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		log.Debug().Str("dir", dir).Msg("Created directory")
	}

	return nil
}

// saveServerConfig saves server configuration
func (m *ConfigMigrator) saveServerConfig(config *SystemConfig) error {
	serverPath := filepath.Join(m.targetDir, "server.json")
	return m.saveJSONFile(serverPath, config.Server)
}

// saveGlobalConfig saves global configuration
func (m *ConfigMigrator) saveGlobalConfig(config *SystemConfig) error {
	globalConfig := GlobalConfig{
		Engine:  config.Engine,
		Events:  config.Events,
		Logging: config.Logging,
		Store: GlobalStoreConfig{
			Type:       config.Store.Type,
			Address:    config.Store.Address,
			Password:   config.Store.Password,
			Database:   config.Store.Database,
			Prefix:     config.Store.Prefix,
			MaxRetries: config.Store.MaxRetries,
			Timeout:    config.Store.Timeout.String(),
			Options:    config.Store.Options,
		},
	}

	globalPath := filepath.Join(m.targetDir, "global.json")
	return m.saveJSONFile(globalPath, globalConfig)
}

// saveDetectorRules saves detector rules to separate files
func (m *ConfigMigrator) saveDetectorRules(config *SystemConfig) error {
	detectorsDir := filepath.Join(m.targetDir, "detectors")

	// Group action rules by detector type
	detectorRules := make(map[string][]ActionRule)
	for _, rule := range config.Engine.ActionRules {
		for _, tag := range rule.ThreatTags {
			detectorName := m.getDetectorNameFromTag(tag)
			if detectorName != "" {
				detectorRules[detectorName] = append(detectorRules[detectorName], rule)
			}
		}
	}

	// Save each detector with its rules
	for detectorName, pluginConfig := range config.Plugins.Detectors {
		detectorRule := DetectorRuleConfig{
			Detector: DetectorConfig{
				Name:       detectorName,
				Enabled:    pluginConfig.Enabled,
				Priority:   pluginConfig.Priority,
				Parameters: pluginConfig.Parameters,
			},
			ActionRules: detectorRules[detectorName],
		}

		filename := m.getDetectorFileName(detectorName)
		filePath := filepath.Join(detectorsDir, filename)
		if err := m.saveJSONFile(filePath, detectorRule); err != nil {
			return fmt.Errorf("failed to save detector %s: %w", detectorName, err)
		}
		log.Debug().Str("detector", detectorName).Str("file", filePath).Msg("Saved detector rules")
	}

	return nil
}

// saveActionRules saves action rules to separate files
func (m *ConfigMigrator) saveActionRules(config *SystemConfig) error {
	actionsDir := filepath.Join(m.targetDir, "actions")

	for actionName, pluginConfig := range config.Plugins.Actions {
		actionRule := ActionRuleConfig{
			Action: ActionConfig{
				Name:       actionName,
				Enabled:    pluginConfig.Enabled,
				Priority:   pluginConfig.Priority,
				Parameters: pluginConfig.Parameters,
			},
		}

		filename := m.getActionFileName(actionName)
		filePath := filepath.Join(actionsDir, filename)
		if err := m.saveJSONFile(filePath, actionRule); err != nil {
			return fmt.Errorf("failed to save action %s: %w", actionName, err)
		}
		log.Debug().Str("action", actionName).Str("file", filePath).Msg("Saved action rules")
	}

	return nil
}

// saveHandlerRules saves handler rules to separate files
func (m *ConfigMigrator) saveHandlerRules(config *SystemConfig) error {
	handlersDir := filepath.Join(m.targetDir, "handlers")

	for handlerName, pluginConfig := range config.Plugins.Handlers {
		handlerRule := HandlerRuleConfig{
			Handler: HandlerConfig{
				Name:       handlerName,
				Enabled:    pluginConfig.Enabled,
				Priority:   pluginConfig.Priority,
				Parameters: pluginConfig.Parameters,
			},
		}

		filename := m.getHandlerFileName(handlerName)
		filePath := filepath.Join(handlersDir, filename)
		if err := m.saveJSONFile(filePath, handlerRule); err != nil {
			return fmt.Errorf("failed to save handler %s: %w", handlerName, err)
		}
		log.Debug().Str("handler", handlerName).Str("file", filePath).Msg("Saved handler rules")
	}

	return nil
}

// saveTCPRules saves TCP protection rules
func (m *ConfigMigrator) saveTCPRules(config *SystemConfig) error {
	tcpDir := filepath.Join(m.targetDir, "tcp-protection")

	tcpRule := TCPRuleConfig{
		TCPProtection: config.TCPProtection,
	}

	tcpConfigPath := filepath.Join(tcpDir, "tcp-config.json")
	if err := m.saveJSONFile(tcpConfigPath, tcpRule); err != nil {
		return fmt.Errorf("failed to save TCP config: %w", err)
	}
	log.Debug().Str("file", tcpConfigPath).Msg("Saved TCP protection config")

	return nil
}

// saveSecurityRules saves security rules
func (m *ConfigMigrator) saveSecurityRules(config *SystemConfig) error {
	securityDir := filepath.Join(m.targetDir, "security")

	securityRule := SecurityRuleConfig{
		Security: config.Security,
	}

	securityConfigPath := filepath.Join(securityDir, "security-config.json")
	if err := m.saveJSONFile(securityConfigPath, securityRule); err != nil {
		return fmt.Errorf("failed to save security config: %w", err)
	}
	log.Debug().Str("file", securityConfigPath).Msg("Saved security config")

	return nil
}

// saveJSONFile saves data as JSON to file
func (m *ConfigMigrator) saveJSONFile(path string, data interface{}) error {
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(path, bytes, 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}

	return nil
}

// getDetectorNameFromTag maps threat tags to detector names
func (m *ConfigMigrator) getDetectorNameFromTag(tag string) string {
	tagToDetector := map[string]string{
		"sql_injection":  "sql_injection_detector",
		"xss":            "xss_detector",
		"path_traversal": "path_traversal_detector",
		"rate_limit":     "rate_limit_detector",
		"ddos":           "rate_limit_detector",
		"brute_force":    "brute_force_detector",
		"login_abuse":    "brute_force_detector",
		"suspicious_ua":  "suspicious_user_agent_detector",
		"geo_location":   "geo_location_detector",
	}

	return tagToDetector[tag]
}

// getDetectorFileName generates filename for detector
func (m *ConfigMigrator) getDetectorFileName(detectorName string) string {
	name := strings.ReplaceAll(detectorName, "_", "-")
	return fmt.Sprintf("%s-rules.json", name)
}

// getActionFileName generates filename for action
func (m *ConfigMigrator) getActionFileName(actionName string) string {
	name := strings.ReplaceAll(actionName, "_", "-")
	return fmt.Sprintf("%s-rules.json", name)
}

// getHandlerFileName generates filename for handler
func (m *ConfigMigrator) getHandlerFileName(handlerName string) string {
	name := strings.ReplaceAll(handlerName, "_", "-")
	return fmt.Sprintf("%s-rules.json", name)
}

// MigrateCommand provides CLI interface for migration
func MigrateCommand(sourceFile, targetDir string) error {
	migrator := NewConfigMigrator(sourceFile, targetDir)
	return migrator.MigrateToModular()
}
