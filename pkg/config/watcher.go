package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/oarkflow/log"
)

// Watcher monitors configuration files for changes and triggers reloads
type Watcher struct {
	configPath     string
	lastModTime    time.Time
	reloadCallback func(*SystemConfig) error
	stopChan       chan struct{}
	mu             sync.RWMutex
	running        bool
}

// ReloadCallback is called when configuration is reloaded
type ReloadCallback func(*SystemConfig) error

// NewConfigWatcher creates a new configuration watcher
func NewConfigWatcher(configPath string, callback ReloadCallback) *Watcher {
	return &Watcher{
		configPath:     configPath,
		reloadCallback: callback,
		stopChan:       make(chan struct{}),
	}
}

// Start begins watching the configuration file for changes
func (cw *Watcher) Start(ctx context.Context) error {
	cw.mu.Lock()
	if cw.running {
		cw.mu.Unlock()
		return fmt.Errorf("config watcher is already running")
	}
	cw.running = true
	cw.mu.Unlock()

	// Get initial modification time
	if err := cw.updateModTime(); err != nil {
		return fmt.Errorf("failed to get initial mod time: %w", err)
	}

	log.Info().Str("config_path", cw.configPath).Msg("Config watcher started")

	// Start the watching goroutine
	go cw.watchLoop(ctx)

	return nil
}

// Stop stops the configuration watcher
func (cw *Watcher) Stop() {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	if !cw.running {
		return
	}

	cw.running = false
	close(cw.stopChan)
	log.Info().Msg("Config watcher stopped")
}

// watchLoop is the main watching loop
func (cw *Watcher) watchLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second) // Check every 2 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cw.stopChan:
			return
		case <-ticker.C:
			if err := cw.checkForChanges(); err != nil {
				log.Error().Err(err).Msg("Error checking for config changes")
			}
		}
	}
}

// checkForChanges checks if the configuration file has been modified
func (cw *Watcher) checkForChanges() error {
	stat, err := os.Stat(cw.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Warn().Str("config_path", cw.configPath).Msg("Config file no longer exists")
			return nil
		}
		return fmt.Errorf("failed to stat config file: %w", err)
	}

	cw.mu.RLock()
	lastMod := cw.lastModTime
	cw.mu.RUnlock()

	if stat.ModTime().After(lastMod) {
		log.Info().Str("config_path", cw.configPath).Msg("Config file has been modified, reloading...")

		if err := cw.reloadConfig(); err != nil {
			log.Error().Err(err).Msg("Failed to reload config")
			return err
		}

		cw.mu.Lock()
		cw.lastModTime = stat.ModTime()
		cw.mu.Unlock()

		log.Info().Msg("Config reloaded successfully")
	}

	return nil
}

// reloadConfig loads and applies the new configuration
func (cw *Watcher) reloadConfig() error {
	// Load the new configuration
	newConfig, err := LoadConfig(cw.configPath)
	if err != nil {
		return fmt.Errorf("failed to load new config: %w", err)
	}

	// Validate the new configuration
	if err := validateConfig(newConfig); err != nil {
		return fmt.Errorf("new config is invalid: %w", err)
	}

	// Apply the new configuration via callback
	if cw.reloadCallback != nil {
		if err := cw.reloadCallback(newConfig); err != nil {
			return fmt.Errorf("failed to apply new config: %w", err)
		}
	}

	return nil
}

// updateModTime updates the stored modification time
func (cw *Watcher) updateModTime() error {
	stat, err := os.Stat(cw.configPath)
	if err != nil {
		return err
	}

	cw.mu.Lock()
	cw.lastModTime = stat.ModTime()
	cw.mu.Unlock()

	return nil
}

// ForceReload forces a configuration reload regardless of modification time
func (cw *Watcher) ForceReload() error {
	log.Info().Msg("Forcing config reload...")
	return cw.reloadConfig()
}

// Manager manages configuration with hot reload capabilities
type Manager struct {
	currentConfig   *SystemConfig
	watcher         *Watcher
	configPath      string
	reloadCallbacks []ReloadCallback
	mu              sync.RWMutex
}

// NewManager creates a new configuration manager
func NewManager(configPath string) *Manager {
	return &Manager{
		configPath:      configPath,
		reloadCallbacks: make([]ReloadCallback, 0),
	}
}

// LoadInitialConfig loads the initial configuration
func (cm *Manager) LoadInitialConfig() error {
	config, err := LoadConfig(cm.configPath)
	if err != nil {
		return fmt.Errorf("failed to load initial config: %w", err)
	}

	cm.mu.Lock()
	cm.currentConfig = config
	cm.mu.Unlock()

	return nil
}

// GetConfig returns the current configuration (thread-safe)
func (cm *Manager) GetConfig() *SystemConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Return a deep copy to prevent external modifications
	configBytes, _ := json.Marshal(cm.currentConfig)
	var configCopy SystemConfig
	json.Unmarshal(configBytes, &configCopy)

	return &configCopy
}

// AddReloadCallback adds a callback to be called when configuration is reloaded
func (cm *Manager) AddReloadCallback(callback ReloadCallback) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.reloadCallbacks = append(cm.reloadCallbacks, callback)
}

// StartWatching starts watching for configuration changes
func (cm *Manager) StartWatching(ctx context.Context) error {
	cm.watcher = NewConfigWatcher(cm.configPath, cm.handleConfigReload)
	return cm.watcher.Start(ctx)
}

// StopWatching stops watching for configuration changes
func (cm *Manager) StopWatching() {
	if cm.watcher != nil {
		cm.watcher.Stop()
	}
}

// handleConfigReload handles configuration reload events
func (cm *Manager) handleConfigReload(newConfig *SystemConfig) error {
	// Update current configuration
	cm.mu.Lock()
	oldConfig := cm.currentConfig
	cm.currentConfig = newConfig
	callbacks := make([]ReloadCallback, len(cm.reloadCallbacks))
	copy(callbacks, cm.reloadCallbacks)
	cm.mu.Unlock()

	// Log configuration changes
	cm.logConfigChanges(oldConfig, newConfig)

	// Notify all registered callbacks
	for _, callback := range callbacks {
		if err := callback(newConfig); err != nil {
			log.Error().Err(err).Msg("Config reload callback failed")
			// Continue with other callbacks even if one fails
		}
	}

	return nil
}

// logConfigChanges logs what changed in the configuration
func (cm *Manager) logConfigChanges(oldConfig, newConfig *SystemConfig) {
	if oldConfig == nil {
		log.Info().Msg("Initial configuration loaded")
		return
	}

	// Check for action rule changes
	if len(oldConfig.Engine.ActionRules) != len(newConfig.Engine.ActionRules) {
		log.Info().Int("old_count", len(oldConfig.Engine.ActionRules)).Int("new_count", len(newConfig.Engine.ActionRules)).Msg("Action rules count changed")
	}

	// Log rule changes
	oldRules := make(map[string]ActionRule)
	for _, rule := range oldConfig.Engine.ActionRules {
		oldRules[rule.Name] = rule
	}

	for _, newRule := range newConfig.Engine.ActionRules {
		if oldRule, exists := oldRules[newRule.Name]; exists {
			if !rulesEqual(oldRule, newRule) {
				log.Info().Str("rule", newRule.Name).Msg("Action rule modified")
			}
		} else {
			log.Info().Str("rule", newRule.Name).Msg("New action rule added")
		}
	}

	// Check for removed rules
	newRules := make(map[string]ActionRule)
	for _, rule := range newConfig.Engine.ActionRules {
		newRules[rule.Name] = rule
	}

	for _, oldRule := range oldConfig.Engine.ActionRules {
		if _, exists := newRules[oldRule.Name]; !exists {
			log.Info().Str("rule", oldRule.Name).Msg("Action rule removed")
		}
	}
}

// rulesEqual compares two action rules for equality
func rulesEqual(rule1, rule2 ActionRule) bool {
	return rule1.MinSeverity == rule2.MinSeverity &&
		rule1.MaxSeverity == rule2.MaxSeverity &&
		rule1.MinConfidence == rule2.MinConfidence &&
		rule1.MaxConfidence == rule2.MaxConfidence &&
		rule1.Priority == rule2.Priority &&
		rule1.Enabled == rule2.Enabled &&
		rule1.RequireAllTags == rule2.RequireAllTags &&
		slicesEqual(rule1.Actions, rule2.Actions) &&
		slicesEqual(rule1.ThreatTags, rule2.ThreatTags) &&
		slicesEqual(rule1.ExcludeTags, rule2.ExcludeTags)
}

// slicesEqual compares two string slices for equality
func slicesEqual(slice1, slice2 []string) bool {
	if len(slice1) != len(slice2) {
		return false
	}
	for i, v := range slice1 {
		if v != slice2[i] {
			return false
		}
	}
	return true
}

// UpdateConfig updates the configuration programmatically and saves it to file
func (cm *Manager) UpdateConfig(updater func(*SystemConfig) error) error {
	cm.mu.Lock()

	// Create a copy of current config
	configBytes, err := json.Marshal(cm.currentConfig)
	if err != nil {
		cm.mu.Unlock()
		return fmt.Errorf("failed to marshal current config: %w", err)
	}

	var newConfig SystemConfig
	if err := json.Unmarshal(configBytes, &newConfig); err != nil {
		cm.mu.Unlock()
		return fmt.Errorf("failed to unmarshal config copy: %w", err)
	}

	// Apply the update
	if err := updater(&newConfig); err != nil {
		cm.mu.Unlock()
		return fmt.Errorf("config update failed: %w", err)
	}

	// Validate the updated configuration
	if err := validateConfig(&newConfig); err != nil {
		cm.mu.Unlock()
		return fmt.Errorf("updated config is invalid: %w", err)
	}

	// Update in-memory configuration first
	oldConfig := cm.currentConfig
	cm.currentConfig = &newConfig

	// Get callbacks while still holding the lock
	callbacks := make([]ReloadCallback, len(cm.reloadCallbacks))
	copy(callbacks, cm.reloadCallbacks)
	cm.mu.Unlock()

	// Save to file
	if err := SaveConfig(&newConfig, cm.configPath); err != nil {
		// Rollback in-memory config on file save failure
		cm.mu.Lock()
		cm.currentConfig = oldConfig
		cm.mu.Unlock()
		return fmt.Errorf("failed to save updated config: %w", err)
	}

	// Log configuration changes
	cm.logConfigChanges(oldConfig, &newConfig)

	// Notify all registered callbacks
	for _, callback := range callbacks {
		if err := callback(&newConfig); err != nil {
			log.Error().Err(err).Msg("Config update callback failed")
			// Continue with other callbacks even if one fails
		}
	}

	log.Info().Msg("Configuration updated and saved successfully")
	return nil
}

// GetConfigPath returns the path to the configuration file
func (cm *Manager) GetConfigPath() string {
	return cm.configPath
}

// ForceReload forces a configuration reload through the watcher
func (cm *Manager) ForceReload() error {
	if cm.watcher == nil {
		// If no watcher, reload directly
		return cm.reloadConfigDirect()
	}
	return cm.watcher.ForceReload()
}

// reloadConfigDirect reloads configuration directly without watcher
func (cm *Manager) reloadConfigDirect() error {
	newConfig, err := LoadConfig(cm.configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := validateConfig(newConfig); err != nil {
		return fmt.Errorf("config is invalid: %w", err)
	}

	return cm.handleConfigReload(newConfig)
}
