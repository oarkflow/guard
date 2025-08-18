package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
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
	multiWatcher    *MultiFileWatcher
	configPath      string
	configLoader    ConfigLoader
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

// NewManagerWithLoader creates a new configuration manager with a specific loader
func NewManagerWithLoader(loader ConfigLoader) *Manager {
	return &Manager{
		configLoader:    loader,
		reloadCallbacks: make([]ReloadCallback, 0),
	}
}

// LoadInitialConfig loads the initial configuration
func (cm *Manager) LoadInitialConfig() error {
	var config *SystemConfig
	var err error

	if cm.configLoader != nil {
		// Use the provided loader
		config, err = cm.configLoader.LoadConfig("")
	} else {
		// Use traditional single file loading
		config, err = LoadConfig(cm.configPath)
	}

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
	if cm.configLoader != nil {
		// Use multi-file watcher for modular configs
		if multiLoader, ok := cm.configLoader.(*MultiFileLoader); ok {
			cm.multiWatcher = NewMultiFileWatcher(multiLoader.configDir, cm.handleConfigReload)
			return cm.multiWatcher.StartWatching(ctx)
		}
	}

	// Fall back to single file watcher
	if cm.configPath != "" {
		cm.watcher = NewConfigWatcher(cm.configPath, cm.handleConfigReload)
		return cm.watcher.Start(ctx)
	}

	return nil
}

// StopWatching stops watching for configuration changes
func (cm *Manager) StopWatching() {
	if cm.multiWatcher != nil {
		cm.multiWatcher.StopWatching()
	}
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

// MultiFileWatcher watches multiple configuration files and directories
type MultiFileWatcher struct {
	configDir    string
	watchers     map[string]*fsnotify.Watcher
	callbacks    []ReloadCallback
	eventChan    chan fsnotify.Event
	stopChan     chan struct{}
	configLoader *MultiFileLoader
	mu           sync.RWMutex
	running      bool
}

// NewMultiFileWatcher creates a new multi-file watcher
func NewMultiFileWatcher(configDir string, callback ReloadCallback) *MultiFileWatcher {
	return &MultiFileWatcher{
		configDir:    configDir,
		watchers:     make(map[string]*fsnotify.Watcher),
		callbacks:    []ReloadCallback{callback},
		eventChan:    make(chan fsnotify.Event, 100),
		stopChan:     make(chan struct{}),
		configLoader: NewMultiFileLoader(configDir),
	}
}

// StartWatching starts watching all configuration files and directories
func (mw *MultiFileWatcher) StartWatching(ctx context.Context) error {
	mw.mu.Lock()
	if mw.running {
		mw.mu.Unlock()
		return fmt.Errorf("multi-file watcher is already running")
	}
	mw.running = true
	mw.mu.Unlock()

	// Watch core config files
	coreFiles := []string{"server.json", "global.json"}
	for _, file := range coreFiles {
		path := filepath.Join(mw.configDir, file)
		if err := mw.watchFile(path); err != nil {
			log.Warn().Str("file", path).Err(err).Msg("Failed to watch config file")
		}
	}

	// Watch rule directories
	ruleDirs := []string{"detectors", "actions", "handlers", "tcp-protection", "security"}
	for _, dir := range ruleDirs {
		dirPath := filepath.Join(mw.configDir, dir)
		if err := mw.watchDirectory(dirPath); err != nil {
			log.Warn().Str("dir", dirPath).Err(err).Msg("Failed to watch rule directory")
		}
	}

	// Start event handling goroutine
	go mw.handleEvents(ctx)

	log.Info().Str("config_dir", mw.configDir).Msg("Multi-file config watcher started")
	return nil
}

// StopWatching stops watching all files and directories
func (mw *MultiFileWatcher) StopWatching() {
	mw.mu.Lock()
	defer mw.mu.Unlock()

	if !mw.running {
		return
	}

	mw.running = false
	close(mw.stopChan)

	// Close all watchers
	for path, watcher := range mw.watchers {
		if err := watcher.Close(); err != nil {
			log.Warn().Str("path", path).Err(err).Msg("Failed to close watcher")
		}
	}

	log.Info().Msg("Multi-file config watcher stopped")
}

// watchFile adds a file to be watched
func (mw *MultiFileWatcher) watchFile(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Debug().Str("file", path).Msg("Config file does not exist, skipping watch")
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher for %s: %w", path, err)
	}

	if err := watcher.Add(path); err != nil {
		watcher.Close()
		return fmt.Errorf("failed to add file %s to watcher: %w", path, err)
	}

	mw.watchers[path] = watcher

	// Forward events to main event channel
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				mw.eventChan <- event
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Error().Str("file", path).Err(err).Msg("File watcher error")
			case <-mw.stopChan:
				return
			}
		}
	}()

	log.Debug().Str("file", path).Msg("Started watching config file")
	return nil
}

// watchDirectory adds a directory to be watched
func (mw *MultiFileWatcher) watchDirectory(dirPath string) error {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		log.Debug().Str("dir", dirPath).Msg("Config directory does not exist, skipping watch")
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher for %s: %w", dirPath, err)
	}

	if err := watcher.Add(dirPath); err != nil {
		watcher.Close()
		return fmt.Errorf("failed to add directory %s to watcher: %w", dirPath, err)
	}

	mw.watchers[dirPath] = watcher

	// Forward events to main event channel
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				mw.eventChan <- event
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Error().Str("dir", dirPath).Err(err).Msg("Directory watcher error")
			case <-mw.stopChan:
				return
			}
		}
	}()

	log.Debug().Str("dir", dirPath).Msg("Started watching config directory")
	return nil
}

// handleEvents processes file system events
func (mw *MultiFileWatcher) handleEvents(ctx context.Context) {
	debounceTimer := time.NewTimer(0)
	debounceTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-mw.stopChan:
			return
		case event := <-mw.eventChan:
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				log.Debug().Str("file", event.Name).Str("op", event.Op.String()).Msg("Config file changed")

				// Debounce rapid file changes
				debounceTimer.Reset(500 * time.Millisecond)
			}
		case <-debounceTimer.C:
			mw.reloadConfiguration()
		}
	}
}

// reloadConfiguration reloads the entire configuration
func (mw *MultiFileWatcher) reloadConfiguration() {
	log.Info().Msg("Reloading modular configuration...")

	// Load new configuration
	newConfig, err := mw.configLoader.LoadConfig("")
	if err != nil {
		log.Error().Err(err).Msg("Failed to reload modular configuration")
		return
	}

	// Notify all callbacks
	mw.mu.RLock()
	callbacks := make([]ReloadCallback, len(mw.callbacks))
	copy(callbacks, mw.callbacks)
	mw.mu.RUnlock()

	for _, callback := range callbacks {
		if err := callback(newConfig); err != nil {
			log.Error().Err(err).Msg("Config reload callback failed")
		}
	}

	log.Info().Msg("Modular configuration reloaded successfully")
}

// AddCallback adds a reload callback
func (mw *MultiFileWatcher) AddCallback(callback ReloadCallback) {
	mw.mu.Lock()
	defer mw.mu.Unlock()
	mw.callbacks = append(mw.callbacks, callback)
}
