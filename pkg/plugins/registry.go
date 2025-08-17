package plugins

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// PluginRegistry manages all registered plugins
type PluginRegistry struct {
	detectors map[string]DetectorPlugin
	actions   map[string]ActionPlugin
	handlers  map[string]EventHandler
	metadata  map[string]PluginMetadata
	configs   map[string]PluginConfig
	mu        sync.RWMutex
}

// NewPluginRegistry creates a new plugin registry
func NewPluginRegistry() *PluginRegistry {
	return &PluginRegistry{
		detectors: make(map[string]DetectorPlugin),
		actions:   make(map[string]ActionPlugin),
		handlers:  make(map[string]EventHandler),
		metadata:  make(map[string]PluginMetadata),
		configs:   make(map[string]PluginConfig),
	}
}

// RegisterDetector registers a detector plugin
func (r *PluginRegistry) RegisterDetector(plugin DetectorPlugin, metadata PluginMetadata, config PluginConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := plugin.Name()
	if _, exists := r.detectors[name]; exists {
		return fmt.Errorf("detector plugin %s already registered", name)
	}

	// Initialize the plugin
	if err := plugin.Initialize(config.Parameters); err != nil {
		return fmt.Errorf("failed to initialize detector plugin %s: %w", name, err)
	}

	r.detectors[name] = plugin
	r.metadata[name] = metadata
	r.configs[name] = config

	return nil
}

// RegisterAction registers an action plugin
func (r *PluginRegistry) RegisterAction(plugin ActionPlugin, metadata PluginMetadata, config PluginConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := plugin.Name()
	if _, exists := r.actions[name]; exists {
		return fmt.Errorf("action plugin %s already registered", name)
	}

	// Initialize the plugin
	if err := plugin.Initialize(config.Parameters); err != nil {
		return fmt.Errorf("failed to initialize action plugin %s: %w", name, err)
	}

	r.actions[name] = plugin
	r.metadata[name] = metadata
	r.configs[name] = config

	return nil
}

// RegisterHandler registers an event handler plugin
func (r *PluginRegistry) RegisterHandler(handler EventHandler, metadata PluginMetadata, config PluginConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := handler.Name()
	if _, exists := r.handlers[name]; exists {
		return fmt.Errorf("handler plugin %s already registered", name)
	}

	// Initialize the handler
	if err := handler.Initialize(config.Parameters); err != nil {
		return fmt.Errorf("failed to initialize handler plugin %s: %w", name, err)
	}

	r.handlers[name] = handler
	r.metadata[name] = metadata
	r.configs[name] = config

	return nil
}

// GetDetector retrieves a detector plugin by name
func (r *PluginRegistry) GetDetector(name string) (DetectorPlugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugin, exists := r.detectors[name]
	if !exists {
		return nil, false
	}

	config, configExists := r.configs[name]
	if !configExists || !config.Enabled {
		return nil, false
	}

	return plugin, true
}

// GetAction retrieves an action plugin by name
func (r *PluginRegistry) GetAction(name string) (ActionPlugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugin, exists := r.actions[name]
	if !exists {
		return nil, false
	}

	config, configExists := r.configs[name]
	if !configExists || !config.Enabled {
		return nil, false
	}

	return plugin, true
}

// GetHandlers retrieves all event handlers that can handle a specific event type
func (r *PluginRegistry) GetHandlers(eventType string) []EventHandler {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var handlers []EventHandler
	for name, handler := range r.handlers {
		config, exists := r.configs[name]
		if !exists || !config.Enabled {
			continue
		}

		if handler.CanHandle(eventType) {
			handlers = append(handlers, handler)
		}
	}

	// Sort handlers by priority (higher priority first)
	sort.Slice(handlers, func(i, j int) bool {
		return handlers[i].Priority() > handlers[j].Priority()
	})

	return handlers
}

// GetAllDetectors returns all enabled detector plugins
func (r *PluginRegistry) GetAllDetectors() []DetectorPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var detectors []DetectorPlugin
	for name, detector := range r.detectors {
		config, exists := r.configs[name]
		if exists && config.Enabled {
			detectors = append(detectors, detector)
		}
	}

	return detectors
}

// GetAllActions returns all enabled action plugins
func (r *PluginRegistry) GetAllActions() []ActionPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var actions []ActionPlugin
	for name, action := range r.actions {
		config, exists := r.configs[name]
		if exists && config.Enabled {
			actions = append(actions, action)
		}
	}

	return actions
}

// UnregisterPlugin removes a plugin from the registry
func (r *PluginRegistry) UnregisterPlugin(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if it's a detector
	if detector, exists := r.detectors[name]; exists {
		if err := detector.Cleanup(); err != nil {
			return fmt.Errorf("failed to cleanup detector %s: %w", name, err)
		}
		delete(r.detectors, name)
	}

	// Check if it's an action
	if action, exists := r.actions[name]; exists {
		if err := action.Cleanup(); err != nil {
			return fmt.Errorf("failed to cleanup action %s: %w", name, err)
		}
		delete(r.actions, name)
	}

	// Check if it's a handler
	if handler, exists := r.handlers[name]; exists {
		if err := handler.Cleanup(); err != nil {
			return fmt.Errorf("failed to cleanup handler %s: %w", name, err)
		}
		delete(r.handlers, name)
	}

	delete(r.metadata, name)
	delete(r.configs, name)

	return nil
}

// UpdatePluginConfig updates the configuration of a plugin
func (r *PluginRegistry) UpdatePluginConfig(name string, config PluginConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.metadata[name]; !exists {
		return fmt.Errorf("plugin %s not found", name)
	}

	r.configs[name] = config
	return nil
}

// GetPluginMetadata returns metadata for a plugin
func (r *PluginRegistry) GetPluginMetadata(name string) (PluginMetadata, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	metadata, exists := r.metadata[name]
	return metadata, exists
}

// GetAllPluginMetadata returns metadata for all plugins
func (r *PluginRegistry) GetAllPluginMetadata() map[string]PluginMetadata {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]PluginMetadata)
	for name, metadata := range r.metadata {
		result[name] = metadata
	}

	return result
}

// HealthCheck performs health checks on all plugins
func (r *PluginRegistry) HealthCheck(ctx context.Context) map[string]error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	results := make(map[string]error)

	// Check detectors
	for name, detector := range r.detectors {
		if config, exists := r.configs[name]; exists && config.Enabled {
			results[name] = detector.Health()
		}
	}

	// Check actions
	for name, action := range r.actions {
		if config, exists := r.configs[name]; exists && config.Enabled {
			results[name] = action.Health()
		}
	}

	return results
}

// Shutdown cleanly shuts down all plugins
func (r *PluginRegistry) Shutdown() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var errors []error

	// Cleanup detectors
	for name, detector := range r.detectors {
		if err := detector.Cleanup(); err != nil {
			errors = append(errors, fmt.Errorf("detector %s cleanup failed: %w", name, err))
		}
	}

	// Cleanup actions
	for name, action := range r.actions {
		if err := action.Cleanup(); err != nil {
			errors = append(errors, fmt.Errorf("action %s cleanup failed: %w", name, err))
		}
	}

	// Cleanup handlers
	for name, handler := range r.handlers {
		if err := handler.Cleanup(); err != nil {
			errors = append(errors, fmt.Errorf("handler %s cleanup failed: %w", name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("shutdown errors: %v", errors)
	}

	return nil
}
