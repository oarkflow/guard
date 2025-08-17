package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/oarkflow/guard/pkg/config"
	"github.com/oarkflow/guard/pkg/engine"
)

// ConfigAPI provides REST endpoints for configuration management
type ConfigAPI struct {
	configManager *config.Manager
	ruleEngine    *engine.RuleEngine
}

// NewConfigAPI creates a new configuration API
func NewConfigAPI(configManager *config.Manager, ruleEngine *engine.RuleEngine) *ConfigAPI {
	return &ConfigAPI{
		configManager: configManager,
		ruleEngine:    ruleEngine,
	}
}

// RegisterRoutes registers all configuration API routes
func (api *ConfigAPI) RegisterRoutes(mux *http.ServeMux) {
	// Configuration endpoints
	mux.HandleFunc("/api/config", api.handleConfig)
	mux.HandleFunc("/api/config/reload", api.handleReload)

	// Action rules endpoints
	mux.HandleFunc("/api/config/rules", api.handleActionRules)
	mux.HandleFunc("/api/config/rules/", api.handleActionRule)

	// Rule management endpoints
	mux.HandleFunc("/api/config/rules/enable", api.handleEnableRule)
	mux.HandleFunc("/api/config/rules/disable", api.handleDisableRule)
	mux.HandleFunc("/api/config/rules/validate", api.handleValidateRule)
}

// handleConfig handles GET/PUT requests for the entire configuration
func (api *ConfigAPI) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		api.getConfig(w, r)
	case http.MethodPut:
		api.updateConfig(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// getConfig returns the current configuration
func (api *ConfigAPI) getConfig(w http.ResponseWriter, r *http.Request) {
	config := api.configManager.GetConfig()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(config); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode config: %v", err), http.StatusInternalServerError)
		return
	}
}

// updateConfig updates the entire configuration
func (api *ConfigAPI) updateConfig(w http.ResponseWriter, r *http.Request) {
	var newConfig config.SystemConfig
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Update configuration through the manager
	err := api.configManager.UpdateConfig(func(cfg *config.SystemConfig) error {
		*cfg = newConfig
		return nil
	})

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to update config: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Configuration updated"})
}

// handleReload forces a configuration reload
func (api *ConfigAPI) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Force reload through config manager
	if err := api.configManager.ForceReload(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to reload config: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Configuration reloaded"})
}

// handleActionRules handles GET/POST requests for action rules
func (api *ConfigAPI) handleActionRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		api.getActionRules(w, r)
	case http.MethodPost:
		api.addActionRule(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// getActionRules returns all action rules
func (api *ConfigAPI) getActionRules(w http.ResponseWriter, r *http.Request) {
	rules := api.ruleEngine.GetActionRules()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rules); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode rules: %v", err), http.StatusInternalServerError)
		return
	}
}

// addActionRule adds a new action rule
func (api *ConfigAPI) addActionRule(w http.ResponseWriter, r *http.Request) {
	var rule config.ActionRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Validate the rule
	if err := api.ruleEngine.ValidateActionRule(rule); err != nil {
		http.Error(w, fmt.Sprintf("Invalid rule: %v", err), http.StatusBadRequest)
		return
	}

	// Add the rule
	if err := api.ruleEngine.AddActionRule(rule); err != nil {
		http.Error(w, fmt.Sprintf("Failed to add rule: %v", err), http.StatusConflict)
		return
	}

	// Update the configuration file
	err := api.configManager.UpdateConfig(func(cfg *config.SystemConfig) error {
		cfg.Engine.ActionRules = api.ruleEngine.GetActionRules()
		return nil
	})

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to save config: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Rule added"})
}

// handleActionRule handles GET/PUT/DELETE requests for a specific action rule
func (api *ConfigAPI) handleActionRule(w http.ResponseWriter, r *http.Request) {
	// Extract rule name from URL path
	ruleName := r.URL.Path[len("/api/config/rules/"):]
	if ruleName == "" {
		http.Error(w, "Rule name is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		api.getActionRule(w, r, ruleName)
	case http.MethodPut:
		api.updateActionRule(w, r, ruleName)
	case http.MethodDelete:
		api.deleteActionRule(w, r, ruleName)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// getActionRule returns a specific action rule
func (api *ConfigAPI) getActionRule(w http.ResponseWriter, r *http.Request, ruleName string) {
	rule, err := api.ruleEngine.GetActionRule(ruleName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rule)
}

// updateActionRule updates a specific action rule
func (api *ConfigAPI) updateActionRule(w http.ResponseWriter, r *http.Request, ruleName string) {
	var updatedRule config.ActionRule
	if err := json.NewDecoder(r.Body).Decode(&updatedRule); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Ensure the name matches
	updatedRule.Name = ruleName

	// Validate the updated rule
	if err := api.ruleEngine.ValidateActionRule(updatedRule); err != nil {
		http.Error(w, fmt.Sprintf("Invalid rule: %v", err), http.StatusBadRequest)
		return
	}

	// Update the rule
	if err := api.ruleEngine.UpdateActionRule(ruleName, updatedRule); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Update the configuration file
	err := api.configManager.UpdateConfig(func(cfg *config.SystemConfig) error {
		cfg.Engine.ActionRules = api.ruleEngine.GetActionRules()
		return nil
	})

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to save config: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Rule updated"})
}

// deleteActionRule deletes a specific action rule
func (api *ConfigAPI) deleteActionRule(w http.ResponseWriter, r *http.Request, ruleName string) {
	// Remove the rule
	if err := api.ruleEngine.RemoveActionRule(ruleName); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Update the configuration file
	err := api.configManager.UpdateConfig(func(cfg *config.SystemConfig) error {
		cfg.Engine.ActionRules = api.ruleEngine.GetActionRules()
		return nil
	})

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to save config: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Rule deleted"})
}

// handleEnableRule enables a specific rule
func (api *ConfigAPI) handleEnableRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ruleName := r.URL.Query().Get("name")
	if ruleName == "" {
		http.Error(w, "Rule name is required", http.StatusBadRequest)
		return
	}

	if err := api.ruleEngine.EnableActionRule(ruleName, true); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Update the configuration file
	err := api.configManager.UpdateConfig(func(cfg *config.SystemConfig) error {
		cfg.Engine.ActionRules = api.ruleEngine.GetActionRules()
		return nil
	})

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to save config: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Rule enabled"})
}

// handleDisableRule disables a specific rule
func (api *ConfigAPI) handleDisableRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ruleName := r.URL.Query().Get("name")
	if ruleName == "" {
		http.Error(w, "Rule name is required", http.StatusBadRequest)
		return
	}

	if err := api.ruleEngine.EnableActionRule(ruleName, false); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Update the configuration file
	err := api.configManager.UpdateConfig(func(cfg *config.SystemConfig) error {
		cfg.Engine.ActionRules = api.ruleEngine.GetActionRules()
		return nil
	})

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to save config: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Rule disabled"})
}

// handleValidateRule validates a rule without adding it
func (api *ConfigAPI) handleValidateRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var rule config.ActionRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Validate the rule
	if err := api.ruleEngine.ValidateActionRule(rule); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"status": "invalid", "error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "valid", "message": "Rule is valid"})
}

// ConfigStats represents configuration statistics
type ConfigStats struct {
	ConfigPath    string `json:"config_path"`
	LastReload    string `json:"last_reload"`
	TotalRules    int    `json:"total_rules"`
	EnabledRules  int    `json:"enabled_rules"`
	DisabledRules int    `json:"disabled_rules"`
	WatcherActive bool   `json:"watcher_active"`
}

// GetStats returns configuration statistics
func (api *ConfigAPI) GetStats() ConfigStats {
	rules := api.ruleEngine.GetActionRules()
	enabled := 0
	disabled := 0

	for _, rule := range rules {
		if rule.Enabled {
			enabled++
		} else {
			disabled++
		}
	}

	return ConfigStats{
		ConfigPath:    api.configManager.GetConfigPath(),
		TotalRules:    len(rules),
		EnabledRules:  enabled,
		DisabledRules: disabled,
		WatcherActive: true, // TODO: Get actual watcher status
	}
}

// handleStats returns configuration statistics
func (api *ConfigAPI) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := api.GetStats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// EnableCORS enables CORS for the API
func (api *ConfigAPI) EnableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
