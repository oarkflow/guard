package tests

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/oarkflow/guard/pkg/config"
)

func TestConfigHotReload(t *testing.T) {
	// Create a temporary config file
	tempConfigFile := "test_config_hot_reload.json"
	defer os.Remove(tempConfigFile)

	// Create initial configuration
	initialConfig := config.CreateDefaultConfig()
	initialConfig.Engine.ActionRules[0].Enabled = true
	initialConfig.Plugins.Detectors["rate_limit_detector"].Parameters["max_requests"] = float64(50)

	if err := config.SaveConfig(initialConfig, tempConfigFile); err != nil {
		t.Fatalf("Failed to save initial config: %v", err)
	}

	// Create config manager
	configManager := config.NewManager(tempConfigFile)

	// Load initial config
	if err := configManager.LoadInitialConfig(); err != nil {
		t.Fatalf("Failed to load initial config: %v", err)
	}

	// Verify initial config
	cfg := configManager.GetConfig()
	if cfg.Plugins.Detectors["rate_limit_detector"].Parameters["max_requests"] != float64(50) {
		t.Error("Initial config not loaded correctly")
	}

	// Set up reload callback to track changes
	reloadCalled := false
	var reloadedConfig *config.SystemConfig

	configManager.AddReloadCallback(func(newConfig *config.SystemConfig) error {
		reloadCalled = true
		reloadedConfig = newConfig
		t.Log("Config reload callback triggered")
		return nil
	})

	// Start watching
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := configManager.StartWatching(ctx); err != nil {
		t.Fatalf("Failed to start config watching: %v", err)
	}
	defer configManager.StopWatching()

	t.Log("Config watcher started, modifying config file...")

	// Modify the configuration
	modifiedConfig := *initialConfig
	modifiedConfig.Plugins.Detectors["rate_limit_detector"].Parameters["max_requests"] = float64(200)
	modifiedConfig.Engine.ActionRules[0].Enabled = false

	// Save modified config
	if err := config.SaveConfig(&modifiedConfig, tempConfigFile); err != nil {
		t.Fatalf("Failed to save modified config: %v", err)
	}

	// Wait for reload to be detected
	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			t.Fatal("Config reload was not detected within timeout")
		case <-ticker.C:
			if reloadCalled {
				t.Log("Config reload detected successfully")
				goto reloadDetected
			}
		}
	}

reloadDetected:
	// Verify the reloaded configuration
	if reloadedConfig == nil {
		t.Fatal("Reloaded config is nil")
	}

	if reloadedConfig.Plugins.Detectors["rate_limit_detector"].Parameters["max_requests"] != float64(200) {
		t.Errorf("Expected max_requests to be 200, got %v",
			reloadedConfig.Plugins.Detectors["rate_limit_detector"].Parameters["max_requests"])
	}

	if reloadedConfig.Engine.ActionRules[0].Enabled != false {
		t.Error("Expected first action rule to be disabled")
	}

	// Verify current config from manager
	currentConfig := configManager.GetConfig()
	if currentConfig.Plugins.Detectors["rate_limit_detector"].Parameters["max_requests"] != float64(200) {
		t.Error("Config manager did not update current config")
	}

	t.Log("Config hot reload test completed successfully")
}

func TestConfigValidation(t *testing.T) {
	// Test invalid configuration
	invalidConfig := config.CreateDefaultConfig()
	invalidConfig.Server.Port = 99999 // Invalid port

	tempFile := "test_invalid_config.json"
	defer os.Remove(tempFile)

	if err := config.SaveConfig(invalidConfig, tempFile); err != nil {
		t.Fatalf("Failed to save invalid config: %v", err)
	}

	// Try to load invalid config
	_, err := config.LoadConfig(tempFile)
	if err == nil {
		t.Error("Expected error when loading invalid config, but got none")
	}

	t.Logf("Config validation correctly rejected invalid config: %v", err)
}

func TestConfigManagerUpdate(t *testing.T) {
	tempConfigFile := "test_config_update.json"
	defer os.Remove(tempConfigFile)

	// Create initial config
	initialConfig := config.CreateDefaultConfig()
	if err := config.SaveConfig(initialConfig, tempConfigFile); err != nil {
		t.Fatalf("Failed to save initial config: %v", err)
	}

	// Create config manager
	configManager := config.NewManager(tempConfigFile)
	if err := configManager.LoadInitialConfig(); err != nil {
		t.Fatalf("Failed to load initial config: %v", err)
	}

	// Update config programmatically
	err := configManager.UpdateConfig(func(cfg *config.SystemConfig) error {
		cfg.Server.Port = 9090
		cfg.Plugins.Detectors["rate_limit_detector"].Parameters["max_requests"] = float64(150)
		return nil
	})

	if err != nil {
		t.Fatalf("Failed to update config: %v", err)
	}

	// Verify the update
	updatedConfig := configManager.GetConfig()
	if updatedConfig.Server.Port != 9090 {
		t.Errorf("Expected port 9090, got %d", updatedConfig.Server.Port)
	}

	if updatedConfig.Plugins.Detectors["rate_limit_detector"].Parameters["max_requests"] != float64(150) {
		t.Error("Rate limit max_requests was not updated")
	}

	// Verify file was updated
	fileConfig, err := config.LoadConfig(tempConfigFile)
	if err != nil {
		t.Fatalf("Failed to load config from file: %v", err)
	}

	if fileConfig.Server.Port != 9090 {
		t.Error("Config file was not updated")
	}

	t.Log("Config manager update test completed successfully")
}
