package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/oarkflow/guard/pkg/config"
	"github.com/oarkflow/log"

	"github.com/oarkflow/guard/pkg/engine"
	"github.com/oarkflow/guard/pkg/events"
	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/guard/pkg/plugins/actions"
	"github.com/oarkflow/guard/pkg/plugins/detectors"
	"github.com/oarkflow/guard/pkg/plugins/handlers"
	"github.com/oarkflow/guard/pkg/store"
)

func main() {
	fmt.Println("🛡️  DDoS Protection System v2.0 - Architecture Demo")
	fmt.Println(strings.Repeat("=", 60))

	// Create default configuration
	cfg := config.CreateDefaultConfig()
	fmt.Printf("✅ Configuration loaded with %d detector plugins\n", len(cfg.Plugins.Detectors))
	fmt.Printf("✅ Default configuration has %d action rules\n", len(cfg.Engine.ActionRules))

	// Create state store
	storeFactory := store.NewStoreFactory()
	stateStore, err := storeFactory.CreateStore(cfg.Store)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create state store")
	}
	fmt.Printf("✅ State store created: %s\n", cfg.Store.Type)

	// Create plugin registry
	registry := plugins.NewPluginRegistry()
	fmt.Println("✅ Plugin registry created")

	// Create event bus
	eventBus := events.NewEventBus(registry, cfg.Events.BufferSize, cfg.Events.WorkerCount)
	fmt.Printf("✅ Event bus created with %d workers\n", cfg.Events.WorkerCount)

	// Create rule engine
	ruleEngine := engine.NewRuleEngine(registry, eventBus, stateStore)
	fmt.Println("✅ Rule engine created")

	// Register plugins
	fmt.Println("\n📦 Registering plugins...")

	// Register SQL injection detector
	sqlDetector := detectors.NewSQLInjectionDetector()
	err = registry.RegisterDetector(
		sqlDetector,
		plugins.PluginMetadata{
			Name:        sqlDetector.Name(),
			Version:     sqlDetector.Version(),
			Description: sqlDetector.Description(),
			Type:        "detector",
			Author:      "System",
		},
		cfg.Plugins.Detectors["sql_injection_detector"],
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to register SQL detector")
	}
	fmt.Printf("  ✅ %s v%s registered\n", sqlDetector.Name(), sqlDetector.Version())

	// Register rate limit detector
	rateLimitDetector := detectors.NewRateLimitDetector(stateStore)
	err = registry.RegisterDetector(
		rateLimitDetector,
		plugins.PluginMetadata{
			Name:        rateLimitDetector.Name(),
			Version:     rateLimitDetector.Version(),
			Description: rateLimitDetector.Description(),
			Type:        "detector",
			Author:      "System",
		},
		cfg.Plugins.Detectors["rate_limit_detector"],
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to register rate limit detector")
	}
	fmt.Printf("  ✅ %s v%s registered\n", rateLimitDetector.Name(), rateLimitDetector.Version())

	// Register all action plugins
	blockAction := actions.NewBlockAction(stateStore)
	err = registry.RegisterAction(
		blockAction,
		plugins.PluginMetadata{
			Name:        blockAction.Name(),
			Version:     blockAction.Version(),
			Description: blockAction.Description(),
			Type:        "action",
			Author:      "System",
		},
		plugins.PluginConfig{Enabled: true, Priority: 100, Parameters: map[string]interface{}{}},
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to register block action")
	}
	fmt.Printf("  ✅ %s v%s registered\n", blockAction.Name(), blockAction.Version())

	// Register incremental block action
	incBlockAction := actions.NewIncrementalBlockAction(stateStore)
	err = registry.RegisterAction(
		incBlockAction,
		plugins.PluginMetadata{
			Name:        incBlockAction.Name(),
			Version:     incBlockAction.Version(),
			Description: incBlockAction.Description(),
			Type:        "action",
			Author:      "System",
		},
		plugins.PluginConfig{Enabled: true, Priority: 90, Parameters: map[string]interface{}{}},
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to register incremental block action")
	}
	fmt.Printf("  ✅ %s v%s registered\n", incBlockAction.Name(), incBlockAction.Version())

	// Register suspension action
	suspensionAction := actions.NewSuspensionAction(stateStore)
	err = registry.RegisterAction(
		suspensionAction,
		plugins.PluginMetadata{
			Name:        suspensionAction.Name(),
			Version:     suspensionAction.Version(),
			Description: suspensionAction.Description(),
			Type:        "action",
			Author:      "System",
		},
		plugins.PluginConfig{Enabled: true, Priority: 80, Parameters: map[string]interface{}{}},
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to register suspension action")
	}
	fmt.Printf("  ✅ %s v%s registered\n", suspensionAction.Name(), suspensionAction.Version())

	// Register account suspend action
	accountSuspendAction := actions.NewAccountSuspendAction(stateStore)
	err = registry.RegisterAction(
		accountSuspendAction,
		plugins.PluginMetadata{
			Name:        accountSuspendAction.Name(),
			Version:     accountSuspendAction.Version(),
			Description: accountSuspendAction.Description(),
			Type:        "action",
			Author:      "System",
		},
		plugins.PluginConfig{Enabled: true, Priority: 70, Parameters: map[string]interface{}{}},
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to register account suspend action")
	}
	fmt.Printf("  ✅ %s v%s registered\n", accountSuspendAction.Name(), accountSuspendAction.Version())

	// Register warning action
	warningAction := actions.NewWarningAction(stateStore)
	err = registry.RegisterAction(
		warningAction,
		plugins.PluginMetadata{
			Name:        warningAction.Name(),
			Version:     warningAction.Version(),
			Description: warningAction.Description(),
			Type:        "action",
			Author:      "System",
		},
		plugins.PluginConfig{Enabled: true, Priority: 60, Parameters: map[string]interface{}{}},
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to register warning action")
	}
	fmt.Printf("  ✅ %s v%s registered\n", warningAction.Name(), warningAction.Version())

	// Register security logger handler
	securityLogger := handlers.NewSecurityLoggerHandler()
	err = registry.RegisterHandler(
		securityLogger,
		plugins.PluginMetadata{
			Name:        securityLogger.Name(),
			Version:     "1.0.0",
			Description: "Logs security events to file",
			Type:        "handler",
			Author:      "System",
		},
		cfg.Plugins.Handlers["security_logger_handler"],
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to register security logger")
	}
	fmt.Printf("  ✅ %s registered\n", securityLogger.Name())

	// Demonstrate configurable action rules
	fmt.Println("\n⚙️  Demonstrating configurable action rules...")
	fmt.Printf("Current action rules (%d total):\n", len(cfg.Engine.ActionRules))
	for i, rule := range cfg.Engine.ActionRules {
		status := "✅"
		if !rule.Enabled {
			status = "❌"
		}
		fmt.Printf("  %s %d. %s (Priority: %d, Severity: %d+, Confidence: %.1f+)\n",
			status, i+1, rule.Name, rule.Priority, rule.MinSeverity, rule.MinConfidence)
		if len(rule.ThreatTags) > 0 {
			fmt.Printf("      Tags: %v\n", rule.ThreatTags)
		}
		fmt.Printf("      Actions: %v\n", rule.Actions)
	}

	// Test loading custom configuration
	fmt.Println("\n📄 Testing custom configuration loading...")
	customCfg, err := config.LoadConfig("custom_rules_config.json")
	if err != nil {
		fmt.Printf("⚠️  Could not load custom config (using defaults): %v\n", err)
	} else {
		fmt.Printf("✅ Custom configuration loaded with %d action rules\n", len(customCfg.Engine.ActionRules))

		// Update the rule engine with custom rules
		ruleEngine.UpdateConfig(customCfg.Engine)
		fmt.Println("✅ Rule engine updated with custom action rules")

		fmt.Println("Custom action rules:")
		for i, rule := range customCfg.Engine.ActionRules {
			status := "✅"
			if !rule.Enabled {
				status = "❌"
			}
			fmt.Printf("  %s %d. %s (Priority: %d)\n", status, i+1, rule.Name, rule.Priority)
		}
	}

	// Demonstrate the system with test requests
	fmt.Println("\n🧪 Testing the system with sample requests...")

	testRequests := []plugins.RequestContext{
		{
			IP:          "192.168.1.100",
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			Method:      "GET",
			Path:        "/api/users",
			Headers:     map[string]string{"Accept": "application/json"},
			QueryParams: map[string]string{},
			Timestamp:   time.Now(),
			UserID:      "user123",
		},
		{
			IP:          "10.0.0.1",
			UserAgent:   "curl/7.68.0",
			Method:      "GET",
			Path:        "/api/users",
			Headers:     map[string]string{"Accept": "*/*"},
			QueryParams: map[string]string{"id": "1' OR '1'='1"},
			Timestamp:   time.Now(),
			UserID:      "user456",
		},
		{
			IP:          "192.168.1.200",
			UserAgent:   "AttackBot/1.0",
			Method:      "POST",
			Path:        "/login",
			Headers:     map[string]string{"Content-Type": "application/json"},
			QueryParams: map[string]string{},
			Timestamp:   time.Now(),
			UserID:      "user789",
		},
		{
			IP:          "192.168.1.300",
			UserAgent:   "Mozilla/5.0",
			Method:      "GET",
			Path:        "/api/data",
			Headers:     map[string]string{"Accept": "application/json"},
			QueryParams: map[string]string{"query": "SELECT * FROM users"},
			Timestamp:   time.Now(),
			UserID:      "user999",
		},
	}

	for i, req := range testRequests {
		fmt.Printf("\n--- Test Request %d ---\n", i+1)
		fmt.Printf("IP: %s, Path: %s, Query: %v\n", req.IP, req.Path, req.QueryParams)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		result := ruleEngine.ProcessRequest(ctx, &req)
		cancel()

		fmt.Printf("Result: Allowed=%t, Detections=%d, Actions=%d\n",
			result.Allowed, len(result.Detections), len(result.Actions))

		for _, detection := range result.Detections {
			if detection.Threat {
				fmt.Printf("  🚨 Threat detected: %s (Confidence: %.2f, Severity: %d)\n",
					detection.Details, detection.Confidence, detection.Severity)
			}
		}

		for _, action := range result.Actions {
			fmt.Printf("  ⚡ Action executed: %s\n", action)
		}

		fmt.Printf("  ⏱️  Processing time: %v\n", result.ProcessTime)
	}

	// Show system metrics
	fmt.Println("\n📊 System Metrics:")
	metrics := ruleEngine.GetMetrics()
	fmt.Printf("  Total Requests: %d\n", metrics.TotalRequests)
	fmt.Printf("  Threats Detected: %d\n", metrics.ThreatsDetected)
	fmt.Printf("  Actions Executed: %d\n", metrics.ActionsExecuted)
	fmt.Printf("  Events Published: %d\n", metrics.EventsPublished)
	fmt.Printf("  Average Process Time: %v\n", metrics.AverageProcessTime)

	// Show plugin metrics
	fmt.Println("\n🔌 Plugin Metrics:")
	for _, detector := range registry.GetAllDetectors() {
		metrics := detector.GetMetrics()
		fmt.Printf("  %s: %v\n", detector.Name(), metrics)
	}

	for _, action := range registry.GetAllActions() {
		metrics := action.GetMetrics()
		fmt.Printf("  %s: %v\n", action.Name(), metrics)
	}

	// Show store stats
	fmt.Println("\n💾 Store Statistics:")
	storeStats := stateStore.GetStats()
	for key, value := range storeStats {
		fmt.Printf("  %s: %v\n", key, value)
	}

	// Show event bus stats
	fmt.Println("\n📡 Event Bus Statistics:")
	eventStats := eventBus.GetStats()
	for key, value := range eventStats {
		fmt.Printf("  %s: %v\n", key, value)
	}

	// Demonstrate rate limiting by making multiple requests
	fmt.Println("\n🔄 Testing rate limiting with rapid requests...")
	rapidReq := plugins.RequestContext{
		IP:          "192.168.1.200",
		UserAgent:   "TestClient/1.0",
		Method:      "GET",
		Path:        "/api/test",
		Headers:     map[string]string{},
		QueryParams: map[string]string{},
		Timestamp:   time.Now(),
		UserID:      "testuser",
	}

	allowedCount := 0
	blockedCount := 0

	for i := 0; i < 150; i++ { // Exceed the default limit of 100
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		result := ruleEngine.ProcessRequest(ctx, &rapidReq)
		cancel()

		if result.Allowed {
			allowedCount++
		} else {
			blockedCount++
		}

		if i%25 == 0 {
			fmt.Printf("  Request %d: Allowed=%t\n", i+1, result.Allowed)
		}
	}

	fmt.Printf("Rate limiting test results: %d allowed, %d blocked\n", allowedCount, blockedCount)

	// Cleanup
	fmt.Println("\n🧹 Cleaning up...")
	if err := ruleEngine.Shutdown(); err != nil {
		log.Error().Err(err).Msg("Error during shutdown")
	}

	fmt.Println("\n✅ Demo completed successfully!")
	fmt.Println("\nKey architectural improvements demonstrated:")
	fmt.Println("  • Plugin-based architecture with dynamic loading")
	fmt.Println("  • Event-driven system with asynchronous processing")
	fmt.Println("  • Distributed state store with multiple backend support")
	fmt.Println("  • Comprehensive metrics and monitoring")
	fmt.Println("  • Configurable and extensible design")
	fmt.Println("  • Configurable action selection with custom severity/confidence rules")
	fmt.Println("  • Priority-based rule evaluation system")
	fmt.Println("  • Tag-based threat filtering and exclusion")
}
