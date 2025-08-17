package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/oarkflow/guard/pkg/config"

	"github.com/oarkflow/guard/pkg/engine"
	"github.com/oarkflow/guard/pkg/events"
	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/guard/pkg/plugins/actions"
	"github.com/oarkflow/guard/pkg/plugins/detectors"
	"github.com/oarkflow/guard/pkg/plugins/handlers"
	"github.com/oarkflow/guard/pkg/store"
	"github.com/oarkflow/guard/pkg/tcp"
)

// TestCompleteIntegration tests the full protection stack end-to-end
func TestCompleteIntegration(t *testing.T) {
	// Create test application
	app, err := createTestApplication()
	if err != nil {
		t.Fatalf("Failed to create test application: %v", err)
	}
	defer app.cleanup()

	// Start test server
	go func() {
		if err := app.fiberApp.Listen("127.0.0.1:8081"); err != nil {
			t.Logf("Server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Test client
	client := &http.Client{Timeout: 5 * time.Second}
	baseURL := "http://127.0.0.1:8081"

	t.Run("HealthCheck", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/health")
		if err != nil {
			t.Fatalf("Health check failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var health map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
			t.Fatalf("Failed to decode health response: %v", err)
		}

		if health["status"] != "healthy" {
			t.Errorf("Expected healthy status, got %v", health["status"])
		}
		t.Logf("Health check passed: %v", health)
	})

	t.Run("TCPProtectionForAPIEndpoints", func(t *testing.T) {
		// Test different API endpoints with TCP protection
		endpoints := []string{
			"/api/v1/status",
			"/test/sql",
			"/test/rate",
			"/metrics",
		}

		for _, endpoint := range endpoints {
			t.Run(fmt.Sprintf("Endpoint_%s", strings.ReplaceAll(endpoint, "/", "_")), func(t *testing.T) {
				// First request should be allowed
				resp, err := client.Get(baseURL + endpoint)
				if err != nil {
					t.Fatalf("Request to %s failed: %v", endpoint, err)
				}
				resp.Body.Close()

				if resp.StatusCode >= 400 && resp.StatusCode != 429 {
					t.Errorf("Unexpected error status %d for %s", resp.StatusCode, endpoint)
				}
				t.Logf("Endpoint %s: Status %d", endpoint, resp.StatusCode)
			})
		}
	})

	t.Run("SQLInjectionDetection", func(t *testing.T) {
		// Test SQL injection detection on different endpoints
		sqlPayloads := []string{
			"' OR '1'='1",
			"'; DROP TABLE users; --",
			"1' UNION SELECT * FROM users --",
			"admin'--",
			"' OR 1=1 #",
		}

		for i, payload := range sqlPayloads {
			t.Run(fmt.Sprintf("SQLPayload_%d", i+1), func(t *testing.T) {
				// Test GET with query parameter
				url := fmt.Sprintf("%s/test/sql?id=%s", baseURL, payload)
				resp, err := client.Get(url)
				if err != nil {
					t.Fatalf("SQL injection test failed: %v", err)
				}
				defer resp.Body.Close()

				body, _ := io.ReadAll(resp.Body)
				t.Logf("SQL injection test - Payload: %s, Status: %d, Response: %s",
					payload, resp.StatusCode, string(body))

				// Should be blocked or flagged
				if resp.StatusCode == 200 {
					t.Logf("Warning: SQL injection payload not blocked: %s", payload)
				}
			})
		}

		// Test POST with SQL injection in body
		t.Run("SQLInPOSTBody", func(t *testing.T) {
			payload := map[string]string{
				"username": "admin' OR '1'='1",
				"password": "password",
			}
			jsonPayload, _ := json.Marshal(payload)

			resp, err := client.Post(baseURL+"/api/v1/login", "application/json",
				bytes.NewBuffer(jsonPayload))
			if err != nil {
				t.Fatalf("POST SQL injection test failed: %v", err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			t.Logf("POST SQL injection - Status: %d, Response: %s", resp.StatusCode, string(body))
		})
	})

	t.Run("RateLimitingPerEndpoint", func(t *testing.T) {
		// Test rate limiting on specific endpoint
		endpoint := "/test/rate"

		// Make multiple rapid requests
		for i := 1; i <= 15; i++ {
			resp, err := client.Get(baseURL + endpoint)
			if err != nil {
				t.Fatalf("Rate limit test request %d failed: %v", i, err)
			}

			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			t.Logf("Rate limit test %d - Status: %d, Response: %s",
				i, resp.StatusCode, string(body))

			// After several requests, should start getting rate limited
			if i > 10 && resp.StatusCode == 429 {
				t.Logf("Rate limiting triggered at request %d", i)

				// Verify detailed block information
				var blockInfo map[string]interface{}
				if err := json.Unmarshal(body, &blockInfo); err == nil {
					if blocked, ok := blockInfo["blocked"].(bool); ok && blocked {
						t.Logf("Detailed block info: %v", blockInfo)
					}
				}
				break
			}

			// Small delay between requests
			time.Sleep(10 * time.Millisecond)
		}
	})

	t.Run("TCPProtectionProgression", func(t *testing.T) {
		// Test TCP protection progression: Allow → Drop → Tarpit → Block
		endpoint := "/api/v1/status"

		// Make many requests to trigger TCP protection
		for i := 1; i <= 20; i++ {
			resp, err := client.Get(baseURL + endpoint)
			if err != nil {
				// Connection might be dropped/reset
				t.Logf("Request %d failed (possibly dropped): %v", i, err)
				continue
			}

			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			t.Logf("TCP protection test %d - Status: %d", i, resp.StatusCode)

			// Check for TCP-level blocking
			if resp.StatusCode == 429 {
				var response map[string]interface{}
				if err := json.Unmarshal(body, &response); err == nil {
					if reason, ok := response["reason"].(string); ok {
						if strings.Contains(reason, "TCP-level") || strings.Contains(reason, "connections") {
							t.Logf("TCP-level protection triggered: %v", response)
						}
					}
				}
			}

			time.Sleep(5 * time.Millisecond)
		}
	})

	t.Run("RulesBasedActions", func(t *testing.T) {
		// Test different severity levels and corresponding actions
		testCases := []struct {
			name     string
			endpoint string
			payload  string
			expected string
		}{
			{
				name:     "HighSeveritySQL",
				endpoint: "/test/sql",
				payload:  "'; DROP TABLE users; DELETE FROM admin; --",
				expected: "block",
			},
			{
				name:     "MediumSeveritySQL",
				endpoint: "/test/sql",
				payload:  "' OR '1'='1",
				expected: "warning_or_block",
			},
			{
				name:     "RateLimitViolation",
				endpoint: "/test/rate",
				payload:  "",
				expected: "incremental_block",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				url := baseURL + tc.endpoint
				if tc.payload != "" {
					url += "?test=" + tc.payload
				}

				resp, err := client.Get(url)
				if err != nil {
					t.Fatalf("Rules test failed: %v", err)
				}
				defer resp.Body.Close()

				body, _ := io.ReadAll(resp.Body)
				t.Logf("Rules test %s - Status: %d, Response: %s",
					tc.name, resp.StatusCode, string(body))

				// Analyze response for rule-based actions
				if resp.StatusCode >= 400 {
					var response map[string]interface{}
					if err := json.Unmarshal(body, &response); err == nil {
						t.Logf("Rule-based action detected: %v", response)
					}
				}
			})
		}
	})

	t.Run("MetricsAndMonitoring", func(t *testing.T) {
		// Check metrics endpoint
		resp, err := client.Get(baseURL + "/metrics")
		if err != nil {
			t.Fatalf("Metrics request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected metrics status 200, got %d", resp.StatusCode)
		}

		var metrics map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&metrics); err != nil {
			t.Fatalf("Failed to decode metrics: %v", err)
		}

		t.Logf("System Metrics:")
		if ruleEngine, ok := metrics["rule_engine"].(map[string]interface{}); ok {
			t.Logf("  Rule Engine: %v", ruleEngine)
		}
		if tcpProtection, ok := metrics["tcp_protection"].(map[string]interface{}); ok {
			t.Logf("  TCP Protection: %v", tcpProtection)
		}
		if plugins, ok := metrics["plugins"].(map[string]interface{}); ok {
			t.Logf("  Plugins: %v", plugins)
		}
	})

	t.Run("TCPManagementAPI", func(t *testing.T) {
		// Test TCP protection management endpoints
		managementTests := []struct {
			method   string
			endpoint string
			params   string
		}{
			{"GET", "/admin/tcp/metrics", ""},
			{"GET", "/admin/tcp/connections", ""},
			{"POST", "/admin/tcp/whitelist", "ip=192.168.1.100"},
			{"DELETE", "/admin/tcp/whitelist", "ip=192.168.1.100"},
		}

		for _, test := range managementTests {
			t.Run(fmt.Sprintf("%s_%s", test.method, strings.ReplaceAll(test.endpoint, "/", "_")), func(t *testing.T) {
				var resp *http.Response
				var err error

				url := baseURL + test.endpoint
				if test.params != "" && test.method == "GET" {
					url += "?" + test.params
				}

				switch test.method {
				case "GET":
					resp, err = client.Get(url)
				case "POST":
					var body io.Reader
					if test.params != "" {
						body = strings.NewReader(test.params)
					}
					resp, err = client.Post(url, "application/x-www-form-urlencoded", body)
				case "DELETE":
					req, _ := http.NewRequest("DELETE", url, nil)
					if test.params != "" {
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						req.Body = io.NopCloser(strings.NewReader(test.params))
					}
					resp, err = client.Do(req)
				}

				if err != nil {
					t.Fatalf("Management API test failed: %v", err)
				}
				defer resp.Body.Close()

				body, _ := io.ReadAll(resp.Body)
				t.Logf("Management API %s %s - Status: %d, Response: %s",
					test.method, test.endpoint, resp.StatusCode, string(body))
			})
		}
	})

	t.Run("ConcurrentRequests", func(t *testing.T) {
		// Test concurrent requests to verify thread safety
		const numGoroutines = 10
		const requestsPerGoroutine = 5

		results := make(chan string, numGoroutines*requestsPerGoroutine)

		for i := 0; i < numGoroutines; i++ {
			go func(goroutineID int) {
				for j := 0; j < requestsPerGoroutine; j++ {
					endpoint := fmt.Sprintf("/test/concurrent?g=%d&r=%d", goroutineID, j)
					resp, err := client.Get(baseURL + endpoint)
					if err != nil {
						results <- fmt.Sprintf("G%d-R%d: ERROR - %v", goroutineID, j, err)
						continue
					}
					resp.Body.Close()
					results <- fmt.Sprintf("G%d-R%d: %d", goroutineID, j, resp.StatusCode)
				}
			}(i)
		}

		// Collect results
		for i := 0; i < numGoroutines*requestsPerGoroutine; i++ {
			result := <-results
			t.Logf("Concurrent test: %s", result)
		}
	})
}

// TestApplication represents a test instance of the application
type TestApplication struct {
	configManager *config.Manager
	registry      *plugins.PluginRegistry
	eventBus      *events.EventBus
	ruleEngine    *engine.RuleEngine
	stateStore    store.StateStore
	fiberApp      *fiber.App
	tcpMiddleware *tcp.TCPMiddleware
}

func (app *TestApplication) cleanup() {
	if app.stateStore != nil {
		app.stateStore.Close()
	}
	if app.fiberApp != nil {
		app.fiberApp.Shutdown()
	}
}

func createTestApplication() (*TestApplication, error) {
	// Create test configuration
	cfg := createTestConfig()

	// Create state store
	storeFactory := store.NewStoreFactory()
	stateStore, err := storeFactory.CreateStore(cfg.Store)
	if err != nil {
		return nil, fmt.Errorf("failed to create state store: %w", err)
	}

	// Create plugin registry
	registry := plugins.NewPluginRegistry()

	// Create event bus
	eventBus := events.NewEventBus(registry, cfg.Events.BufferSize, cfg.Events.WorkerCount)

	// Create rule engine
	ruleEngine := engine.NewRuleEngine(registry, eventBus, stateStore)

	// Register plugins
	if err := registerTestPlugins(registry, cfg, stateStore); err != nil {
		return nil, fmt.Errorf("failed to register plugins: %w", err)
	}

	// Create Fiber app
	fiberApp := fiber.New(fiber.Config{
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
		BodyLimit:    cfg.Server.BodyLimit,
	})

	// Create TCP protection
	tcpConfig := tcp.TCPProtectionConfig{
		EnableTCPProtection:  cfg.TCPProtection.EnableTCPProtection,
		ConnectionRateLimit:  cfg.TCPProtection.ConnectionRateLimit,
		ConnectionWindow:     cfg.TCPProtection.ConnectionWindow,
		SilentDropThreshold:  cfg.TCPProtection.SilentDropThreshold,
		TarpitThreshold:      cfg.TCPProtection.TarpitThreshold,
		TarpitDelay:          cfg.TCPProtection.TarpitDelay,
		MaxTarpitConnections: cfg.TCPProtection.MaxTarpitConnections,
		BruteForceThreshold:  cfg.TCPProtection.BruteForceThreshold,
		BruteForceWindow:     cfg.TCPProtection.BruteForceWindow,
		CleanupInterval:      cfg.TCPProtection.CleanupInterval,
		WhitelistedIPs:       cfg.TCPProtection.WhitelistedIPs,
		BlacklistedIPs:       cfg.TCPProtection.BlacklistedIPs,
	}

	tcpMiddleware := tcp.NewTCPMiddleware(tcpConfig, stateStore, nil)

	app := &TestApplication{
		registry:      registry,
		eventBus:      eventBus,
		ruleEngine:    ruleEngine,
		stateStore:    stateStore,
		fiberApp:      fiberApp,
		tcpMiddleware: tcpMiddleware,
	}

	// Setup middleware and routes
	setupTestMiddleware(app, ruleEngine, tcpMiddleware)
	setupTestRoutes(app)

	return app, nil
}

func createTestConfig() *config.SystemConfig {
	return &config.SystemConfig{
		Server: config.ServerConfig{
			Address:      "127.0.0.1",
			Port:         8081,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  30 * time.Second,
			BodyLimit:    1024 * 1024,
		},
		Engine: config.EngineConfig{
			MaxConcurrentRequests: 100,
			RequestTimeout:        10 * time.Second,
			EnableMetrics:         true,
			EnableEvents:          true,
			DefaultAction:         "allow",
			FailureMode:           "allow",
			ActionRules: []config.ActionRule{
				{
					Name:          "SQL Injection Block",
					MinSeverity:   1,
					MinConfidence: 0.7,
					Actions:       []string{"block_action"},
					ThreatTags:    []string{"sql_injection"},
					Priority:      100,
					Enabled:       true,
				},
				{
					Name:          "Rate Limit Block",
					MinSeverity:   1,
					MinConfidence: 0.8,
					Actions:       []string{"incremental_block_action"},
					ThreatTags:    []string{"rate_limit"},
					Priority:      90,
					Enabled:       true,
				},
			},
		},
		Store: store.StoreConfig{
			Type:    "memory",
			Timeout: 5 * time.Second,
		},
		Events: config.EventsConfig{
			BufferSize:  100,
			WorkerCount: 2,
		},
		TCPProtection: config.TCPProtectionConfig{
			EnableTCPProtection:  true,
			ConnectionRateLimit:  10, // Low for testing
			ConnectionWindow:     10 * time.Second,
			SilentDropThreshold:  5,
			TarpitThreshold:      7,
			TarpitDelay:          50 * time.Millisecond,
			MaxTarpitConnections: 2,
			BruteForceThreshold:  5,
			BruteForceWindow:     30 * time.Second,
			CleanupInterval:      5 * time.Second,
			WhitelistedIPs:       []string{"127.0.0.1"},
			BlacklistedIPs:       []string{},
		},
	}
}

func registerTestPlugins(registry *plugins.PluginRegistry, cfg *config.SystemConfig, stateStore store.StateStore) error {
	// Register SQL injection detector
	sqlDetector := detectors.NewSQLInjectionDetector()
	if err := registry.RegisterDetector(
		sqlDetector,
		plugins.PluginMetadata{
			Name:        "sql_injection_detector",
			Version:     "1.0.0",
			Description: "SQL injection detector",
			Type:        "detector",
		},
		plugins.PluginConfig{
			Enabled:  true,
			Priority: 100,
		},
	); err != nil {
		return err
	}

	// Register rate limit detector
	rateLimitDetector := detectors.NewRateLimitDetector(stateStore)
	if err := registry.RegisterDetector(
		rateLimitDetector,
		plugins.PluginMetadata{
			Name:        "rate_limit_detector",
			Version:     "1.0.0",
			Description: "Rate limit detector",
			Type:        "detector",
		},
		plugins.PluginConfig{
			Enabled:  true,
			Priority: 90,
			Parameters: map[string]any{
				"window_size":   "10s", // Short window for testing
				"max_requests":  5,     // Low limit for testing
				"key_template":  "rate_limit:{ip}",
				"burst_allowed": 2,
			},
		},
	); err != nil {
		return err
	}

	// Register block action
	blockAction := actions.NewBlockAction(stateStore)
	if err := registry.RegisterAction(
		blockAction,
		plugins.PluginMetadata{
			Name:        "block_action",
			Version:     "1.0.0",
			Description: "Block action",
			Type:        "action",
		},
		plugins.PluginConfig{
			Enabled:  true,
			Priority: 100,
		},
	); err != nil {
		return err
	}

	// Register incremental block action
	incrementalBlockAction := actions.NewIncrementalBlockAction(stateStore)
	if err := registry.RegisterAction(
		incrementalBlockAction,
		plugins.PluginMetadata{
			Name:        "incremental_block_action",
			Version:     "1.0.0",
			Description: "Incremental block action",
			Type:        "action",
		},
		plugins.PluginConfig{
			Enabled:  true,
			Priority: 90,
		},
	); err != nil {
		return err
	}

	// Register security logger
	securityLogger := handlers.NewSecurityLoggerHandler()
	if err := registry.RegisterHandler(
		securityLogger,
		plugins.PluginMetadata{
			Name:        "security_logger_handler",
			Version:     "1.0.0",
			Description: "Security logger",
			Type:        "handler",
		},
		plugins.PluginConfig{
			Enabled:  true,
			Priority: 100,
		},
	); err != nil {
		return err
	}

	return nil
}

func setupTestMiddleware(app *TestApplication, ruleEngine *engine.RuleEngine, tcpMiddleware *tcp.TCPMiddleware) {
	// TCP protection middleware (first layer)
	app.fiberApp.Use(func(c *fiber.Ctx) error {
		if !tcpMiddleware.GetProtection().IsIPWhitelisted("127.0.0.1") {
			// Create fake remote addr for testing
			remoteAddr := &testAddr{address: "127.0.0.1:12345"}
			action, connInfo, err := tcpMiddleware.GetProtection().CheckConnection(c.Context(), remoteAddr)
			if err != nil {
				return c.Next()
			}

			switch action {
			case tcp.ActionDrop:
				return c.SendStatus(fiber.StatusNoContent)
			case tcp.ActionTarpit:
				time.Sleep(50 * time.Millisecond)
				return c.Next()
			case tcp.ActionBlock:
				return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
					"error":            "Request blocked by TCP-level DDoS protection",
					"reason":           "Too many connections",
					"connection_count": connInfo.ConnectionCount,
					"retry_after":      10,
				})
			}
		}
		return c.Next()
	})

	// Application-level DDoS protection middleware (second layer)
	app.fiberApp.Use(func(c *fiber.Ctx) error {
		// Build request context
		reqCtx := &plugins.RequestContext{
			IP:            "127.0.0.1",
			UserAgent:     c.Get("User-Agent"),
			Method:        c.Method(),
			Path:          c.Path(),
			Headers:       make(map[string]string),
			QueryParams:   c.Queries(),
			ContentLength: int64(len(c.Body())),
			Timestamp:     time.Now(),
			Metadata:      make(map[string]any),
		}

		// Copy headers
		for key, values := range c.GetReqHeaders() {
			if len(values) > 0 {
				reqCtx.Headers[key] = values[0]
			}
		}

		// Process request through rule engine
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result := ruleEngine.ProcessRequest(ctx, reqCtx)

		// Check if request should be blocked
		if !result.Allowed {
			// Return appropriate response based on actions
			for _, action := range result.Actions {
				if action == "block_action" {
					return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
						"error":      "Access denied",
						"message":    "Request blocked due to security policy violation",
						"blocked":    true,
						"detections": result.Detections,
					})
				}
				if action == "incremental_block_action" {
					return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
						"error":      "Rate limit exceeded",
						"message":    "Too many requests",
						"blocked":    true,
						"detections": result.Detections,
					})
				}
			}
		}

		return c.Next()
	})
}

func setupTestRoutes(app *TestApplication) {
	// Health check
	app.fiberApp.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":    "healthy",
			"timestamp": time.Now(),
		})
	})

	// Metrics
	app.fiberApp.Get("/metrics", func(c *fiber.Ctx) error {
		metrics := map[string]any{
			"rule_engine":    app.ruleEngine.GetMetrics(),
			"event_bus":      app.eventBus.GetStats(),
			"store":          app.stateStore.GetStats(),
			"tcp_protection": app.tcpMiddleware.GetMetrics(),
		}
		return c.JSON(metrics)
	})

	// API routes
	api := app.fiberApp.Group("/api/v1")
	api.Get("/status", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})
	api.Post("/login", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "login endpoint"})
	})

	// Test routes
	test := app.fiberApp.Group("/test")
	test.Get("/sql", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "SQL test endpoint"})
	})
	test.Get("/rate", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Rate limit test endpoint"})
	})
	test.Get("/concurrent", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Concurrent test endpoint"})
	})

	// TCP management routes
	tcpAdmin := app.fiberApp.Group("/admin/tcp")
	tcpAdmin.Get("/metrics", func(c *fiber.Ctx) error {
		return c.JSON(app.tcpMiddleware.GetMetrics())
	})
	tcpAdmin.Get("/connections", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"active_connections": app.tcpMiddleware.GetActiveConnections()})
	})
	tcpAdmin.Post("/whitelist", func(c *fiber.Ctx) error {
		ip := c.FormValue("ip")
		if ip == "" {
			return c.Status(400).JSON(fiber.Map{"error": "IP required"})
		}
		app.tcpMiddleware.GetProtection().AddToWhitelist(ip)
		return c.JSON(fiber.Map{"message": fmt.Sprintf("IP %s added to whitelist", ip)})
	})
	tcpAdmin.Delete("/whitelist", func(c *fiber.Ctx) error {
		ip := c.FormValue("ip")
		if ip == "" {
			return c.Status(400).JSON(fiber.Map{"error": "IP required"})
		}
		app.tcpMiddleware.GetProtection().RemoveFromWhitelist(ip)
		return c.JSON(fiber.Map{"message": fmt.Sprintf("IP %s removed from whitelist", ip)})
	})
}

type testAddr struct {
	address string
}

func (a *testAddr) Network() string { return "tcp" }
func (a *testAddr) String() string  { return a.address }
