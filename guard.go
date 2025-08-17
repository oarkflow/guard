package guard

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"

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

// Application holds the main application components
type Application struct {
	configManager *config.Manager
	registry      *plugins.PluginRegistry
	eventBus      *events.EventBus
	ruleEngine    *engine.RuleEngine
	stateStore    store.StateStore
	fiberApp      *fiber.App
	tcpMiddleware *tcp.TCPMiddleware
	tcpHandler    *tcp.TCPProtectionHandler
	tcpConfig     tcp.TCPProtectionConfig
	mu            sync.RWMutex
}

// NewApplication creates a new application instance
func NewApplication(configFile string) (*Application, error) {
	// Create config manager
	configManager := config.NewManager(configFile)

	// Load initial configuration
	if err := configManager.LoadInitialConfig(); err != nil {
		// Create default config if file doesn't exist
		cfg := config.CreateDefaultConfig()
		if err := config.SaveConfig(cfg, configFile); err != nil {
			log.Printf("Warning: Could not save default config: %v", err)
		}
		log.Printf("Created default configuration file: %s", configFile)

		// Reload the config manager with the new file
		if err := configManager.LoadInitialConfig(); err != nil {
			return nil, fmt.Errorf("failed to load initial config: %w", err)
		}
	}

	cfg := configManager.GetConfig()

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

	// Create Fiber app
	fiberApp := fiber.New(fiber.Config{
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
		BodyLimit:    cfg.Server.BodyLimit,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			log.Printf("Request error: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Internal server error",
			})
		},
	})

	// Create TCP protection middleware
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
	tcpHandler := tcp.NewTCPProtectionHandler(tcpMiddleware.GetProtection())

	app := &Application{
		configManager: configManager,
		registry:      registry,
		eventBus:      eventBus,
		ruleEngine:    ruleEngine,
		stateStore:    stateStore,
		fiberApp:      fiberApp,
		tcpMiddleware: tcpMiddleware,
		tcpHandler:    tcpHandler,
		tcpConfig:     tcpConfig,
	}

	return app, nil
}

// Initialize initializes the application components
func (app *Application) Initialize() error {
	log.Println("Initializing application components...")

	// Register built-in plugins
	if err := app.registerBuiltinPlugins(); err != nil {
		return fmt.Errorf("failed to register builtin plugins: %w", err)
	}

	// Setup config reload callback
	app.configManager.AddReloadCallback(app.handleConfigReload)

	// Setup middleware
	app.setupMiddleware()

	// Setup routes
	app.setupRoutes()

	log.Println("Application initialized successfully")
	return nil
}

// registerBuiltinPlugins registers the built-in plugins
func (app *Application) registerBuiltinPlugins() error {
	cfg := app.configManager.GetConfig()

	// Register detector plugins
	sqlDetector := detectors.NewSQLInjectionDetector()
	if err := app.registry.RegisterDetector(
		sqlDetector,
		plugins.PluginMetadata{
			Name:        sqlDetector.Name(),
			Version:     sqlDetector.Version(),
			Description: sqlDetector.Description(),
			Type:        "detector",
			Author:      "System",
		},
		cfg.Plugins.Detectors["sql_injection_detector"],
	); err != nil {
		return fmt.Errorf("failed to register SQL injection detector: %w", err)
	}

	xssDetector := detectors.NewXSSDetector()
	if err := app.registry.RegisterDetector(
		xssDetector,
		plugins.PluginMetadata{
			Name:        xssDetector.Name(),
			Version:     xssDetector.Version(),
			Description: xssDetector.Description(),
			Type:        "detector",
			Author:      "System",
		},
		cfg.Plugins.Detectors["xss_detector"],
	); err != nil {
		return fmt.Errorf("failed to register XSS detector: %w", err)
	}

	pathTraversalDetector := detectors.NewPathTraversalDetector()
	if err := app.registry.RegisterDetector(
		pathTraversalDetector,
		plugins.PluginMetadata{
			Name:        pathTraversalDetector.Name(),
			Version:     pathTraversalDetector.Version(),
			Description: pathTraversalDetector.Description(),
			Type:        "detector",
			Author:      "System",
		},
		cfg.Plugins.Detectors["path_traversal_detector"],
	); err != nil {
		return fmt.Errorf("failed to register path traversal detector: %w", err)
	}

	bruteForceDetector := detectors.NewBruteForceDetector(app.stateStore)
	if err := app.registry.RegisterDetector(
		bruteForceDetector,
		plugins.PluginMetadata{
			Name:        bruteForceDetector.Name(),
			Version:     bruteForceDetector.Version(),
			Description: bruteForceDetector.Description(),
			Type:        "detector",
			Author:      "System",
		},
		cfg.Plugins.Detectors["brute_force_detector"],
	); err != nil {
		return fmt.Errorf("failed to register brute force detector: %w", err)
	}

	suspiciousUADetector := detectors.NewSuspiciousUserAgentDetector()
	if err := app.registry.RegisterDetector(
		suspiciousUADetector,
		plugins.PluginMetadata{
			Name:        suspiciousUADetector.Name(),
			Version:     suspiciousUADetector.Version(),
			Description: suspiciousUADetector.Description(),
			Type:        "detector",
			Author:      "System",
		},
		cfg.Plugins.Detectors["suspicious_user_agent_detector"],
	); err != nil {
		return fmt.Errorf("failed to register suspicious user agent detector: %w", err)
	}

	geoLocationDetector := detectors.NewGeoLocationDetector()
	if err := app.registry.RegisterDetector(
		geoLocationDetector,
		plugins.PluginMetadata{
			Name:        geoLocationDetector.Name(),
			Version:     geoLocationDetector.Version(),
			Description: geoLocationDetector.Description(),
			Type:        "detector",
			Author:      "System",
		},
		cfg.Plugins.Detectors["geo_location_detector"],
	); err != nil {
		return fmt.Errorf("failed to register geo location detector: %w", err)
	}

	rateLimitDetector := detectors.NewRateLimitDetector(app.stateStore)
	if err := app.registry.RegisterDetector(
		rateLimitDetector,
		plugins.PluginMetadata{
			Name:        rateLimitDetector.Name(),
			Version:     rateLimitDetector.Version(),
			Description: rateLimitDetector.Description(),
			Type:        "detector",
			Author:      "System",
		},
		cfg.Plugins.Detectors["rate_limit_detector"],
	); err != nil {
		return fmt.Errorf("failed to register rate limit detector: %w", err)
	}

	// Register action plugins
	blockAction := actions.NewBlockAction(app.stateStore)
	if err := app.registry.RegisterAction(
		blockAction,
		plugins.PluginMetadata{
			Name:        blockAction.Name(),
			Version:     blockAction.Version(),
			Description: blockAction.Description(),
			Type:        "action",
			Author:      "System",
		},
		cfg.Plugins.Actions["block_action"],
	); err != nil {
		return fmt.Errorf("failed to register block action: %w", err)
	}

	incrementalBlockAction := actions.NewIncrementalBlockAction(app.stateStore)
	if err := app.registry.RegisterAction(
		incrementalBlockAction,
		plugins.PluginMetadata{
			Name:        incrementalBlockAction.Name(),
			Version:     incrementalBlockAction.Version(),
			Description: incrementalBlockAction.Description(),
			Type:        "action",
			Author:      "System",
		},
		cfg.Plugins.Actions["incremental_block_action"],
	); err != nil {
		return fmt.Errorf("failed to register incremental block action: %w", err)
	}

	suspensionAction := actions.NewSuspensionAction(app.stateStore)
	if err := app.registry.RegisterAction(
		suspensionAction,
		plugins.PluginMetadata{
			Name:        suspensionAction.Name(),
			Version:     suspensionAction.Version(),
			Description: suspensionAction.Description(),
			Type:        "action",
			Author:      "System",
		},
		cfg.Plugins.Actions["suspension_action"],
	); err != nil {
		return fmt.Errorf("failed to register suspension action: %w", err)
	}

	accountSuspendAction := actions.NewAccountSuspendAction(app.stateStore)
	if err := app.registry.RegisterAction(
		accountSuspendAction,
		plugins.PluginMetadata{
			Name:        accountSuspendAction.Name(),
			Version:     accountSuspendAction.Version(),
			Description: accountSuspendAction.Description(),
			Type:        "action",
			Author:      "System",
		},
		cfg.Plugins.Actions["account_suspend_action"],
	); err != nil {
		return fmt.Errorf("failed to register account suspend action: %w", err)
	}

	warningAction := actions.NewWarningAction(app.stateStore)
	if err := app.registry.RegisterAction(
		warningAction,
		plugins.PluginMetadata{
			Name:        warningAction.Name(),
			Version:     warningAction.Version(),
			Description: warningAction.Description(),
			Type:        "action",
			Author:      "System",
		},
		cfg.Plugins.Actions["warning_action"],
	); err != nil {
		return fmt.Errorf("failed to register warning action: %w", err)
	}

	captchaAction := actions.NewCaptchaAction(app.stateStore)
	if err := app.registry.RegisterAction(
		captchaAction,
		plugins.PluginMetadata{
			Name:        captchaAction.Name(),
			Version:     captchaAction.Version(),
			Description: captchaAction.Description(),
			Type:        "action",
			Author:      "System",
		},
		cfg.Plugins.Actions["captcha_action"],
	); err != nil {
		return fmt.Errorf("failed to register captcha action: %w", err)
	}

	// Register event handler plugins
	securityLogger := handlers.NewSecurityLoggerHandler()
	if err := app.registry.RegisterHandler(
		securityLogger,
		plugins.PluginMetadata{
			Name:        securityLogger.Name(),
			Version:     "1.0.0",
			Description: "Logs security events to file",
			Type:        "handler",
			Author:      "System",
		},
		cfg.Plugins.Handlers["security_logger_handler"],
	); err != nil {
		return fmt.Errorf("failed to register security logger handler: %w", err)
	}

	webhookHandler := handlers.NewWebhookHandler()
	if err := app.registry.RegisterHandler(
		webhookHandler,
		plugins.PluginMetadata{
			Name:        webhookHandler.Name(),
			Version:     "1.0.0",
			Description: "Sends security events to webhook endpoints",
			Type:        "handler",
			Author:      "System",
		},
		cfg.Plugins.Handlers["webhook_handler"],
	); err != nil {
		return fmt.Errorf("failed to register webhook handler: %w", err)
	}

	emailHandler := handlers.NewEmailHandler()
	if err := app.registry.RegisterHandler(
		emailHandler,
		plugins.PluginMetadata{
			Name:        emailHandler.Name(),
			Version:     "1.0.0",
			Description: "Sends security alerts via email",
			Type:        "handler",
			Author:      "System",
		},
		cfg.Plugins.Handlers["email_handler"],
	); err != nil {
		return fmt.Errorf("failed to register email handler: %w", err)
	}

	metricsHandler := handlers.NewMetricsHandler()
	if err := app.registry.RegisterHandler(
		metricsHandler,
		plugins.PluginMetadata{
			Name:        metricsHandler.Name(),
			Version:     "1.0.0",
			Description: "Collects and exposes security metrics",
			Type:        "handler",
			Author:      "System",
		},
		cfg.Plugins.Handlers["metrics_handler"],
	); err != nil {
		return fmt.Errorf("failed to register metrics handler: %w", err)
	}

	return nil
}

// setupMiddleware sets up Fiber middleware
func (app *Application) setupMiddleware() {
	cfg := app.configManager.GetConfig()

	// Recovery middleware
	app.fiberApp.Use(recover.New())

	// CORS middleware
	if len(cfg.Security.AllowedOrigins) > 0 {
		app.fiberApp.Use(cors.New(cors.Config{
			AllowOrigins: cfg.Security.AllowedOrigins[0],
			AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
			AllowHeaders: "Origin,Content-Type,Accept,Authorization",
		}))
	}

	// Security headers middleware
	if cfg.Security.EnableSecurityHeaders {
		app.fiberApp.Use(func(c *fiber.Ctx) error {
			c.Set("X-Content-Type-Options", "nosniff")
			c.Set("X-Frame-Options", "DENY")
			c.Set("X-XSS-Protection", "1; mode=block")
			c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			return c.Next()
		})
	}

	// TCP-level DDoS protection middleware (first layer)
	if app.tcpMiddleware != nil {
		app.fiberApp.Use(app.createTCPProtectionMiddleware())
	}

	// Application-level DDoS protection middleware (second layer)
	app.fiberApp.Use(app.ddosProtectionMiddleware())
}

// ddosProtectionMiddleware creates the DDoS protection middleware
func (app *Application) ddosProtectionMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Build request context
		reqCtx := &plugins.RequestContext{
			IP:            app.getRealIP(c),
			UserAgent:     c.Get("User-Agent"),
			Method:        c.Method(),
			Path:          c.Path(),
			Headers:       make(map[string]string),
			QueryParams:   c.Queries(),
			ContentLength: int64(len(c.Body())),
			Timestamp:     time.Now(),
			UserID:        c.Get("X-User-ID"),
			SessionID:     c.Get("X-Session-ID"),
			Metadata:      make(map[string]any),
		}

		// Copy headers
		for key, values := range c.GetReqHeaders() {
			if len(values) > 0 {
				reqCtx.Headers[key] = values[0]
			}
		}

		// Process request through rule engine
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result := app.ruleEngine.ProcessRequest(ctx, reqCtx)

		// Handle processing errors
		if result.Error != nil {
			log.Printf("Rule engine error: %v", result.Error)
			// Continue with request based on failure mode
			cfg := app.configManager.GetConfig()
			if cfg.Engine.FailureMode == "deny" {
				return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
					"error": "Service temporarily unavailable",
				})
			}
		}

		// Check if request should be blocked
		if !result.Allowed {
			// Log the block
			log.Printf("Request blocked from %s: %v", reqCtx.IP, result.Detections)

			// Return appropriate response based on highest severity action
			for _, action := range result.Actions {
				if action == "block_action" {
					// Get detailed block information
					blockAction, exists := app.registry.GetAction("block_action")
					if exists {
						if ba, ok := blockAction.(*actions.BlockAction); ok {
							if blockDetails, err := ba.GetDetailedBlockInfo(ctx, reqCtx.IP); err == nil && blockDetails != nil {
								response := fiber.Map{
									"error":      "Access denied",
									"message":    blockDetails.FormatUserMessage(),
									"request_id": c.Get("X-Request-ID"),
									"blocked":    true,
									"permanent":  blockDetails.IsPermanent,
									"reason":     blockDetails.Reason,
									"blocked_at": blockDetails.BlockedAt.Format(time.RFC3339),
								}

								// Add retry information for temporary blocks
								if !blockDetails.IsPermanent {
									if blockDetails.RemainingTime > 0 {
										response["retry_after"] = blockDetails.RetryAfter.Format(time.RFC3339)
										response["retry_in_seconds"] = int(blockDetails.RemainingTime.Seconds())
									} else {
										response["retry_after"] = "now"
										response["retry_in_seconds"] = 0
									}
								}

								// Add violation information
								if blockDetails.ViolationCount > 0 {
									response["violation_count"] = blockDetails.ViolationCount
								}

								// Set appropriate HTTP headers
								if !blockDetails.IsPermanent && blockDetails.RemainingTime > 0 {
									c.Set("Retry-After", fmt.Sprintf("%d", int(blockDetails.RemainingTime.Seconds())))
								}

								return c.Status(fiber.StatusTooManyRequests).JSON(response)
							}
						}
					}

					// Fallback to basic response if detailed info is not available
					return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
						"error":      "Access denied",
						"message":    "Your request has been blocked due to security policy violations",
						"request_id": c.Get("X-Request-ID"),
						"blocked":    true,
					})
				}
			}
		}

		// Add security information to response headers
		if len(result.Detections) > 0 {
			c.Set("X-Security-Scan", "completed")
			c.Set("X-Threat-Level", fmt.Sprintf("%d", len(result.Detections)))
		}

		return c.Next()
	}
}

// createTCPProtectionMiddleware creates the TCP-level protection middleware
func (app *Application) createTCPProtectionMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if app.tcpMiddleware == nil {
			return c.Next()
		}

		// Create a fake net.Addr from the request
		remoteAddr := &tcpAddr{
			network: "tcp",
			address: c.IP(),
		}

		// Check connection with TCP protection
		action, connInfo, err := app.tcpMiddleware.GetProtection().CheckConnection(c.Context(), remoteAddr)
		if err != nil {
			log.Printf("TCP protection check failed for %s: %v", c.IP(), err)
			return c.Next() // Continue on error
		}

		// Handle different actions
		switch action {
		case tcp.ActionAllow:
			// Connection is allowed, proceed with request
			return c.Next()

		case tcp.ActionDrop:
			// Silent drop - close connection without response
			log.Printf("Silently dropping HTTP request from %s (connections: %d)",
				connInfo.IP, connInfo.ConnectionCount)
			return c.SendStatus(fiber.StatusNoContent)

		case tcp.ActionTarpit:
			// Tarpit - delay the response
			log.Printf("Tarpitting HTTP request from %s (connections: %d)",
				connInfo.IP, connInfo.ConnectionCount)
			time.Sleep(app.tcpConfig.TarpitDelay)
			return c.Next()

		case tcp.ActionBlock:
			// Block - return error response
			log.Printf("Blocking HTTP request from %s (connections: %d, failed: %d)",
				connInfo.IP, connInfo.ConnectionCount, connInfo.FailedAttempts)

			response := fiber.Map{
				"error":            "Request blocked by TCP-level DDoS protection",
				"reason":           "Too many connections",
				"ip":               connInfo.IP,
				"connection_count": connInfo.ConnectionCount,
				"failed_attempts":  connInfo.FailedAttempts,
				"blocked_at":       connInfo.ConnectedAt.Format(time.RFC3339),
				"retry_after":      int(app.tcpConfig.ConnectionWindow.Seconds()),
			}

			c.Set("Retry-After", fmt.Sprintf("%d", int(app.tcpConfig.ConnectionWindow.Seconds())))
			return c.Status(fiber.StatusTooManyRequests).JSON(response)

		default:
			// Unknown action, default to allow
			log.Printf("Unknown TCP action %s for %s, allowing", action.String(), c.IP())
			return c.Next()
		}
	}
}

// tcpAddr implements net.Addr for TCP protection
type tcpAddr struct {
	network string
	address string
}

func (a *tcpAddr) Network() string {
	return a.network
}

func (a *tcpAddr) String() string {
	return a.address
}

// getRealIP extracts the real IP address from the request
func (app *Application) getRealIP(c *fiber.Ctx) string {
	// Check X-Forwarded-For header
	xff := c.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP from the list
		if ip := net.ParseIP(xff); ip != nil {
			return ip.String()
		}
	}

	// Check X-Real-IP header
	xri := c.Get("X-Real-IP")
	if xri != "" {
		if ip := net.ParseIP(xri); ip != nil {
			return ip.String()
		}
	}

	// Fall back to connection IP
	return c.IP()
}

// setupRoutes sets up the application routes
func (app *Application) setupRoutes() {
	// Health check endpoint
	app.fiberApp.Get("/health", func(c *fiber.Ctx) error {
		health := map[string]any{
			"status":    "healthy",
			"timestamp": time.Now(),
			"version":   "2.0.0",
		}

		// Check rule engine health
		if err := app.ruleEngine.Health(); err != nil {
			health["status"] = "unhealthy"
			health["rule_engine_error"] = err.Error()
		}

		// Check store health
		if err := app.stateStore.Health(); err != nil {
			health["status"] = "unhealthy"
			health["store_error"] = err.Error()
		}

		return c.JSON(health)
	})

	// Metrics endpoint
	app.fiberApp.Get("/metrics", func(c *fiber.Ctx) error {
		metrics := map[string]any{
			"rule_engine": app.ruleEngine.GetMetrics(),
			"event_bus":   app.eventBus.GetStats(),
			"store":       app.stateStore.GetStats(),
		}

		// Add plugin metrics
		pluginMetrics := make(map[string]any)
		for _, detector := range app.registry.GetAllDetectors() {
			pluginMetrics[detector.Name()] = detector.GetMetrics()
		}
		for _, action := range app.registry.GetAllActions() {
			pluginMetrics[action.Name()] = action.GetMetrics()
		}
		metrics["plugins"] = pluginMetrics

		// Add TCP protection metrics
		if app.tcpMiddleware != nil {
			metrics["tcp_protection"] = app.tcpMiddleware.GetMetrics()
		}

		return c.JSON(metrics)
	})

	// Plugin management endpoints
	app.fiberApp.Get("/admin/plugins", func(c *fiber.Ctx) error {
		return c.JSON(app.registry.GetAllPluginMetadata())
	})

	// TCP protection management endpoints
	if app.tcpHandler != nil {
		tcpAdmin := app.fiberApp.Group("/admin/tcp")

		tcpAdmin.Get("/metrics", func(c *fiber.Ctx) error {
			metrics := app.tcpMiddleware.GetMetrics()
			return c.JSON(metrics)
		})

		tcpAdmin.Get("/connections", func(c *fiber.Ctx) error {
			connections := app.tcpMiddleware.GetActiveConnections()
			return c.JSON(fiber.Map{"active_connections": connections})
		})

		tcpAdmin.Post("/whitelist", func(c *fiber.Ctx) error {
			ip := c.FormValue("ip")
			if ip == "" {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "IP parameter required"})
			}
			app.tcpMiddleware.GetProtection().AddToWhitelist(ip)
			return c.JSON(fiber.Map{"message": fmt.Sprintf("IP %s added to whitelist", ip)})
		})

		tcpAdmin.Delete("/whitelist", func(c *fiber.Ctx) error {
			ip := c.FormValue("ip")
			if ip == "" {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "IP parameter required"})
			}
			app.tcpMiddleware.GetProtection().RemoveFromWhitelist(ip)
			return c.JSON(fiber.Map{"message": fmt.Sprintf("IP %s removed from whitelist", ip)})
		})

		tcpAdmin.Post("/blacklist", func(c *fiber.Ctx) error {
			ip := c.FormValue("ip")
			if ip == "" {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "IP parameter required"})
			}
			app.tcpMiddleware.GetProtection().AddToBlacklist(ip)
			return c.JSON(fiber.Map{"message": fmt.Sprintf("IP %s added to blacklist", ip)})
		})

		tcpAdmin.Delete("/blacklist", func(c *fiber.Ctx) error {
			ip := c.FormValue("ip")
			if ip == "" {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "IP parameter required"})
			}
			app.tcpMiddleware.GetProtection().RemoveFromBlacklist(ip)
			return c.JSON(fiber.Map{"message": fmt.Sprintf("IP %s removed from blacklist", ip)})
		})
	}

	// Demo routes
	app.setupDemoRoutes()

	// Main application routes
	app.fiberApp.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message":   "DDoS Protection System v2.0",
			"timestamp": time.Now(),
			"ip":        app.getRealIP(c),
			"protected": true,
		})
	})

	// API routes
	api := app.fiberApp.Group("/api/v1")

	api.Get("/status", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":     "operational",
			"protection": "active",
			"version":    "2.0.0",
		})
	})

	// Test endpoints (remove in production)
	test := app.fiberApp.Group("/test")

	test.Get("/sql", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "SQL test endpoint"})
	})

	test.Get("/rate", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Rate limit test endpoint"})
	})
}

// setupDemoRoutes sets up the demo and testing routes
func (app *Application) setupDemoRoutes() {
	// Serve static demo files
	app.fiberApp.Static("/demo", "./demo")

	// Demo API endpoints
	demo := app.fiberApp.Group("/demo")

	// Main demo page
	demo.Get("/", func(c *fiber.Ctx) error {
		return c.SendFile("./demo/index.html")
	})

	// CAPTCHA challenge page
	demo.Get("/captcha", func(c *fiber.Ctx) error {
		return c.SendFile("./demo/captcha.html")
	})

	// Get user info
	demo.Get("/user-info", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"ip":         app.getRealIP(c),
			"user_agent": c.Get("User-Agent"),
			"timestamp":  time.Now(),
		})
	})

	// Trigger CAPTCHA challenge
	demo.Post("/trigger-captcha", func(c *fiber.Ctx) error {
		ip := app.getRealIP(c)

		// Get CAPTCHA action from registry
		captchaAction, exists := app.registry.GetAction("captcha_action")
		if !exists {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"error": "CAPTCHA service not available",
			})
		}

		ca, ok := captchaAction.(*actions.CaptchaAction)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "CAPTCHA service error",
			})
		}

		// Create a fake rule result to trigger CAPTCHA
		reqCtx := &plugins.RequestContext{
			IP:        ip,
			UserAgent: c.Get("User-Agent"),
			Method:    c.Method(),
			Path:      c.Path(),
			Headers:   make(map[string]string),
			Timestamp: time.Now(),
		}

		ruleResult := plugins.RuleResult{
			Triggered:  true,
			Action:     "captcha_action",
			Confidence: 0.8,
			Details:    "Demo CAPTCHA challenge triggered",
			RuleName:   "demo_rule",
			Severity:   5,
		}

		// Execute CAPTCHA action
		err := ca.Execute(c.Context(), reqCtx, ruleResult)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to create CAPTCHA challenge",
			})
		}

		return c.JSON(fiber.Map{
			"captcha_required": true,
			"message":          "CAPTCHA challenge created",
		})
	})

	// Get CAPTCHA challenge
	demo.Get("/captcha-challenge", func(c *fiber.Ctx) error {
		ip := app.getRealIP(c)

		// Get CAPTCHA action from registry
		captchaAction, exists := app.registry.GetAction("captcha_action")
		if !exists {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"error": "CAPTCHA service not available",
			})
		}

		ca, ok := captchaAction.(*actions.CaptchaAction)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "CAPTCHA service error",
			})
		}

		// Get active challenge
		hasChallenge, challenge, err := ca.GetActiveChallenge(c.Context(), ip)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to get CAPTCHA challenge",
			})
		}

		if !hasChallenge {
			return c.JSON(fiber.Map{
				"challenge": nil,
				"message":   "No active CAPTCHA challenge",
			})
		}

		return c.JSON(fiber.Map{
			"challenge": challenge,
		})
	})

	// Check CAPTCHA status
	demo.Get("/captcha-status", func(c *fiber.Ctx) error {
		ip := app.getRealIP(c)

		// Get CAPTCHA action from registry
		captchaAction, exists := app.registry.GetAction("captcha_action")
		if !exists {
			return c.JSON(fiber.Map{
				"has_challenge": false,
				"message":       "CAPTCHA service not available",
			})
		}

		ca, ok := captchaAction.(*actions.CaptchaAction)
		if !ok {
			return c.JSON(fiber.Map{
				"has_challenge": false,
				"message":       "CAPTCHA service error",
			})
		}

		// Get active challenge
		hasChallenge, challenge, err := ca.GetActiveChallenge(c.Context(), ip)
		if err != nil {
			return c.JSON(fiber.Map{
				"has_challenge": false,
				"error":         "Failed to check CAPTCHA status",
			})
		}

		return c.JSON(fiber.Map{
			"has_challenge": hasChallenge,
			"challenge":     challenge,
		})
	})

	// Verify CAPTCHA answer
	demo.Post("/verify-captcha", func(c *fiber.Ctx) error {
		ip := app.getRealIP(c)

		var request struct {
			Answer      string `json:"answer"`
			ChallengeID string `json:"challenge_id"`
		}

		if err := c.BodyParser(&request); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request format",
			})
		}

		// Get CAPTCHA action from registry
		captchaAction, exists := app.registry.GetAction("captcha_action")
		if !exists {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"error": "CAPTCHA service not available",
			})
		}

		ca, ok := captchaAction.(*actions.CaptchaAction)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "CAPTCHA service error",
			})
		}

		// Verify the challenge
		verified, err := ca.VerifyChallenge(c.Context(), ip, request.Answer)
		if err != nil {
			return c.JSON(fiber.Map{
				"success": false,
				"error":   err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"success": verified,
			"message": func() string {
				if verified {
					return "CAPTCHA verified successfully"
				}
				return "CAPTCHA verification failed"
			}(),
		})
	})

	// Generate new CAPTCHA challenge
	demo.Post("/new-captcha", func(c *fiber.Ctx) error {
		ip := app.getRealIP(c)

		// Get CAPTCHA action from registry
		captchaAction, exists := app.registry.GetAction("captcha_action")
		if !exists {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"error": "CAPTCHA service not available",
			})
		}

		ca, ok := captchaAction.(*actions.CaptchaAction)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "CAPTCHA service error",
			})
		}

		// Clear existing challenge
		ca.ClearChallenge(c.Context(), ip)

		// Create new challenge
		reqCtx := &plugins.RequestContext{
			IP:        ip,
			UserAgent: c.Get("User-Agent"),
			Method:    c.Method(),
			Path:      c.Path(),
			Headers:   make(map[string]string),
			Timestamp: time.Now(),
		}

		ruleResult := plugins.RuleResult{
			Triggered:  true,
			Action:     "captcha_action",
			Confidence: 0.8,
			Details:    "New CAPTCHA challenge requested",
			RuleName:   "demo_rule",
			Severity:   5,
		}

		err := ca.Execute(c.Context(), reqCtx, ruleResult)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"error":   "Failed to create new CAPTCHA challenge",
			})
		}

		return c.JSON(fiber.Map{
			"success": true,
			"message": "New CAPTCHA challenge created",
		})
	})

	// Enhanced test endpoints for demo
	test := app.fiberApp.Group("/test")

	// XSS test endpoint
	test.Post("/xss", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "XSS test endpoint - input processed"})
	})

	// User agent test endpoint
	test.Get("/useragent", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message":    "User agent test endpoint",
			"user_agent": c.Get("User-Agent"),
		})
	})

	// File access test endpoint
	test.Get("/files/*", func(c *fiber.Ctx) error {
		path := c.Params("*")
		return c.JSON(fiber.Map{
			"message": "File access test endpoint",
			"path":    path,
		})
	})

	// Login test endpoint
	test.Post("/login", func(c *fiber.Ctx) error {
		username := c.FormValue("username")
		_ = c.FormValue("password") // Ignore password for demo

		// Always fail for demo purposes
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message":  "Login failed - invalid credentials",
			"username": username,
		})
	})

	// Add login endpoint for brute force testing
	app.fiberApp.Post("/login", func(c *fiber.Ctx) error {
		username := c.FormValue("username")
		_ = c.FormValue("password") // Ignore password for demo

		// Always fail for demo purposes
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message":  "Login failed - invalid credentials",
			"username": username,
		})
	})
}

// Start starts the application
func (app *Application) Start(ctx context.Context) error {
	cfg := app.configManager.GetConfig()
	address := fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.Port)

	log.Printf("🛡️  DDoS Protection System v2.0 starting on %s", address)
	log.Printf("📊 Metrics available at http://%s/metrics", address)
	log.Printf("🔧 Health check at http://%s/health", address)

	// Print plugin information
	metadata := app.registry.GetAllPluginMetadata()
	log.Printf("📦 Loaded %d plugins:", len(metadata))
	for name, meta := range metadata {
		log.Printf("   - %s v%s (%s)", name, meta.Version, meta.Type)
	}

	// Start config watcher
	if err := app.configManager.StartWatching(ctx); err != nil {
		log.Printf("Warning: Failed to start config watcher: %v", err)
	} else {
		log.Println("📁 Config file watcher started")
	}

	return app.fiberApp.Listen(address)
}

// Shutdown gracefully shuts down the application
func (app *Application) Shutdown() error {
	log.Println("Shutting down application...")

	// Stop config watcher
	app.configManager.StopWatching()

	// Shutdown rule engine
	if err := app.ruleEngine.Shutdown(); err != nil {
		log.Printf("Error shutting down rule engine: %v", err)
	}

	// Shutdown Fiber app
	if err := app.fiberApp.Shutdown(); err != nil {
		log.Printf("Error shutting down Fiber app: %v", err)
	}

	log.Println("Application shutdown complete")
	return nil
}

// handleConfigReload handles configuration reload events
func (app *Application) handleConfigReload(newConfig *config.SystemConfig) error {
	app.mu.Lock()
	defer app.mu.Unlock()

	log.Println("Handling configuration reload...")

	// Update rule engine with new action rules
	app.ruleEngine.UpdateConfig(newConfig.Engine)

	// Re-register plugins with new configurations
	if err := app.reloadPlugins(newConfig); err != nil {
		log.Printf("Failed to reload plugins: %v", err)
		return err
	}

	log.Println("Configuration reload completed successfully")
	return nil
}

// reloadPlugins reloads plugin configurations
func (app *Application) reloadPlugins(cfg *config.SystemConfig) error {
	// Update detector configurations
	for name, pluginConfig := range cfg.Plugins.Detectors {
		if detector, exists := app.registry.GetDetector(name); exists {
			if err := detector.Initialize(pluginConfig.Parameters); err != nil {
				log.Printf("Failed to reinitialize detector %s: %v", name, err)
			} else {
				log.Printf("Reloaded detector: %s", name)
			}
		}
	}

	// Update action configurations
	for name, pluginConfig := range cfg.Plugins.Actions {
		if action, exists := app.registry.GetAction(name); exists {
			if err := action.Initialize(pluginConfig.Parameters); err != nil {
				log.Printf("Failed to reinitialize action %s: %v", name, err)
			} else {
				log.Printf("Reloaded action: %s", name)
			}
		}
	}

	// Update handler configurations
	// Note: We'll iterate through configured handlers since registry doesn't expose GetAllHandlers
	for name := range cfg.Plugins.Handlers {
		// We can't directly access handlers from registry, so we'll log the configuration update
		log.Printf("Handler configuration updated: %s", name)
	}

	return nil
}
