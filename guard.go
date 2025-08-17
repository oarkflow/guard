package guard

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/oarkflow/log"

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
	configManager        *config.Manager
	registry             *plugins.PluginRegistry
	eventBus             *events.EventBus
	ruleEngine           *engine.RuleEngine
	stateStore           store.StateStore
	fiberApp             *fiber.App
	tcpMiddleware        *tcp.TCPMiddleware
	tcpHandler           *tcp.TCPProtectionHandler
	tcpConfig            tcp.TCPProtectionConfig
	enableTCPMiddleware  bool
	enableDdosMiddleware bool
	mu                   sync.RWMutex
}

type Options func(*Application)

func WithApp(app *fiber.App) Options {
	return func(a *Application) {
		a.fiberApp = app
	}
}

func WithTCPMiddleware(enable bool) Options {
	return func(a *Application) {
		a.enableTCPMiddleware = enable
	}
}

func WithDdosMiddleware(enable bool) Options {
	return func(a *Application) {
		a.enableDdosMiddleware = enable
	}
}

// NewApplication creates a new application instance
func NewApplication(configFile string, opts ...Options) (*Application, error) {
	// Create config manager
	configManager := config.NewManager(configFile)

	// Load initial configuration
	if err := configManager.LoadInitialConfig(); err != nil {
		// Create default config if file doesn't exist
		cfg := config.CreateDefaultConfig()
		if err := config.SaveConfig(cfg, configFile); err != nil {
			log.Warn().Err(err).Msg("Could not save default config")
		}
		log.Info().Str("config_file", configFile).Msg("Created default configuration file")

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

	app := &Application{
		enableTCPMiddleware:  true,
		enableDdosMiddleware: true,
		configManager:        configManager,
		registry:             registry,
		eventBus:             eventBus,
		ruleEngine:           ruleEngine,
		stateStore:           stateStore,
	}
	for _, opt := range opts {
		opt(app)
	}

	if app.fiberApp == nil {
		// Create default Fiber app if not provided
		app.fiberApp = fiber.New(fiber.Config{
			ReadTimeout:  cfg.Server.ReadTimeout,
			WriteTimeout: cfg.Server.WriteTimeout,
			IdleTimeout:  cfg.Server.IdleTimeout,
			BodyLimit:    cfg.Server.BodyLimit,
			ErrorHandler: func(c *fiber.Ctx, err error) error {
				log.Error().Err(err).Msg("Request error")
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Internal server error",
				})
			},
		})
		app.fiberApp.Use(recover.New())
	}

	if app.enableTCPMiddleware {
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
		app.tcpMiddleware = tcpMiddleware
		app.tcpHandler = tcpHandler
		app.fiberApp.Use(app.createTCPProtectionMiddleware())
	}

	if app.enableDdosMiddleware {
		app.fiberApp.Use(app.ddosProtectionMiddleware())
	}

	return app, nil
}

// Initialize initializes the application components
func (app *Application) Initialize() error {
	log.Info().Msg("Initializing application components...")

	// Register built-in plugins
	if err := app.registerBuiltinPlugins(); err != nil {
		return fmt.Errorf("failed to register builtin plugins: %w", err)
	}

	// Setup config reload callback
	app.configManager.AddReloadCallback(app.handleConfigReload)

	// Setup routes
	app.setupRoutes()

	log.Info().Msg("Application initialized successfully")
	return nil
}

func (app *Application) Use(middleware ...any) {
	app.fiberApp.Use(middleware...)
}

func (app *Application) AddRoute(method, path string, handlers ...fiber.Handler) {
	app.fiberApp.Add(method, path, handlers...)
}

func (app *Application) Static(prefix, root string, config ...fiber.Static) {
	app.fiberApp.Static(prefix, root, config...)
}

func (app *Application) Get(path string, handlers ...fiber.Handler) {
	app.fiberApp.Get(path, handlers...)
}

func (app *Application) Post(path string, handlers ...fiber.Handler) {
	app.fiberApp.Post(path, handlers...)
}

func (app *Application) All(path string, handlers ...fiber.Handler) {
	app.fiberApp.All(path, handlers...)
}

func (app *Application) Delete(path string, handlers ...fiber.Handler) {
	app.fiberApp.Delete(path, handlers...)
}

func (app *Application) Patch(path string, handlers ...fiber.Handler) {
	app.fiberApp.Patch(path, handlers...)
}

func (app *Application) Trace(path string, handlers ...fiber.Handler) {
	app.fiberApp.Trace(path, handlers...)
}

func (app *Application) AddRouteGroup(prefix string, handlers ...fiber.Handler) fiber.Router {
	return app.fiberApp.Group(prefix, handlers...)
}

func (app *Application) GetRegistry() *plugins.PluginRegistry {
	return app.registry
}

func (app *Application) GetEventBus() *events.EventBus {
	return app.eventBus
}

func (app *Application) GetRuleEngine() *engine.RuleEngine {
	return app.ruleEngine
}

func (app *Application) GetStateStore() store.StateStore {
	return app.stateStore
}

func (app *Application) GetFiberApp() *fiber.App {
	return app.fiberApp
}

func (app *Application) GetTCPMiddleware() *tcp.TCPMiddleware {
	return app.tcpMiddleware
}

func (app *Application) GetConfig() *config.Manager {
	return app.configManager
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

// ddosProtectionMiddleware creates the DDoS protection middleware
func (app *Application) ddosProtectionMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Build request context
		reqCtx := &plugins.RequestContext{
			IP:            app.GetRealIP(c),
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
			log.Error().Err(result.Error).Msg("Rule engine error")
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
			log.Warn().Str("ip", reqCtx.IP).Interface("detections", result.Detections).Msg("Request blocked")

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
			log.Warn().Str("ip", connInfo.IP).Int64("connections", connInfo.ConnectionCount).Msg("Silently dropping HTTP request")
			return c.SendStatus(fiber.StatusNoContent)

		case tcp.ActionTarpit:
			// Tarpit - delay the response
			log.Warn().Str("ip", connInfo.IP).Int64("connections", connInfo.ConnectionCount).Msg("Tarpitting HTTP request")
			time.Sleep(app.tcpConfig.TarpitDelay)
			return c.Next()

		case tcp.ActionBlock:
			// Block - return error response
			log.Warn().Str("ip", connInfo.IP).Int64("connections", connInfo.ConnectionCount).Int64("failed", connInfo.FailedAttempts).Msg("Blocking HTTP request")

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
			log.Warn().Str("action", action.String()).Str("ip", c.IP()).Msg("Unknown TCP action, allowing")
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
func (app *Application) GetRealIP(c *fiber.Ctx) string {
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
}

// Start starts the application
func (app *Application) Start(ctx context.Context) error {
	cfg := app.configManager.GetConfig()
	address := fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.Port)

	log.Info().Msg("🛡️  DDoS Protection System v2.0 starting on " + address)
	log.Info().Msgf("📊 Metrics available at http://%s/metrics", address)
	log.Info().Msgf("🔧 Health check at http://%s/health", address)

	// Print plugin information
	metadata := app.registry.GetAllPluginMetadata()
	log.Info().Int("plugin_count", len(metadata)).Msg("📦 Loaded plugins")
	for name, meta := range metadata {
		log.Info().Str("name", name).Str("version", meta.Version).Str("type", meta.Type).Msg("Plugin loaded")
	}

	// Start config watcher
	if err := app.configManager.StartWatching(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to start config watcher")
	} else {
		log.Info().Msg("📁 Config file watcher started")
	}

	return app.fiberApp.Listen(address)
}

func (app *Application) StartTLS(ctx context.Context) error {
	cfg := app.configManager.GetConfig()
	address := fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.TLSPort)

	log.Info().Msg("🛡️  DDoS Protection System v2.0 starting on " + address)
	log.Info().Msgf("📊 Metrics available at https://%s/metrics", address)
	log.Info().Msgf("🔧 Health check at https://%s/health", address)

	// Print plugin information
	metadata := app.registry.GetAllPluginMetadata()
	log.Info().Int("plugin_count", len(metadata)).Msg("📦 Loaded plugins")
	for name, meta := range metadata {
		log.Info().
			Str("name", name).
			Str("version", meta.Version).
			Str("type", meta.Type).
			Msg("Plugin loaded")
	}

	// Start config watcher
	if err := app.configManager.StartWatching(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to start config watcher")
	} else {
		log.Info().Msg("📁 Config file watcher started")
	}
	// Ensure TLS cert and key files are provided
	if cfg.Server.TLSCertFile == "" || cfg.Server.TLSKeyFile == "" {
		log.Error().Msg("TLS certificate and key files must be provided")
		return fmt.Errorf("TLS certificate and key files must be provided")
	}

	// Start Fiber with TLS
	return app.fiberApp.ListenTLS(address, cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
}

// Shutdown gracefully shuts down the application
func (app *Application) Shutdown() error {
	log.Info().Msg("Shutting down application...")

	// Stop config watcher
	app.configManager.StopWatching()

	// Shutdown rule engine
	if err := app.ruleEngine.Shutdown(); err != nil {
		log.Error().Err(err).Msg("Error shutting down rule engine")
	}

	// Shutdown Fiber app
	if err := app.fiberApp.Shutdown(); err != nil {
		log.Error().Err(err).Msg("Error shutting down Fiber app")
	}

	log.Info().Msg("Application shutdown complete")
	return nil
}

// handleConfigReload handles configuration reload events
func (app *Application) handleConfigReload(newConfig *config.SystemConfig) error {
	app.mu.Lock()
	defer app.mu.Unlock()

	log.Info().Msg("Handling configuration reload...")

	// Update rule engine with new action rules
	app.ruleEngine.UpdateConfig(newConfig.Engine)

	// Re-register plugins with new configurations
	if err := app.reloadPlugins(newConfig); err != nil {
		log.Error().Err(err).Msg("Failed to reload plugins")
		return err
	}

	log.Info().Msg("Configuration reload completed successfully")
	return nil
}

// reloadPlugins reloads plugin configurations
func (app *Application) reloadPlugins(cfg *config.SystemConfig) error {
	// Update detector configurations
	for name, pluginConfig := range cfg.Plugins.Detectors {
		if detector, exists := app.registry.GetDetector(name); exists {
			if err := detector.Initialize(pluginConfig.Parameters); err != nil {
				log.Error().Str("detector", name).Err(err).Msg("Failed to reinitialize detector")
			} else {
				log.Info().Str("detector", name).Msg("Reloaded detector")
			}
		}
	}

	// Update action configurations
	for name, pluginConfig := range cfg.Plugins.Actions {
		if action, exists := app.registry.GetAction(name); exists {
			if err := action.Initialize(pluginConfig.Parameters); err != nil {
				log.Error().Str("action", name).Err(err).Msg("Failed to reinitialize action")
			} else {
				log.Info().Str("action", name).Msg("Reloaded action")
			}
		}
	}

	// Update handler configurations
	// Note: We'll iterate through configured handlers since registry doesn't expose GetAllHandlers
	for name := range cfg.Plugins.Handlers {
		// We can't directly access handlers from registry, so we'll log the configuration update
		log.Info().Str("handler", name).Msg("Handler configuration updated")
	}

	return nil
}
