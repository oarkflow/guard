package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/guard"
	"github.com/oarkflow/guard/pkg/config"
	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/guard/pkg/plugins/actions"
	"github.com/oarkflow/log"
)

func main() {
	// Add flag for config file
	configFile := flag.String("config", "testdata/system_config.json", "Path to configuration file")
	flag.StringVar(configFile, "c", "testdata/system_config.json", "Path to configuration file (shorthand)")
	flag.Parse()

	// Ensure config file exists, create default if missing
	if _, err := os.Stat(*configFile); os.IsNotExist(err) {
		log.Warn().Str("config_file", *configFile).Msg("Config file does not exist, creating default...")
		cfg := config.CreateDefaultConfig()
		if err := config.SaveConfig(cfg, *configFile); err != nil {
			log.Fatal().Err(err).Msg("Failed to create default config file")
		}
		log.Info().Str("config_file", *configFile).Msg("Default config file created")
	}

	// Create application
	app, err := guard.NewApplication(*configFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create application")
	}

	// Initialize application
	if err := app.Initialize(); err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize application")
	}
	setupDemoRoutes(app)
	// Setup graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Info().Msg("Received shutdown signal...")
		app.Shutdown()
		os.Exit(0)
	}()

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start application
	if err := app.Start(ctx); err != nil {
		log.Fatal().Err(err).Msg("Failed to start application")
	}
}

// setupDemoRoutes sets up the demo and testing routes
func setupDemoRoutes(app *guard.Application) {
	// Serve static demo files
	app.Static("/demo", "./demo")

	// Demo API endpoints
	demo := app.Group("/demo")

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
			"ip":         app.GetRealIP(c),
			"user_agent": c.Get("User-Agent"),
			"timestamp":  time.Now(),
		})
	})

	// Trigger CAPTCHA challenge
	demo.Post("/trigger-captcha", func(c *fiber.Ctx) error {
		ip := app.GetRealIP(c)

		// Get CAPTCHA action from registry
		captchaAction, exists := app.GetRegistry().GetAction("captcha_action")
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
		ip := app.GetRealIP(c)

		// Get CAPTCHA action from registry
		captchaAction, exists := app.GetRegistry().GetAction("captcha_action")
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
		ip := app.GetRealIP(c)

		// Get CAPTCHA action from registry
		captchaAction, exists := app.GetRegistry().GetAction("captcha_action")
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
		ip := app.GetRealIP(c)

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
		captchaAction, exists := app.GetRegistry().GetAction("captcha_action")
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
		ip := app.GetRealIP(c)

		// Get CAPTCHA action from registry
		captchaAction, exists := app.GetRegistry().GetAction("captcha_action")
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
	test := app.Group("/test")

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
	app.Post("/login", func(c *fiber.Ctx) error {
		username := c.FormValue("username")
		_ = c.FormValue("password") // Ignore password for demo

		// Always fail for demo purposes
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message":  "Login failed - invalid credentials",
			"username": username,
		})
	})

	demo.Get("/signup", func(c *fiber.Ctx) error {
		return c.SendFile("./demo/signup.html")
	})

	// Signup endpoint for multiple signup detection demo
	demo.Post("/signup", func(c *fiber.Ctx) error {
		username := c.FormValue("username")
		email := c.FormValue("email")
		_ = c.FormValue("password") // Ignore password for demo

		// Get real IP for logging
		ip := app.GetRealIP(c)

		// Log the signup attempt
		log.Info().Str("ip", ip).Str("username", username).Str("email", email).Msg("Signup attempt")

		// For demo purposes, we'll always succeed but log the attempt
		// In a real implementation, this would create an account
		return c.JSON(fiber.Map{
			"success":  true,
			"message":  "Account created successfully",
			"username": username,
			"email":    email,
		})
	})
}
