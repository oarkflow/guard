package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/oarkflow/guard"
)

// User represents a user in the system
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Country  string `json:"country"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

// SignupRequest represents a signup request
type SignupRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Country  string `json:"country"`
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// Mock user database
var users = []User{
	{ID: 1, Username: "admin", Email: "admin@example.com", Role: "admin", Country: "US"},
	{ID: 2, Username: "user1", Email: "user1@example.com", Role: "user", Country: "US"},
	{ID: 3, Username: "user2", Email: "user2@example.com", Role: "user", Country: "CA"},
}

// Mock session storage
var sessions = make(map[string]User)

func main() {
	fmt.Println("🚀 Starting Guard Security System Demo Server...")
	fmt.Println("==================================================")

	// Create Guard application
	guardApp, err := guard.NewApplication("config")
	if err != nil {
		log.Fatalf("Failed to create Guard application: %v", err)
	}

	if err := guardApp.Initialize(); err != nil {
		log.Fatalf("Failed to initialize Guard application: %v", err)
	}

	// Get the Fiber app from Guard
	app := guardApp.GetFiberApp()

	// Add middleware
	app.Use(cors.New())
	app.Use(logger.New())

	// Serve static files
	app.Static("/", "./views")

	// Authentication endpoints
	setupAuthRoutes(app)

	// API endpoints
	setupAPIRoutes(app)

	// Admin endpoints
	setupAdminRoutes(app)

	// Test endpoints for security rules
	setupTestRoutes(app)

	fmt.Println("📋 Available endpoints:")
	fmt.Println("  Authentication:")
	fmt.Println("    POST /auth/login - User login")
	fmt.Println("    POST /auth/signup - User registration")
	fmt.Println("    POST /auth/logout - User logout")
	fmt.Println("    GET  /auth/profile - Get user profile")
	fmt.Println()
	fmt.Println("  API endpoints:")
	fmt.Println("    GET  /api/users - List users")
	fmt.Println("    GET  /api/users/:id - Get user by ID")
	fmt.Println("    POST /api/users - Create user")
	fmt.Println("    PUT  /api/users/:id - Update user")
	fmt.Println("    DELETE /api/users/:id - Delete user")
	fmt.Println()
	fmt.Println("  Admin endpoints:")
	fmt.Println("    GET  /admin/dashboard - Admin dashboard")
	fmt.Println("    GET  /admin/users - Admin user management")
	fmt.Println("    POST /admin/settings - Update settings")
	fmt.Println()
	fmt.Println("  Test endpoints:")
	fmt.Println("    GET  /test/sql-injection - Test SQL injection detection")
	fmt.Println("    GET  /test/xss - Test XSS detection")
	fmt.Println("    GET  /test/ddos - Test DDoS detection")
	fmt.Println("    GET  /export/users - Test data exfiltration detection")
	fmt.Println()
	fmt.Println("🌐 Demo Interface: http://localhost:8080")
	fmt.Println("📊 Security Metrics: http://localhost:8080/metrics")
	fmt.Println("🔧 Health Check: http://localhost:8080/health")
	fmt.Println("📖 Demo Guide: See demo/README.md")
	fmt.Println()
	fmt.Println("🛡️ All security features are active and ready for testing!")

	// Start the server using Guard's Start method
	ctx := context.Background()
	if err := guardApp.Start(ctx); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func setupAuthRoutes(app *fiber.App) {
	auth := app.Group("/auth")

	// Login endpoint
	auth.Post("/login", func(c *fiber.Ctx) error {
		var req LoginRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(APIResponse{
				Success: false,
				Error:   "Invalid request body",
			})
		}

		// Simulate authentication
		for _, user := range users {
			if user.Username == req.Username || user.Email == req.Email {
				// Create session
				sessionID := fmt.Sprintf("session_%d_%d", user.ID, time.Now().Unix())
				sessions[sessionID] = user

				c.Cookie(&fiber.Cookie{
					Name:     "session_id",
					Value:    sessionID,
					Expires:  time.Now().Add(24 * time.Hour),
					HTTPOnly: true,
				})

				return c.JSON(APIResponse{
					Success: true,
					Message: "Login successful",
					Data: map[string]interface{}{
						"user":       user,
						"session_id": sessionID,
					},
				})
			}
		}

		return c.Status(401).JSON(APIResponse{
			Success: false,
			Error:   "Invalid credentials",
		})
	})

	// Signup endpoint
	auth.Post("/signup", func(c *fiber.Ctx) error {
		var req SignupRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(APIResponse{
				Success: false,
				Error:   "Invalid request body",
			})
		}

		// Check if user already exists
		for _, user := range users {
			if user.Username == req.Username || user.Email == req.Email {
				return c.Status(409).JSON(APIResponse{
					Success: false,
					Error:   "User already exists",
				})
			}
		}

		// Create new user
		newUser := User{
			ID:       len(users) + 1,
			Username: req.Username,
			Email:    req.Email,
			Role:     "user",
			Country:  req.Country,
		}
		users = append(users, newUser)

		return c.JSON(APIResponse{
			Success: true,
			Message: "User created successfully",
			Data:    newUser,
		})
	})

	// Logout endpoint
	auth.Post("/logout", func(c *fiber.Ctx) error {
		sessionID := c.Cookies("session_id")
		if sessionID != "" {
			delete(sessions, sessionID)
		}

		c.ClearCookie("session_id")
		return c.JSON(APIResponse{
			Success: true,
			Message: "Logged out successfully",
		})
	})

	// Profile endpoint
	auth.Get("/profile", func(c *fiber.Ctx) error {
		sessionID := c.Cookies("session_id")
		if sessionID == "" {
			return c.Status(401).JSON(APIResponse{
				Success: false,
				Error:   "Not authenticated",
			})
		}

		user, exists := sessions[sessionID]
		if !exists {
			return c.Status(401).JSON(APIResponse{
				Success: false,
				Error:   "Invalid session",
			})
		}

		return c.JSON(APIResponse{
			Success: true,
			Data:    user,
		})
	})
}

func setupAPIRoutes(app *fiber.App) {
	api := app.Group("/api")

	// List users
	api.Get("/users", func(c *fiber.Ctx) error {
		limit := c.QueryInt("limit", 10)
		if limit > 1000 {
			// This should trigger data exfiltration detection
			return c.Status(400).JSON(APIResponse{
				Success: false,
				Error:   "Limit too high",
			})
		}

		return c.JSON(APIResponse{
			Success: true,
			Data:    users[:min(limit, len(users))],
		})
	})

	// Get user by ID
	api.Get("/users/:id", func(c *fiber.Ctx) error {
		id, err := strconv.Atoi(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(APIResponse{
				Success: false,
				Error:   "Invalid user ID",
			})
		}

		for _, user := range users {
			if user.ID == id {
				return c.JSON(APIResponse{
					Success: true,
					Data:    user,
				})
			}
		}

		return c.Status(404).JSON(APIResponse{
			Success: false,
			Error:   "User not found",
		})
	})

	// Create user
	api.Post("/users", func(c *fiber.Ctx) error {
		var user User
		if err := c.BodyParser(&user); err != nil {
			return c.Status(400).JSON(APIResponse{
				Success: false,
				Error:   "Invalid request body",
			})
		}

		user.ID = len(users) + 1
		users = append(users, user)

		return c.Status(201).JSON(APIResponse{
			Success: true,
			Message: "User created",
			Data:    user,
		})
	})

	// Update user
	api.Put("/users/:id", func(c *fiber.Ctx) error {
		id, err := strconv.Atoi(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(APIResponse{
				Success: false,
				Error:   "Invalid user ID",
			})
		}

		var updatedUser User
		if err := c.BodyParser(&updatedUser); err != nil {
			return c.Status(400).JSON(APIResponse{
				Success: false,
				Error:   "Invalid request body",
			})
		}

		for i, user := range users {
			if user.ID == id {
				updatedUser.ID = id
				users[i] = updatedUser
				return c.JSON(APIResponse{
					Success: true,
					Message: "User updated",
					Data:    updatedUser,
				})
			}
		}

		return c.Status(404).JSON(APIResponse{
			Success: false,
			Error:   "User not found",
		})
	})

	// Delete user
	api.Delete("/users/:id", func(c *fiber.Ctx) error {
		id, err := strconv.Atoi(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(APIResponse{
				Success: false,
				Error:   "Invalid user ID",
			})
		}

		for i, user := range users {
			if user.ID == id {
				users = append(users[:i], users[i+1:]...)
				return c.JSON(APIResponse{
					Success: true,
					Message: "User deleted",
				})
			}
		}

		return c.Status(404).JSON(APIResponse{
			Success: false,
			Error:   "User not found",
		})
	})
}

func setupAdminRoutes(app *fiber.App) {
	admin := app.Group("/admin")

	// Admin dashboard
	admin.Get("/dashboard", func(c *fiber.Ctx) error {
		return c.JSON(APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"total_users":     len(users),
				"active_sessions": len(sessions),
				"server_time":     time.Now(),
			},
		})
	})

	// Admin user management
	admin.Get("/users", func(c *fiber.Ctx) error {
		return c.JSON(APIResponse{
			Success: true,
			Data:    users,
		})
	})

	// Admin settings
	admin.Post("/settings", func(c *fiber.Ctx) error {
		var settings map[string]interface{}
		if err := c.BodyParser(&settings); err != nil {
			return c.Status(400).JSON(APIResponse{
				Success: false,
				Error:   "Invalid request body",
			})
		}

		return c.JSON(APIResponse{
			Success: true,
			Message: "Settings updated",
			Data:    settings,
		})
	})
}

func setupTestRoutes(app *fiber.App) {
	test := app.Group("/test")

	// SQL injection test
	test.Get("/sql-injection", func(c *fiber.Ctx) error {
		return c.JSON(APIResponse{
			Success: true,
			Message: "This endpoint is designed to test SQL injection detection",
		})
	})

	// XSS test
	test.Get("/xss", func(c *fiber.Ctx) error {
		return c.JSON(APIResponse{
			Success: true,
			Message: "This endpoint is designed to test XSS detection",
		})
	})

	// DDoS test
	test.Get("/ddos", func(c *fiber.Ctx) error {
		return c.JSON(APIResponse{
			Success: true,
			Message: "This endpoint is designed to test DDoS detection",
		})
	})

	// Data export (potential exfiltration)
	app.Get("/export/users", func(c *fiber.Ctx) error {
		count := c.QueryInt("count", 10)
		if count > 10000 {
			// This should trigger data exfiltration detection
			return c.Status(400).JSON(APIResponse{
				Success: false,
				Error:   "Export limit exceeded",
			})
		}

		return c.JSON(APIResponse{
			Success: true,
			Message: "User export",
			Data:    users,
		})
	})

	// Download endpoint
	app.Get("/download/backup", func(c *fiber.Ctx) error {
		size := c.QueryInt("size", 1000)
		return c.JSON(APIResponse{
			Success: true,
			Message: fmt.Sprintf("Backup download requested (size: %d)", size),
		})
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
