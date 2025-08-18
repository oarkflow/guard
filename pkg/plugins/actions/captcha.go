package actions

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/guard/pkg/store"
)

// CaptchaAction implements ActionPlugin for CAPTCHA challenges
type CaptchaAction struct {
	name        string
	version     string
	description string
	store       store.StateStore
	config      CaptchaConfig
	metrics     struct {
		totalChallenges   int64
		successfulSolves  int64
		failedSolves      int64
		activeChallenges  int64
		expiredChallenges int64
	}
	mu sync.RWMutex
}

// CaptchaConfig holds configuration for CAPTCHA action
type CaptchaConfig struct {
	Provider    string        `json:"provider"`     // "recaptcha", "hcaptcha", "turnstile", "simple"
	SiteKey     string        `json:"site_key"`     // Public key for the CAPTCHA service
	SecretKey   string        `json:"secret_key"`   // Secret key for verification
	Threshold   float64       `json:"threshold"`    // Score threshold for reCAPTCHA v3
	Duration    time.Duration `json:"duration"`     // How long the CAPTCHA challenge lasts
	MaxAttempts int           `json:"max_attempts"` // Maximum solve attempts
	Difficulty  string        `json:"difficulty"`   // "easy", "medium", "hard"
	Template    string        `json:"template"`     // HTML template for CAPTCHA page
}

// CaptchaChallenge represents an active CAPTCHA challenge
type CaptchaChallenge struct {
	ID          string                 `json:"id"`
	IP          string                 `json:"ip"`
	UserID      string                 `json:"user_id"`
	Provider    string                 `json:"provider"`
	Challenge   string                 `json:"challenge"` // The actual challenge (for simple CAPTCHA)
	Answer      string                 `json:"answer"`    // Expected answer (for simple CAPTCHA)
	Token       string                 `json:"token"`     // Token for verification
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
	Attempts    int                    `json:"attempts"`
	MaxAttempts int                    `json:"max_attempts"`
	Solved      bool                   `json:"solved"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewCaptchaAction creates a new CAPTCHA action plugin
func NewCaptchaAction(stateStore store.StateStore) *CaptchaAction {
	return &CaptchaAction{
		name:        "captcha_action",
		version:     "1.0.0",
		description: "Presents CAPTCHA challenges to verify human users",
		store:       stateStore,
		config: CaptchaConfig{
			Provider:    "simple", // Default to simple math CAPTCHA
			Threshold:   0.5,
			Duration:    10 * time.Minute,
			MaxAttempts: 3,
			Difficulty:  "medium",
			Template:    "", // Will use default template
		},
	}
}

// Name returns the plugin name
func (a *CaptchaAction) Name() string {
	return a.name
}

// Version returns the plugin version
func (a *CaptchaAction) Version() string {
	return a.version
}

// Description returns the plugin description
func (a *CaptchaAction) Description() string {
	return a.description
}

// Initialize initializes the plugin with configuration
func (a *CaptchaAction) Initialize(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Parse provider
	if provider, ok := config["provider"].(string); ok {
		a.config.Provider = provider
	}

	// Parse site key
	if siteKey, ok := config["site_key"].(string); ok {
		a.config.SiteKey = siteKey
	}

	// Parse secret key
	if secretKey, ok := config["secret_key"].(string); ok {
		a.config.SecretKey = secretKey
	}

	// Parse threshold
	if threshold, ok := config["threshold"].(float64); ok {
		a.config.Threshold = threshold
	}

	// Parse duration
	if durationStr, ok := config["duration"].(string); ok {
		if duration, err := time.ParseDuration(durationStr); err == nil {
			a.config.Duration = duration
		}
	}

	// Parse max attempts
	if maxAttempts, ok := config["max_attempts"].(float64); ok {
		a.config.MaxAttempts = int(maxAttempts)
	}

	// Parse difficulty
	if difficulty, ok := config["difficulty"].(string); ok {
		a.config.Difficulty = difficulty
	}

	// Parse template
	if template, ok := config["template"].(string); ok {
		a.config.Template = template
	}

	return nil
}

// Execute executes the CAPTCHA action
func (a *CaptchaAction) Execute(ctx context.Context, reqCtx *plugins.RequestContext, result plugins.RuleResult) error {
	a.mu.RLock()
	config := a.config
	a.mu.RUnlock()

	a.metrics.totalChallenges++

	// Generate challenge ID
	challengeID := fmt.Sprintf("captcha_%d_%s", time.Now().Unix(), reqCtx.IP)

	// Create CAPTCHA challenge based on provider
	challenge, err := a.createChallenge(challengeID, reqCtx, config)
	if err != nil {
		return fmt.Errorf("failed to create CAPTCHA challenge: %w", err)
	}

	// Store challenge
	challengeKey := fmt.Sprintf("captcha:%s", reqCtx.IP)
	err = a.store.Set(ctx, challengeKey, challenge, config.Duration)
	if err != nil {
		return fmt.Errorf("failed to store CAPTCHA challenge: %w", err)
	}

	a.metrics.activeChallenges++

	return nil
}

// createChallenge creates a CAPTCHA challenge based on the provider
func (a *CaptchaAction) createChallenge(challengeID string, reqCtx *plugins.RequestContext, config CaptchaConfig) (CaptchaChallenge, error) {
	challenge := CaptchaChallenge{
		ID:          challengeID,
		IP:          reqCtx.IP,
		UserID:      reqCtx.UserID,
		Provider:    config.Provider,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(config.Duration),
		Attempts:    0,
		MaxAttempts: config.MaxAttempts,
		Solved:      false,
		Metadata: map[string]interface{}{
			"user_agent": reqCtx.UserAgent,
			"path":       reqCtx.Path,
			"method":     reqCtx.Method,
		},
	}

	switch config.Provider {
	case "simple":
		return a.createSimpleChallenge(challenge, config)
	case "recaptcha":
		return a.createRecaptchaChallenge(challenge, config)
	case "hcaptcha":
		return a.createHcaptchaChallenge(challenge, config)
	case "turnstile":
		return a.createTurnstileChallenge(challenge, config)
	default:
		return a.createSimpleChallenge(challenge, config)
	}
}

// createSimpleChallenge creates a simple math-based CAPTCHA
func (a *CaptchaAction) createSimpleChallenge(challenge CaptchaChallenge, config CaptchaConfig) (CaptchaChallenge, error) {
	// Generate simple math problem based on difficulty
	var question, answer string

	switch config.Difficulty {
	case "easy":
		num1, num2 := a.generateNumbers(1, 10)
		question = fmt.Sprintf("What is %d + %d?", num1, num2)
		answer = fmt.Sprintf("%d", num1+num2)
	case "hard":
		num1, num2 := a.generateNumbers(10, 50)
		operation := []string{"+", "-", "*"}[time.Now().Unix()%3]
		switch operation {
		case "+":
			question = fmt.Sprintf("What is %d + %d?", num1, num2)
			answer = fmt.Sprintf("%d", num1+num2)
		case "-":
			if num1 < num2 {
				num1, num2 = num2, num1
			}
			question = fmt.Sprintf("What is %d - %d?", num1, num2)
			answer = fmt.Sprintf("%d", num1-num2)
		case "*":
			num1, num2 = a.generateNumbers(2, 12)
			question = fmt.Sprintf("What is %d × %d?", num1, num2)
			answer = fmt.Sprintf("%d", num1*num2)
		}
	default: // medium
		num1, num2 := a.generateNumbers(5, 25)
		question = fmt.Sprintf("What is %d + %d?", num1, num2)
		answer = fmt.Sprintf("%d", num1+num2)
	}

	challenge.Challenge = question
	challenge.Answer = answer
	challenge.Token = a.generateToken()

	return challenge, nil
}

// createRecaptchaChallenge creates a reCAPTCHA challenge
func (a *CaptchaAction) createRecaptchaChallenge(challenge CaptchaChallenge, config CaptchaConfig) (CaptchaChallenge, error) {
	challenge.Token = a.generateToken()
	challenge.Metadata["site_key"] = config.SiteKey
	challenge.Metadata["threshold"] = config.Threshold
	return challenge, nil
}

// createHcaptchaChallenge creates an hCaptcha challenge
func (a *CaptchaAction) createHcaptchaChallenge(challenge CaptchaChallenge, config CaptchaConfig) (CaptchaChallenge, error) {
	challenge.Token = a.generateToken()
	challenge.Metadata["site_key"] = config.SiteKey
	return challenge, nil
}

// createTurnstileChallenge creates a Cloudflare Turnstile challenge
func (a *CaptchaAction) createTurnstileChallenge(challenge CaptchaChallenge, config CaptchaConfig) (CaptchaChallenge, error) {
	challenge.Token = a.generateToken()
	challenge.Metadata["site_key"] = config.SiteKey
	return challenge, nil
}

// generateNumbers generates random numbers within a range
func (a *CaptchaAction) generateNumbers(min, max int) (int, int) {
	// Simple pseudo-random number generation based on current time
	seed := time.Now().UnixNano()
	num1 := int(seed%int64(max-min+1)) + min
	num2 := int((seed/1000)%int64(max-min+1)) + min
	return num1, num2
}

// generateToken generates a unique token for the challenge
func (a *CaptchaAction) generateToken() string {
	return fmt.Sprintf("token_%d_%d", time.Now().UnixNano(), time.Now().Unix())
}

// GetActiveChallenge retrieves the active CAPTCHA challenge for an IP
func (a *CaptchaAction) GetActiveChallenge(ctx context.Context, ip string) (bool, CaptchaChallenge, error) {
	challengeKey := fmt.Sprintf("captcha:%s", ip)

	challengeData, err := a.store.Get(ctx, challengeKey)
	if err != nil {
		return false, CaptchaChallenge{}, nil // No challenge if key doesn't exist
	}

	if challenge, ok := challengeData.(CaptchaChallenge); ok {
		// Check if challenge is still active
		if time.Now().Before(challenge.ExpiresAt) && !challenge.Solved {
			return true, challenge, nil
		} else {
			// Challenge expired or solved, clean up
			a.store.Delete(ctx, challengeKey)
			if time.Now().After(challenge.ExpiresAt) {
				a.metrics.expiredChallenges++
			}
			a.metrics.activeChallenges--
		}
	}

	return false, CaptchaChallenge{}, nil
}

// VerifyChallenge verifies a CAPTCHA challenge response
func (a *CaptchaAction) VerifyChallenge(ctx context.Context, ip, response string) (bool, error) {
	hasChallenge, challenge, err := a.GetActiveChallenge(ctx, ip)
	if err != nil {
		return false, err
	}

	if !hasChallenge {
		return false, fmt.Errorf("no active challenge found for IP %s", ip)
	}

	// Increment attempts
	challenge.Attempts++

	// Check if max attempts exceeded
	if challenge.Attempts > challenge.MaxAttempts {
		challengeKey := fmt.Sprintf("captcha:%s", ip)
		a.store.Delete(ctx, challengeKey)
		a.metrics.activeChallenges--
		a.metrics.failedSolves++
		return false, fmt.Errorf("maximum attempts exceeded")
	}

	// Verify based on provider
	var verified bool
	switch challenge.Provider {
	case "simple":
		verified = (response == challenge.Answer)
	case "recaptcha", "hcaptcha", "turnstile":
		// In a real implementation, you would verify with the respective service
		// For now, we'll accept any non-empty response
		verified = (response != "")
	default:
		verified = (response == challenge.Answer)
	}

	challengeKey := fmt.Sprintf("captcha:%s", ip)

	if verified {
		// Mark as solved
		challenge.Solved = true
		challenge.Metadata["solved_at"] = time.Now()

		// Store solved challenge for a short time for reference
		a.store.Set(ctx, challengeKey, challenge, time.Hour)

		a.metrics.activeChallenges--
		a.metrics.successfulSolves++
		return true, nil
	} else {
		// Update challenge with new attempt count
		a.store.Set(ctx, challengeKey, challenge, time.Until(challenge.ExpiresAt))

		if challenge.Attempts >= challenge.MaxAttempts {
			a.metrics.failedSolves++
		}

		return false, nil
	}
}

// ClearChallenge manually clears a CAPTCHA challenge for an IP
func (a *CaptchaAction) ClearChallenge(ctx context.Context, ip string) error {
	challengeKey := fmt.Sprintf("captcha:%s", ip)

	if hasChallenge, _, err := a.GetActiveChallenge(ctx, ip); err == nil && hasChallenge {
		a.metrics.activeChallenges--
	}

	return a.store.Delete(ctx, challengeKey)
}

// GetActiveChallenges returns all currently active CAPTCHA challenges
func (a *CaptchaAction) GetActiveChallenges(ctx context.Context) (map[string]CaptchaChallenge, error) {
	keys, err := a.store.Keys(ctx, "captcha:*")
	if err != nil {
		return nil, err
	}

	activeChallenges := make(map[string]CaptchaChallenge)
	for _, key := range keys {
		// Extract IP from key (remove "captcha:" prefix)
		if len(key) > 8 {
			ip := key[8:]
			if hasChallenge, challenge, err := a.GetActiveChallenge(ctx, ip); err == nil && hasChallenge {
				activeChallenges[ip] = challenge
			}
		}
	}

	return activeChallenges, nil
}

// Cleanup cleans up plugin resources
func (a *CaptchaAction) Cleanup() error {
	return nil
}

// Health checks plugin health
func (a *CaptchaAction) Health() error {
	if a.store == nil {
		return fmt.Errorf("state store not initialized")
	}
	return a.store.Health()
}

// GetMetrics returns plugin metrics
func (a *CaptchaAction) GetMetrics() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	successRate := float64(0)
	if a.metrics.totalChallenges > 0 {
		successRate = float64(a.metrics.successfulSolves) / float64(a.metrics.totalChallenges)
	}

	return map[string]interface{}{
		"total_challenges":   a.metrics.totalChallenges,
		"successful_solves":  a.metrics.successfulSolves,
		"failed_solves":      a.metrics.failedSolves,
		"active_challenges":  a.metrics.activeChallenges,
		"expired_challenges": a.metrics.expiredChallenges,
		"success_rate":       successRate,
		"provider":           a.config.Provider,
		"duration":           a.config.Duration.String(),
		"max_attempts":       a.config.MaxAttempts,
		"difficulty":         a.config.Difficulty,
	}
}

func (a *CaptchaAction) Render(ctx context.Context, c *fiber.Ctx, response map[string]any) error {
	ip, _ := response["ip"].(string)
	if hasChallenge, challenge, err := a.GetActiveChallenge(ctx, ip); err == nil && hasChallenge {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":     "CAPTCHA required",
			"message":   "Please complete the CAPTCHA challenge to continue",
			"challenge": challenge.Challenge,
			"token":     challenge.Token,
			"blocked":   true,
			"reason":    "Bot detection - CAPTCHA required",
		})
	}
	// Fallback CAPTCHA response
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error":   "CAPTCHA required",
		"message": "Bot activity detected. CAPTCHA verification required.",
		"blocked": true,
		"reason":  "Bot detection",
	})
}
