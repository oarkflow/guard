package tests

import (
	"context"
	"testing"
	"time"

	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/guard/pkg/plugins/detectors"
	"github.com/oarkflow/guard/pkg/store"
)

func TestProductionRateLimitConfiguration(t *testing.T) {
	// Create memory store with production config
	storeConfig := store.StoreConfig{
		Type:   "memory",
		Prefix: "",
	}
	memStore := store.NewMemoryStore(storeConfig)
	defer memStore.Close()

	// Create rate limit detector
	detector := detectors.NewRateLimitDetector(memStore)

	// Configure with production settings
	config := map[string]any{
		"window_size":    "1m",         // Production: 1 minute window
		"max_requests":   float64(100), // Production: 100 requests limit
		"key_template":   "rate_limit:{ip}",
		"burst_allowed":  float64(10),
		"cleanup_period": "5m",
	}

	err := detector.Initialize(config)
	if err != nil {
		t.Fatalf("Failed to initialize detector: %v", err)
	}

	ctx := context.Background()
	reqCtx := &plugins.RequestContext{
		IP:     "127.0.0.1",
		Method: "GET",
		Path:   "/test",
		UserID: "test-user",
	}

	t.Log("Phase 1: Testing with production rate limit (100 requests/minute)")

	// Send 105 requests rapidly to exceed the limit
	allowedCount := 0
	blockedCount := 0

	for i := 1; i <= 105; i++ {
		result := detector.Detect(ctx, reqCtx)
		if result.Threat {
			blockedCount++
			if i <= 5 || i > 100 { // Log first few and blocked ones
				t.Logf("Request %d: BLOCKED - %s", i, result.Details)
			}
		} else {
			allowedCount++
			if i <= 5 { // Log first few allowed
				t.Logf("Request %d: ALLOWED - %s", i, result.Details)
			}
		}

		// Small delay to simulate realistic request pattern
		time.Sleep(10 * time.Millisecond)
	}

	t.Logf("Initial phase: %d allowed, %d blocked", allowedCount, blockedCount)

	// Should have exactly 100 allowed and 5 blocked
	if allowedCount != 100 {
		t.Errorf("Expected 100 allowed requests, got %d", allowedCount)
	}
	if blockedCount != 5 {
		t.Errorf("Expected 5 blocked requests, got %d", blockedCount)
	}

	t.Log("Phase 2: Waiting for window to expire (65 seconds)...")
	time.Sleep(65 * time.Second) // Wait longer than 1 minute window

	t.Log("Phase 3: Testing after window expiration")

	// Send requests after window expiration - should be allowed again
	postExpiryAllowed := 0
	postExpiryBlocked := 0

	for i := 1; i <= 10; i++ {
		result := detector.Detect(ctx, reqCtx)
		if result.Threat {
			postExpiryBlocked++
			t.Logf("Request %d (after expiry): BLOCKED - %s", i, result.Details)
		} else {
			postExpiryAllowed++
			t.Logf("Request %d (after expiry): ALLOWED - %s", i, result.Details)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// After window expiration, all requests should be allowed initially
	if postExpiryAllowed != 10 {
		t.Errorf("Expected all 10 requests to be allowed after window expiration, got %d allowed, %d blocked",
			postExpiryAllowed, postExpiryBlocked)
	}

	t.Logf("Production test completed successfully: Initial allowed=%d, blocked=%d; Post-expiry allowed=%d, blocked=%d",
		allowedCount, blockedCount, postExpiryAllowed, postExpiryBlocked)
}

func TestQuickRateLimitReset(t *testing.T) {
	// Create memory store
	storeConfig := store.StoreConfig{
		Type:   "memory",
		Prefix: "quick_test:",
	}
	memStore := store.NewMemoryStore(storeConfig)
	defer memStore.Close()

	// Create rate limit detector with very short window
	detector := detectors.NewRateLimitDetector(memStore)

	// Configure with short window for quick testing
	config := map[string]any{
		"window_size":    "3s",       // 3 second window
		"max_requests":   float64(5), // 5 requests limit
		"key_template":   "rate_limit:{ip}",
		"burst_allowed":  float64(2),
		"cleanup_period": "1s",
	}

	err := detector.Initialize(config)
	if err != nil {
		t.Fatalf("Failed to initialize detector: %v", err)
	}

	ctx := context.Background()
	reqCtx := &plugins.RequestContext{
		IP:     "192.168.1.100",
		Method: "GET",
		Path:   "/api/test",
		UserID: "quick-test-user",
	}

	t.Log("Quick test: Sending 8 requests (limit: 5)")

	// Send 8 requests to exceed the limit
	results := make([]plugins.DetectionResult, 8)
	for i := 0; i < 8; i++ {
		results[i] = detector.Detect(ctx, reqCtx)
		status := "ALLOWED"
		if results[i].Threat {
			status = "BLOCKED"
		}
		t.Logf("Request %d: %s - %s", i+1, status, results[i].Details)
		time.Sleep(100 * time.Millisecond)
	}

	// Count results
	allowed := 0
	blocked := 0
	for _, result := range results {
		if result.Threat {
			blocked++
		} else {
			allowed++
		}
	}

	if allowed != 5 || blocked != 3 {
		t.Errorf("Expected 5 allowed and 3 blocked, got %d allowed and %d blocked", allowed, blocked)
	}

	t.Log("Waiting for window to expire (4 seconds)...")
	time.Sleep(4 * time.Second)

	t.Log("Testing after expiration...")

	// Test after expiration
	postResults := make([]plugins.DetectionResult, 3)
	for i := 0; i < 3; i++ {
		postResults[i] = detector.Detect(ctx, reqCtx)
		status := "ALLOWED"
		if postResults[i].Threat {
			status = "BLOCKED"
		}
		t.Logf("Post-expiry request %d: %s - %s", i+1, status, postResults[i].Details)
		time.Sleep(100 * time.Millisecond)
	}

	// All should be allowed after expiration
	for i, result := range postResults {
		if result.Threat {
			t.Errorf("Request %d should be allowed after window expiration but was blocked: %s", i+1, result.Details)
		}
	}

	t.Log("Quick test completed successfully - window reset working correctly")
}
