package tests

import (
	"context"
	"testing"
	"time"

	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/guard/pkg/plugins/detectors"
	"github.com/oarkflow/guard/pkg/store"
)

func TestRateLimitWindowExpiration(t *testing.T) {
	// Create memory store
	storeConfig := store.StoreConfig{
		Type:   "memory",
		Prefix: "test:",
	}
	memStore := store.NewMemoryStore(storeConfig)
	defer memStore.Close()

	// Create rate limit detector with short window for testing
	detector := detectors.NewRateLimitDetector(memStore)

	// Configure with very short window for testing
	config := map[string]any{
		"window_size":    "2s",       // 2 second window
		"max_requests":   float64(3), // Allow only 3 requests
		"key_template":   "rate_limit:{ip}",
		"burst_allowed":  float64(1),
		"cleanup_period": "1s",
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

	t.Log("Phase 1: Testing rate limit detection")

	// Send requests to trigger rate limit
	allowedCount := 0
	blockedCount := 0

	for i := 1; i <= 5; i++ {
		result := detector.Detect(ctx, reqCtx)
		if result.Threat {
			blockedCount++
			t.Logf("Request %d: BLOCKED - %s", i, result.Details)
		} else {
			allowedCount++
			t.Logf("Request %d: ALLOWED - %s", i, result.Details)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Should have some blocked requests
	if blockedCount == 0 {
		t.Error("Expected some requests to be blocked, but none were")
	}

	t.Log("Phase 2: Waiting for window to expire...")
	time.Sleep(3 * time.Second) // Wait longer than window size

	t.Log("Phase 3: Testing after window expiration")

	// Send requests after window expiration - should be allowed again
	postExpiryAllowed := 0
	postExpiryBlocked := 0

	for i := 1; i <= 3; i++ {
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

	// After window expiration, first few requests should be allowed
	if postExpiryAllowed == 0 {
		t.Error("Expected requests to be allowed after window expiration, but none were")
	}

	t.Logf("Test completed: Initial allowed=%d, blocked=%d; Post-expiry allowed=%d, blocked=%d",
		allowedCount, blockedCount, postExpiryAllowed, postExpiryBlocked)
}

func TestMemoryStoreIncrementWithTTL(t *testing.T) {
	storeConfig := store.StoreConfig{
		Type:   "memory",
		Prefix: "test:",
	}
	memStore := store.NewMemoryStore(storeConfig)
	defer memStore.Close()

	ctx := context.Background()
	key := "test_key"
	ttl := 2 * time.Second

	// Test increment with TTL on new key
	count1, err := memStore.IncrementWithTTL(ctx, key, 1, ttl)
	if err != nil {
		t.Fatalf("Failed to increment new key: %v", err)
	}
	if count1 != 1 {
		t.Errorf("Expected count 1, got %d", count1)
	}

	// Test increment on existing key (should preserve TTL)
	count2, err := memStore.IncrementWithTTL(ctx, key, 1, ttl)
	if err != nil {
		t.Fatalf("Failed to increment existing key: %v", err)
	}
	if count2 != 2 {
		t.Errorf("Expected count 2, got %d", count2)
	}

	// Wait for TTL to expire
	time.Sleep(3 * time.Second)

	// Key should be expired and increment should start from 1 again
	count3, err := memStore.IncrementWithTTL(ctx, key, 1, ttl)
	if err != nil {
		t.Fatalf("Failed to increment after expiry: %v", err)
	}
	if count3 != 1 {
		t.Errorf("Expected count to reset to 1 after expiry, got %d", count3)
	}

	t.Log("Memory store TTL test passed")
}
