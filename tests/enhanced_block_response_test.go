package tests

import (
	"context"
	"testing"
	"time"

	"github.com/oarkflow/guard/pkg/plugins"
	"github.com/oarkflow/guard/pkg/plugins/actions"
	"github.com/oarkflow/guard/pkg/store"
)

func TestEnhancedBlockResponse(t *testing.T) {
	// Create memory store
	storeConfig := store.StoreConfig{
		Type:   "memory",
		Prefix: "block_test:",
	}
	memStore := store.NewMemoryStore(storeConfig)
	defer memStore.Close()

	// Create block action
	blockAction := actions.NewBlockAction(memStore)

	// Initialize with test configuration
	config := map[string]any{
		"default_duration": "5m",
		"max_duration":     "24h",
		"block_message":    "Access denied due to security policy violation",
		"log_blocks":       true,
	}

	err := blockAction.Initialize(config)
	if err != nil {
		t.Fatalf("Failed to initialize block action: %v", err)
	}

	ctx := context.Background()
	reqCtx := &plugins.RequestContext{
		IP:     "192.168.1.200",
		Method: "GET",
		Path:   "/api/test",
		UserID: "test-user",
	}

	// Create a rule result to trigger blocking
	ruleResult := plugins.RuleResult{
		Triggered:  true,
		Action:     "block_action",
		Confidence: 0.9,
		Details:    "Rate limit exceeded: 105 requests in window (limit: 100)",
		RuleName:   "rate_limit_block",
		Severity:   5,
		Metadata: map[string]any{
			"current_count": 105,
			"max_requests":  100,
		},
	}

	t.Log("Phase 1: Testing initial block")

	// Execute block action
	err = blockAction.Execute(ctx, reqCtx, ruleResult)
	if err != nil {
		t.Fatalf("Failed to execute block action: %v", err)
	}

	// Get detailed block information
	blockDetails, err := blockAction.GetDetailedBlockInfo(ctx, reqCtx.IP)
	if err != nil {
		t.Fatalf("Failed to get block details: %v", err)
	}

	if blockDetails == nil {
		t.Fatal("Expected block details but got nil")
	}

	// Verify block details
	if !blockDetails.IsBlocked {
		t.Error("Expected IP to be blocked")
	}

	if blockDetails.IsPermanent {
		t.Error("Expected temporary block, got permanent")
	}

	if blockDetails.ViolationCount != 1 {
		t.Errorf("Expected violation count 1, got %d", blockDetails.ViolationCount)
	}

	if blockDetails.RemainingTime <= 0 {
		t.Error("Expected positive remaining time for temporary block")
	}

	// Test user message formatting
	message := blockDetails.FormatUserMessage()
	t.Logf("User message: %s", message)

	if message == "" {
		t.Error("Expected non-empty user message")
	}

	t.Log("Phase 2: Testing multiple violations for escalation")

	// Trigger multiple violations to test escalation
	for i := 2; i <= 5; i++ {
		ruleResult.Details = "Additional violation"
		err = blockAction.Execute(ctx, reqCtx, ruleResult)
		if err != nil {
			t.Fatalf("Failed to execute block action for violation %d: %v", i, err)
		}
	}

	// Get updated block details
	blockDetails, err = blockAction.GetDetailedBlockInfo(ctx, reqCtx.IP)
	if err != nil {
		t.Fatalf("Failed to get updated block details: %v", err)
	}

	if blockDetails.ViolationCount != 5 {
		t.Errorf("Expected violation count 5, got %d", blockDetails.ViolationCount)
	}

	// Test message for escalated block
	escalatedMessage := blockDetails.FormatUserMessage()
	t.Logf("Escalated message: %s", escalatedMessage)

	t.Log("Phase 3: Testing permanent block scenario")

	// Create a new IP for permanent block testing
	permanentReqCtx := &plugins.RequestContext{
		IP:     "192.168.1.201",
		Method: "GET",
		Path:   "/api/test",
		UserID: "permanent-test-user",
	}

	// Trigger enough violations to cause permanent block (20+ violations)
	for i := 1; i <= 25; i++ {
		ruleResult.Details = "Severe violation"
		err = blockAction.Execute(ctx, permanentReqCtx, ruleResult)
		if err != nil {
			t.Fatalf("Failed to execute block action for permanent violation %d: %v", i, err)
		}
	}

	// Get permanent block details
	permanentBlockDetails, err := blockAction.GetDetailedBlockInfo(ctx, permanentReqCtx.IP)
	if err != nil {
		t.Fatalf("Failed to get permanent block details: %v", err)
	}

	if !permanentBlockDetails.IsPermanent {
		t.Error("Expected permanent block after 25 violations")
	}

	permanentMessage := permanentBlockDetails.FormatUserMessage()
	t.Logf("Permanent block message: %s", permanentMessage)

	if permanentMessage == "" {
		t.Error("Expected non-empty permanent block message")
	}

	t.Log("Phase 4: Testing block expiration")

	// Create a short-duration block for expiration testing
	shortBlockAction := actions.NewBlockAction(memStore)
	shortConfig := map[string]any{
		"default_duration": "2s", // Very short for testing
		"max_duration":     "10s",
		"block_message":    "Short test block",
		"log_blocks":       true,
	}

	err = shortBlockAction.Initialize(shortConfig)
	if err != nil {
		t.Fatalf("Failed to initialize short block action: %v", err)
	}

	shortReqCtx := &plugins.RequestContext{
		IP:     "192.168.1.202",
		Method: "GET",
		Path:   "/api/test",
		UserID: "short-test-user",
	}

	// Execute short block
	err = shortBlockAction.Execute(ctx, shortReqCtx, ruleResult)
	if err != nil {
		t.Fatalf("Failed to execute short block action: %v", err)
	}

	// Verify block exists
	shortBlockDetails, err := shortBlockAction.GetDetailedBlockInfo(ctx, shortReqCtx.IP)
	if err != nil {
		t.Fatalf("Failed to get short block details: %v", err)
	}

	if !shortBlockDetails.IsBlocked {
		t.Error("Expected IP to be blocked initially")
	}

	initialRemainingTime := shortBlockDetails.RemainingTime
	t.Logf("Initial remaining time: %v", initialRemainingTime)

	// Wait for block to expire
	time.Sleep(3 * time.Second)

	// Check if block has expired
	expiredBlockDetails, err := shortBlockAction.GetDetailedBlockInfo(ctx, shortReqCtx.IP)
	if err != nil {
		t.Fatalf("Failed to get expired block details: %v", err)
	}

	if expiredBlockDetails != nil && expiredBlockDetails.IsBlocked && expiredBlockDetails.RemainingTime > 0 {
		t.Error("Expected block to have expired")
	}

	t.Log("Enhanced block response test completed successfully")
}

// Note: Duration formatting is tested indirectly through FormatUserMessage()
