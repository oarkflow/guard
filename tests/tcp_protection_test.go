package tests

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/oarkflow/guard/pkg/store"
	"github.com/oarkflow/guard/pkg/tcp"
)

func TestTCPProtection(t *testing.T) {
	// Create memory store
	storeFactory := store.NewStoreFactory()
	stateStore, err := storeFactory.CreateStore(store.StoreConfig{
		Type:    "memory",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create state store: %v", err)
	}
	defer stateStore.Close()

	// Create TCP protection config
	config := tcp.TCPProtectionConfig{
		EnableTCPProtection:  true,
		ConnectionRateLimit:  5, // Low limit for testing
		ConnectionWindow:     10 * time.Second,
		SilentDropThreshold:  3,
		TarpitThreshold:      4,
		TarpitDelay:          100 * time.Millisecond,
		MaxTarpitConnections: 2,
		BruteForceThreshold:  3,
		BruteForceWindow:     30 * time.Second,
		CleanupInterval:      5 * time.Second,
		WhitelistedIPs:       []string{"127.0.0.1"},
		BlacklistedIPs:       []string{"192.168.1.100"},
	}

	// Create TCP protection
	protection := tcp.NewTCPProtection(config, stateStore)
	defer protection.Shutdown()

	ctx := context.Background()

	t.Run("WhitelistedIP", func(t *testing.T) {
		addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
		action, connInfo, err := protection.CheckConnection(ctx, addr)
		if err != nil {
			t.Fatalf("CheckConnection failed: %v", err)
		}
		if action != tcp.ActionAllow {
			t.Errorf("Expected ActionAllow for whitelisted IP, got %s", action.String())
		}
		if !connInfo.IsWhitelisted {
			t.Error("Expected connection to be marked as whitelisted")
		}
	})

	t.Run("BlacklistedIP", func(t *testing.T) {
		addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
		action, connInfo, err := protection.CheckConnection(ctx, addr)
		if err != nil {
			t.Fatalf("CheckConnection failed: %v", err)
		}
		if action != tcp.ActionBlock {
			t.Errorf("Expected ActionBlock for blacklisted IP, got %s", action.String())
		}
		if !connInfo.IsBlacklisted {
			t.Error("Expected connection to be marked as blacklisted")
		}
	})

	t.Run("RateLimitProgression", func(t *testing.T) {
		testIP := "10.0.0.1"
		addr := &net.TCPAddr{IP: net.ParseIP(testIP), Port: 12345}

		// First few connections should be allowed
		for i := 1; i <= 2; i++ {
			action, connInfo, err := protection.CheckConnection(ctx, addr)
			if err != nil {
				t.Fatalf("CheckConnection %d failed: %v", i, err)
			}
			if action != tcp.ActionAllow {
				t.Errorf("Connection %d: Expected ActionAllow, got %s", i, action.String())
			}
			t.Logf("Connection %d: %s (count: %d)", i, action.String(), connInfo.ConnectionCount)
		}

		// Next connection should trigger silent drop
		action, connInfo, err := protection.CheckConnection(ctx, addr)
		if err != nil {
			t.Fatalf("CheckConnection for drop failed: %v", err)
		}
		if action != tcp.ActionDrop {
			t.Errorf("Expected ActionDrop, got %s", action.String())
		}
		t.Logf("Drop action: %s (count: %d)", action.String(), connInfo.ConnectionCount)

		// Next connection should trigger tarpit
		action, connInfo, err = protection.CheckConnection(ctx, addr)
		if err != nil {
			t.Fatalf("CheckConnection for tarpit failed: %v", err)
		}
		if action != tcp.ActionTarpit {
			t.Errorf("Expected ActionTarpit, got %s", action.String())
		}
		t.Logf("Tarpit action: %s (count: %d)", action.String(), connInfo.ConnectionCount)

		// Final connection should trigger block
		action, connInfo, err = protection.CheckConnection(ctx, addr)
		if err != nil {
			t.Fatalf("CheckConnection for block failed: %v", err)
		}
		if action != tcp.ActionBlock {
			t.Errorf("Expected ActionBlock, got %s", action.String())
		}
		t.Logf("Block action: %s (count: %d)", action.String(), connInfo.ConnectionCount)
	})

	t.Run("BruteForceDetection", func(t *testing.T) {
		testIP := "10.0.0.2"
		addr := &net.TCPAddr{IP: net.ParseIP(testIP), Port: 12345}

		// Record failed attempts
		for i := 1; i <= 3; i++ {
			err := protection.RecordFailedConnection(ctx, addr)
			if err != nil {
				t.Fatalf("RecordFailedConnection %d failed: %v", i, err)
			}
		}

		// Next connection should be blocked due to brute force
		action, connInfo, err := protection.CheckConnection(ctx, addr)
		if err != nil {
			t.Fatalf("CheckConnection after brute force failed: %v", err)
		}
		if action != tcp.ActionBlock {
			t.Errorf("Expected ActionBlock for brute force, got %s", action.String())
		}
		t.Logf("Brute force block: %s (failed attempts: %d)", action.String(), connInfo.FailedAttempts)
	})

	t.Run("Metrics", func(t *testing.T) {
		metrics := protection.GetMetrics()
		t.Logf("TCP Protection Metrics:")
		t.Logf("  Total Connections: %d", metrics.TotalConnections)
		t.Logf("  Allowed: %d", metrics.AllowedConnections)
		t.Logf("  Dropped: %d", metrics.DroppedConnections)
		t.Logf("  Tarpitted: %d", metrics.TarpitConnections)
		t.Logf("  Blocked: %d", metrics.BlockedConnections)
		t.Logf("  Active Tarpits: %d", metrics.ActiveTarpits)
		t.Logf("  Brute Force Detections: %d", metrics.BruteForceDetections)

		if metrics.TotalConnections == 0 {
			t.Error("Expected some total connections")
		}
	})

	t.Run("ActiveConnections", func(t *testing.T) {
		connections := protection.GetActiveConnections()
		t.Logf("Active Connections: %d", len(connections))
		for addr, connInfo := range connections {
			t.Logf("  %s: %s (count: %d, failed: %d)",
				addr, connInfo.Action.String(), connInfo.ConnectionCount, connInfo.FailedAttempts)
		}
	})

	t.Run("WhitelistManagement", func(t *testing.T) {
		testIP := "10.0.0.3"

		// Initially not whitelisted
		if protection.IsIPWhitelisted(testIP) {
			t.Error("IP should not be whitelisted initially")
		}

		// Add to whitelist
		protection.AddToWhitelist(testIP)
		if !protection.IsIPWhitelisted(testIP) {
			t.Error("IP should be whitelisted after adding")
		}

		// Test connection is allowed
		addr := &net.TCPAddr{IP: net.ParseIP(testIP), Port: 12345}
		action, connInfo, err := protection.CheckConnection(ctx, addr)
		if err != nil {
			t.Fatalf("CheckConnection for whitelisted IP failed: %v", err)
		}
		if action != tcp.ActionAllow {
			t.Errorf("Expected ActionAllow for whitelisted IP, got %s", action.String())
		}
		if !connInfo.IsWhitelisted {
			t.Error("Connection should be marked as whitelisted")
		}

		// Remove from whitelist
		protection.RemoveFromWhitelist(testIP)
		if protection.IsIPWhitelisted(testIP) {
			t.Error("IP should not be whitelisted after removal")
		}
	})

	t.Run("BlacklistManagement", func(t *testing.T) {
		testIP := "10.0.0.4"

		// Initially not blacklisted
		if protection.IsIPBlacklisted(testIP) {
			t.Error("IP should not be blacklisted initially")
		}

		// Add to blacklist
		protection.AddToBlacklist(testIP)
		if !protection.IsIPBlacklisted(testIP) {
			t.Error("IP should be blacklisted after adding")
		}

		// Test connection is blocked
		addr := &net.TCPAddr{IP: net.ParseIP(testIP), Port: 12345}
		action, connInfo, err := protection.CheckConnection(ctx, addr)
		if err != nil {
			t.Fatalf("CheckConnection for blacklisted IP failed: %v", err)
		}
		if action != tcp.ActionBlock {
			t.Errorf("Expected ActionBlock for blacklisted IP, got %s", action.String())
		}
		if !connInfo.IsBlacklisted {
			t.Error("Connection should be marked as blacklisted")
		}

		// Remove from blacklist
		protection.RemoveFromBlacklist(testIP)
		if protection.IsIPBlacklisted(testIP) {
			t.Error("IP should not be blacklisted after removal")
		}
	})
}

func TestTCPMiddleware(t *testing.T) {
	// Create memory store
	storeFactory := store.NewStoreFactory()
	stateStore, err := storeFactory.CreateStore(store.StoreConfig{
		Type:    "memory",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create state store: %v", err)
	}
	defer stateStore.Close()

	// Create TCP protection config
	config := tcp.TCPProtectionConfig{
		EnableTCPProtection:  true,
		ConnectionRateLimit:  3,
		ConnectionWindow:     10 * time.Second,
		SilentDropThreshold:  2,
		TarpitThreshold:      2,
		TarpitDelay:          50 * time.Millisecond,
		MaxTarpitConnections: 1,
		BruteForceThreshold:  2,
		BruteForceWindow:     30 * time.Second,
		CleanupInterval:      5 * time.Second,
		WhitelistedIPs:       []string{},
		BlacklistedIPs:       []string{},
	}

	// Create TCP middleware
	middleware := tcp.NewTCPMiddleware(config, stateStore, nil)

	t.Run("MiddlewareMetrics", func(t *testing.T) {
		metrics := middleware.GetMetrics()
		t.Logf("Middleware Metrics:")
		t.Logf("  Total Connections: %d", metrics.TotalConnections)
		t.Logf("  Allowed: %d", metrics.AllowedConnections)
		t.Logf("  Dropped: %d", metrics.DroppedConnections)
		t.Logf("  Tarpitted: %d", metrics.TarpitConnections)
		t.Logf("  Blocked: %d", metrics.BlockedConnections)
	})

	t.Run("MiddlewareActiveConnections", func(t *testing.T) {
		connections := middleware.GetActiveConnections()
		t.Logf("Active Connections: %d", len(connections))
	})

	t.Run("ProtectionAccess", func(t *testing.T) {
		protection := middleware.GetProtection()
		if protection == nil {
			t.Error("Expected protection instance from middleware")
		}

		// Test whitelist operations
		testIP := "192.168.1.1"
		protection.AddToWhitelist(testIP)
		if !protection.IsIPWhitelisted(testIP) {
			t.Error("IP should be whitelisted")
		}
		protection.RemoveFromWhitelist(testIP)
		if protection.IsIPWhitelisted(testIP) {
			t.Error("IP should not be whitelisted after removal")
		}
	})
}

func TestTCPListener(t *testing.T) {
	// Create memory store
	storeFactory := store.NewStoreFactory()
	stateStore, err := storeFactory.CreateStore(store.StoreConfig{
		Type:    "memory",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create state store: %v", err)
	}
	defer stateStore.Close()

	// Create TCP protection config
	config := tcp.TCPProtectionConfig{
		EnableTCPProtection:  true,
		ConnectionRateLimit:  10,
		ConnectionWindow:     10 * time.Second,
		SilentDropThreshold:  5,
		TarpitThreshold:      7,
		TarpitDelay:          10 * time.Millisecond,
		MaxTarpitConnections: 2,
		BruteForceThreshold:  5,
		BruteForceWindow:     30 * time.Second,
		CleanupInterval:      5 * time.Second,
		WhitelistedIPs:       []string{"127.0.0.1"},
		BlacklistedIPs:       []string{},
	}

	t.Run("TCPServerCreation", func(t *testing.T) {
		// Test TCP server creation
		server, err := tcp.NewTCPServer("127.0.0.1:0", config, stateStore, nil)
		if err != nil {
			t.Fatalf("Failed to create TCP server: %v", err)
		}
		defer server.Shutdown()

		// Test metrics
		metrics := server.GetMetrics()
		t.Logf("Server Metrics:")
		t.Logf("  Total Connections: %d", metrics.TotalConnections)

		// Test active connections
		connections := server.GetActiveConnections()
		t.Logf("Server Active Connections: %d", len(connections))
	})

	t.Run("ConnectionHandlerInterface", func(t *testing.T) {
		// Test default connection handler
		handler := &tcp.DefaultConnectionHandler{}

		// Create a mock connection info
		connInfo := &tcp.TCPConnectionInfo{
			IP:     "127.0.0.1",
			Action: tcp.ActionAllow,
		}

		// This would normally handle a real connection, but we can't easily test that
		// without setting up actual network connections
		t.Logf("Handler created successfully for action: %s", connInfo.Action.String())

		// Use the handler to avoid unused variable warning
		if handler == nil {
			t.Error("Handler should not be nil")
		}
	})
}

func BenchmarkTCPProtection(b *testing.B) {
	// Create memory store
	storeFactory := store.NewStoreFactory()
	stateStore, err := storeFactory.CreateStore(store.StoreConfig{
		Type:    "memory",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		b.Fatalf("Failed to create state store: %v", err)
	}
	defer stateStore.Close()

	// Create TCP protection config
	config := tcp.TCPProtectionConfig{
		EnableTCPProtection:  true,
		ConnectionRateLimit:  1000,
		ConnectionWindow:     60 * time.Second,
		SilentDropThreshold:  500,
		TarpitThreshold:      750,
		TarpitDelay:          1 * time.Millisecond,
		MaxTarpitConnections: 10,
		BruteForceThreshold:  100,
		BruteForceWindow:     300 * time.Second,
		CleanupInterval:      60 * time.Second,
		WhitelistedIPs:       []string{},
		BlacklistedIPs:       []string{},
	}

	protection := tcp.NewTCPProtection(config, stateStore)
	defer protection.Shutdown()

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// Use different IPs to avoid hitting rate limits
			ip := fmt.Sprintf("10.0.%d.%d", (i/256)%256, i%256)
			addr := &net.TCPAddr{IP: net.ParseIP(ip), Port: 12345}

			_, _, err := protection.CheckConnection(ctx, addr)
			if err != nil {
				b.Errorf("CheckConnection failed: %v", err)
			}
			i++
		}
	})
}
