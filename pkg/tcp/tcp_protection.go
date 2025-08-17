package tcp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/oarkflow/guard/pkg/store"
	"github.com/oarkflow/log"
)

// TCPProtectionAction defines the action to take for a connection
type TCPProtectionAction int

const (
	ActionAllow TCPProtectionAction = iota
	ActionDrop
	ActionTarpit
	ActionBlock
)

func (a TCPProtectionAction) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionDrop:
		return "drop"
	case ActionTarpit:
		return "tarpit"
	case ActionBlock:
		return "block"
	default:
		return "unknown"
	}
}

// TCPProtectionConfig holds configuration for TCP-level protection
type TCPProtectionConfig struct {
	EnableTCPProtection  bool          `json:"enable_tcp_protection"`
	ConnectionRateLimit  int64         `json:"connection_rate_limit"`  // connections per minute per IP
	ConnectionWindow     time.Duration `json:"connection_window"`      // time window for rate limiting
	SilentDropThreshold  int64         `json:"silent_drop_threshold"`  // connections before silent drop
	TarpitThreshold      int64         `json:"tarpit_threshold"`       // connections before tarpit
	TarpitDelay          time.Duration `json:"tarpit_delay"`           // delay for tarpit connections
	MaxTarpitConnections int           `json:"max_tarpit_connections"` // max concurrent tarpit connections
	BruteForceThreshold  int64         `json:"brute_force_threshold"`  // failed connections before blocking
	BruteForceWindow     time.Duration `json:"brute_force_window"`     // time window for brute force detection
	CleanupInterval      time.Duration `json:"cleanup_interval"`       // cleanup interval for expired entries
	WhitelistedIPs       []string      `json:"whitelisted_ips"`        // IPs to never block
	BlacklistedIPs       []string      `json:"blacklisted_ips"`        // IPs to always block
}

// TCPConnectionInfo holds information about a TCP connection
type TCPConnectionInfo struct {
	IP              string
	Port            int
	ConnectedAt     time.Time
	LastActivity    time.Time
	ConnectionCount int64
	FailedAttempts  int64
	Action          TCPProtectionAction
	TarpitStartTime time.Time
	IsWhitelisted   bool
	IsBlacklisted   bool
}

// TCPProtection provides TCP-level DDoS protection
type TCPProtection struct {
	config            TCPProtectionConfig
	store             store.StateStore
	activeConnections map[string]*TCPConnectionInfo
	tarpitConnections map[string]*TCPConnectionInfo
	whitelistMap      map[string]bool
	blacklistMap      map[string]bool
	mu                sync.RWMutex
	stopCleanup       chan struct{}
	metrics           TCPMetrics
}

// TCPMetrics holds metrics for TCP protection
type TCPMetrics struct {
	TotalConnections     int64 `json:"total_connections"`
	AllowedConnections   int64 `json:"allowed_connections"`
	DroppedConnections   int64 `json:"dropped_connections"`
	TarpitConnections    int64 `json:"tarpit_connections"`
	BlockedConnections   int64 `json:"blocked_connections"`
	ActiveTarpits        int64 `json:"active_tarpits"`
	BruteForceDetections int64 `json:"brute_force_detections"`
}

// NewTCPProtection creates a new TCP protection instance
func NewTCPProtection(config TCPProtectionConfig, stateStore store.StateStore) *TCPProtection {
	tcp := &TCPProtection{
		config:            config,
		store:             stateStore,
		activeConnections: make(map[string]*TCPConnectionInfo),
		tarpitConnections: make(map[string]*TCPConnectionInfo),
		whitelistMap:      make(map[string]bool),
		blacklistMap:      make(map[string]bool),
		stopCleanup:       make(chan struct{}),
	}

	// Build whitelist map
	for _, ip := range config.WhitelistedIPs {
		tcp.whitelistMap[ip] = true
	}

	// Build blacklist map
	for _, ip := range config.BlacklistedIPs {
		tcp.blacklistMap[ip] = true
	}

	// Start cleanup goroutine
	go tcp.cleanupRoutine()

	return tcp
}

// CheckConnection evaluates a new TCP connection and returns the action to take
func (tcp *TCPProtection) CheckConnection(ctx context.Context, remoteAddr net.Addr) (TCPProtectionAction, *TCPConnectionInfo, error) {
	if !tcp.config.EnableTCPProtection {
		return ActionAllow, nil, nil
	}

	// Extract IP from address
	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		return ActionAllow, nil, fmt.Errorf("failed to parse remote address: %w", err)
	}

	tcp.mu.Lock()
	defer tcp.mu.Unlock()

	tcp.metrics.TotalConnections++

	// Check whitelist first
	if tcp.whitelistMap[ip] {
		connInfo := &TCPConnectionInfo{
			IP:            ip,
			ConnectedAt:   time.Now(),
			LastActivity:  time.Now(),
			Action:        ActionAllow,
			IsWhitelisted: true,
		}
		tcp.activeConnections[remoteAddr.String()] = connInfo
		tcp.metrics.AllowedConnections++
		return ActionAllow, connInfo, nil
	}

	// Check blacklist
	if tcp.blacklistMap[ip] {
		connInfo := &TCPConnectionInfo{
			IP:            ip,
			ConnectedAt:   time.Now(),
			Action:        ActionBlock,
			IsBlacklisted: true,
		}
		tcp.metrics.BlockedConnections++
		return ActionBlock, connInfo, nil
	}

	// Get connection count for this IP
	connectionKey := fmt.Sprintf("tcp_conn:%s", ip)
	connectionCount, err := tcp.store.IncrementWithTTL(ctx, connectionKey, 1, tcp.config.ConnectionWindow)
	if err != nil {
		log.Error().Str("ip", ip).Err(err).Msg("Failed to increment connection count")
		connectionCount = 1
	}

	// Get failed attempts count
	bruteForceKey := fmt.Sprintf("tcp_brute:%s", ip)
	failedAttempts, err := tcp.store.Get(ctx, bruteForceKey)
	if err != nil {
		failedAttempts = int64(0)
	}

	failedCount, ok := failedAttempts.(int64)
	if !ok {
		failedCount = 0
	}

	// Determine action based on thresholds
	action := tcp.determineAction(connectionCount, failedCount)

	connInfo := &TCPConnectionInfo{
		IP:              ip,
		ConnectedAt:     time.Now(),
		LastActivity:    time.Now(),
		ConnectionCount: connectionCount,
		FailedAttempts:  failedCount,
		Action:          action,
	}

	// Store connection info
	tcp.activeConnections[remoteAddr.String()] = connInfo

	// Handle tarpit connections
	if action == ActionTarpit {
		tcp.handleTarpitConnection(connInfo)
	}

	// Update metrics
	switch action {
	case ActionAllow:
		tcp.metrics.AllowedConnections++
	case ActionDrop:
		tcp.metrics.DroppedConnections++
	case ActionTarpit:
		tcp.metrics.TarpitConnections++
	case ActionBlock:
		tcp.metrics.BlockedConnections++
	}

	return action, connInfo, nil
}

// determineAction determines what action to take based on connection patterns
func (tcp *TCPProtection) determineAction(connectionCount, failedAttempts int64) TCPProtectionAction {
	// Check for brute force first
	if failedAttempts >= tcp.config.BruteForceThreshold {
		tcp.metrics.BruteForceDetections++
		return ActionBlock
	}

	// Check connection rate thresholds
	if connectionCount >= tcp.config.ConnectionRateLimit {
		return ActionBlock
	}

	if connectionCount >= tcp.config.TarpitThreshold {
		// Check if we have capacity for more tarpit connections
		if len(tcp.tarpitConnections) < tcp.config.MaxTarpitConnections {
			return ActionTarpit
		} else {
			return ActionDrop // Fall back to drop if tarpit is full
		}
	}

	if connectionCount >= tcp.config.SilentDropThreshold {
		return ActionDrop
	}

	return ActionAllow
}

// handleTarpitConnection manages a connection in tarpit mode
func (tcp *TCPProtection) handleTarpitConnection(connInfo *TCPConnectionInfo) {
	connInfo.TarpitStartTime = time.Now()
	tcp.tarpitConnections[connInfo.IP] = connInfo
	tcp.metrics.ActiveTarpits++

	// Start tarpit delay in a goroutine
	go func() {
		time.Sleep(tcp.config.TarpitDelay)
		tcp.mu.Lock()
		delete(tcp.tarpitConnections, connInfo.IP)
		tcp.metrics.ActiveTarpits--
		tcp.mu.Unlock()
	}()
}

// RecordFailedConnection records a failed connection attempt for brute force detection
func (tcp *TCPProtection) RecordFailedConnection(ctx context.Context, remoteAddr net.Addr) error {
	if !tcp.config.EnableTCPProtection {
		return nil
	}

	ip, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		return fmt.Errorf("failed to parse remote address: %w", err)
	}

	// Don't track failures for whitelisted IPs
	if tcp.whitelistMap[ip] {
		return nil
	}

	bruteForceKey := fmt.Sprintf("tcp_brute:%s", ip)
	_, err = tcp.store.IncrementWithTTL(ctx, bruteForceKey, 1, tcp.config.BruteForceWindow)
	if err != nil {
		log.Error().Str("ip", ip).Err(err).Msg("Failed to increment brute force count")
	}

	return nil
}

// CloseConnection removes a connection from tracking
func (tcp *TCPProtection) CloseConnection(remoteAddr net.Addr) {
	tcp.mu.Lock()
	defer tcp.mu.Unlock()

	addrStr := remoteAddr.String()
	if connInfo, exists := tcp.activeConnections[addrStr]; exists {
		// Remove from tarpit if it was tarpitted
		if connInfo.Action == ActionTarpit {
			delete(tcp.tarpitConnections, connInfo.IP)
			tcp.metrics.ActiveTarpits--
		}
		delete(tcp.activeConnections, addrStr)
	}
}

// UpdateActivity updates the last activity time for a connection
func (tcp *TCPProtection) UpdateActivity(remoteAddr net.Addr) {
	tcp.mu.Lock()
	defer tcp.mu.Unlock()

	addrStr := remoteAddr.String()
	if connInfo, exists := tcp.activeConnections[addrStr]; exists {
		connInfo.LastActivity = time.Now()
	}
}

// GetMetrics returns current TCP protection metrics
func (tcp *TCPProtection) GetMetrics() TCPMetrics {
	tcp.mu.RLock()
	defer tcp.mu.RUnlock()
	return tcp.metrics
}

// GetActiveConnections returns information about active connections
func (tcp *TCPProtection) GetActiveConnections() map[string]*TCPConnectionInfo {
	tcp.mu.RLock()
	defer tcp.mu.RUnlock()

	result := make(map[string]*TCPConnectionInfo)
	for k, v := range tcp.activeConnections {
		result[k] = v
	}
	return result
}

// cleanupRoutine periodically cleans up expired connections
func (tcp *TCPProtection) cleanupRoutine() {
	ticker := time.NewTicker(tcp.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tcp.cleanup()
		case <-tcp.stopCleanup:
			return
		}
	}
}

// cleanup removes stale connections
func (tcp *TCPProtection) cleanup() {
	tcp.mu.Lock()
	defer tcp.mu.Unlock()

	now := time.Now()
	staleThreshold := 5 * time.Minute // Consider connections stale after 5 minutes of inactivity

	for addr, connInfo := range tcp.activeConnections {
		if now.Sub(connInfo.LastActivity) > staleThreshold {
			// Remove from tarpit if it was tarpitted
			if connInfo.Action == ActionTarpit {
				delete(tcp.tarpitConnections, connInfo.IP)
				tcp.metrics.ActiveTarpits--
			}
			delete(tcp.activeConnections, addr)
		}
	}
}

// Shutdown stops the TCP protection system
func (tcp *TCPProtection) Shutdown() {
	close(tcp.stopCleanup)
}

// IsIPWhitelisted checks if an IP is whitelisted
func (tcp *TCPProtection) IsIPWhitelisted(ip string) bool {
	tcp.mu.RLock()
	defer tcp.mu.RUnlock()
	return tcp.whitelistMap[ip]
}

// IsIPBlacklisted checks if an IP is blacklisted
func (tcp *TCPProtection) IsIPBlacklisted(ip string) bool {
	tcp.mu.RLock()
	defer tcp.mu.RUnlock()
	return tcp.blacklistMap[ip]
}

// AddToWhitelist adds an IP to the whitelist
func (tcp *TCPProtection) AddToWhitelist(ip string) {
	tcp.mu.Lock()
	defer tcp.mu.Unlock()
	tcp.whitelistMap[ip] = true
	tcp.config.WhitelistedIPs = append(tcp.config.WhitelistedIPs, ip)
}

// AddToBlacklist adds an IP to the blacklist
func (tcp *TCPProtection) AddToBlacklist(ip string) {
	tcp.mu.Lock()
	defer tcp.mu.Unlock()
	tcp.blacklistMap[ip] = true
	tcp.config.BlacklistedIPs = append(tcp.config.BlacklistedIPs, ip)
}

// RemoveFromWhitelist removes an IP from the whitelist
func (tcp *TCPProtection) RemoveFromWhitelist(ip string) {
	tcp.mu.Lock()
	defer tcp.mu.Unlock()
	delete(tcp.whitelistMap, ip)

	// Remove from config slice
	for i, whiteIP := range tcp.config.WhitelistedIPs {
		if whiteIP == ip {
			tcp.config.WhitelistedIPs = append(tcp.config.WhitelistedIPs[:i], tcp.config.WhitelistedIPs[i+1:]...)
			break
		}
	}
}

// RemoveFromBlacklist removes an IP from the blacklist
func (tcp *TCPProtection) RemoveFromBlacklist(ip string) {
	tcp.mu.Lock()
	defer tcp.mu.Unlock()
	delete(tcp.blacklistMap, ip)

	// Remove from config slice
	for i, blackIP := range tcp.config.BlacklistedIPs {
		if blackIP == ip {
			tcp.config.BlacklistedIPs = append(tcp.config.BlacklistedIPs[:i], tcp.config.BlacklistedIPs[i+1:]...)
			break
		}
	}
}
