package tcp

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/oarkflow/guard/pkg/store"
)

// TCPMiddleware provides TCP-level protection for HTTP servers
type TCPMiddleware struct {
	protection *TCPProtection
	next       http.Handler
}

// NewTCPMiddleware creates a new TCP middleware
func NewTCPMiddleware(config TCPProtectionConfig, stateStore store.StateStore, next http.Handler) *TCPMiddleware {
	protection := NewTCPProtection(config, stateStore)

	return &TCPMiddleware{
		protection: protection,
		next:       next,
	}
}

// ServeHTTP implements http.Handler with TCP-level protection
func (tm *TCPMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !tm.protection.config.EnableTCPProtection {
		tm.next.ServeHTTP(w, r)
		return
	}

	// Create a fake net.Addr from the request
	remoteAddr := &tcpAddr{
		network: "tcp",
		address: r.RemoteAddr,
	}

	// Check connection with TCP protection
	action, connInfo, err := tm.protection.CheckConnection(r.Context(), remoteAddr)
	if err != nil {
		log.Printf("TCP protection check failed for %s: %v", r.RemoteAddr, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Handle different actions
	switch action {
	case ActionAllow:
		// Connection is allowed, proceed with request
		tm.next.ServeHTTP(w, r)

	case ActionDrop:
		// Silent drop - close connection without response
		log.Printf("Silently dropping HTTP request from %s (connections: %d)",
			connInfo.IP, connInfo.ConnectionCount)
		// For HTTP, we can't truly "drop" silently, so we close the connection
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				conn.Close()
				return
			}
		}
		// Fallback to empty response
		w.WriteHeader(http.StatusNoContent)

	case ActionTarpit:
		// Tarpit - delay the response
		log.Printf("Tarpitting HTTP request from %s (connections: %d)",
			connInfo.IP, connInfo.ConnectionCount)
		time.Sleep(tm.protection.config.TarpitDelay)
		tm.next.ServeHTTP(w, r)

	case ActionBlock:
		// Block - return error response
		log.Printf("Blocking HTTP request from %s (connections: %d, failed: %d)",
			connInfo.IP, connInfo.ConnectionCount, connInfo.FailedAttempts)

		// Return detailed block information
		blockInfo := map[string]interface{}{
			"error":            "Request blocked by TCP-level DDoS protection",
			"reason":           "Too many connections",
			"ip":               connInfo.IP,
			"connection_count": connInfo.ConnectionCount,
			"failed_attempts":  connInfo.FailedAttempts,
			"blocked_at":       connInfo.ConnectedAt.Format(time.RFC3339),
			"retry_after":      int(tm.protection.config.ConnectionWindow.Seconds()),
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(tm.protection.config.ConnectionWindow.Seconds())))
		w.WriteHeader(http.StatusTooManyRequests)

		// Write JSON response
		fmt.Fprintf(w, `{
			"error": "%s",
			"reason": "%s",
			"ip": "%s",
			"connection_count": %d,
			"failed_attempts": %d,
			"blocked_at": "%s",
			"retry_after": %d
		}`,
			blockInfo["error"],
			blockInfo["reason"],
			blockInfo["ip"],
			blockInfo["connection_count"],
			blockInfo["failed_attempts"],
			blockInfo["blocked_at"],
			blockInfo["retry_after"])

	default:
		// Unknown action, default to block
		log.Printf("Unknown TCP action %s for %s, blocking", action.String(), r.RemoteAddr)
		http.Error(w, "Request blocked", http.StatusTooManyRequests)
	}

	// Clean up connection tracking when request is done
	defer tm.protection.CloseConnection(remoteAddr)
}

// RecordFailedConnection records a failed connection attempt
func (tm *TCPMiddleware) RecordFailedConnection(r *http.Request) error {
	remoteAddr := &tcpAddr{
		network: "tcp",
		address: r.RemoteAddr,
	}
	return tm.protection.RecordFailedConnection(r.Context(), remoteAddr)
}

// GetMetrics returns TCP protection metrics
func (tm *TCPMiddleware) GetMetrics() TCPMetrics {
	return tm.protection.GetMetrics()
}

// GetActiveConnections returns active connection information
func (tm *TCPMiddleware) GetActiveConnections() map[string]*TCPConnectionInfo {
	return tm.protection.GetActiveConnections()
}

// GetProtection returns the underlying TCP protection instance
func (tm *TCPMiddleware) GetProtection() *TCPProtection {
	return tm.protection
}

// tcpAddr implements net.Addr for HTTP requests
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

// TCPProtectionHandler provides HTTP endpoints for TCP protection management
type TCPProtectionHandler struct {
	protection *TCPProtection
}

// NewTCPProtectionHandler creates a new TCP protection handler
func NewTCPProtectionHandler(protection *TCPProtection) *TCPProtectionHandler {
	return &TCPProtectionHandler{
		protection: protection,
	}
}

// HandleMetrics returns TCP protection metrics
func (h *TCPProtectionHandler) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := h.protection.GetMetrics()

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"total_connections": %d,
		"allowed_connections": %d,
		"dropped_connections": %d,
		"tarpit_connections": %d,
		"blocked_connections": %d,
		"active_tarpits": %d,
		"brute_force_detections": %d
	}`,
		metrics.TotalConnections,
		metrics.AllowedConnections,
		metrics.DroppedConnections,
		metrics.TarpitConnections,
		metrics.BlockedConnections,
		metrics.ActiveTarpits,
		metrics.BruteForceDetections)
}

// HandleActiveConnections returns active connection information
func (h *TCPProtectionHandler) HandleActiveConnections(w http.ResponseWriter, r *http.Request) {
	connections := h.protection.GetActiveConnections()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	fmt.Fprint(w, "{\"active_connections\": [")
	first := true
	for addr, connInfo := range connections {
		if !first {
			fmt.Fprint(w, ",")
		}
		first = false

		fmt.Fprintf(w, `{
			"address": "%s",
			"ip": "%s",
			"port": %d,
			"connected_at": "%s",
			"last_activity": "%s",
			"connection_count": %d,
			"failed_attempts": %d,
			"action": "%s",
			"is_whitelisted": %t,
			"is_blacklisted": %t
		}`,
			addr,
			connInfo.IP,
			connInfo.Port,
			connInfo.ConnectedAt.Format(time.RFC3339),
			connInfo.LastActivity.Format(time.RFC3339),
			connInfo.ConnectionCount,
			connInfo.FailedAttempts,
			connInfo.Action.String(),
			connInfo.IsWhitelisted,
			connInfo.IsBlacklisted)
	}
	fmt.Fprint(w, "]}")
}

// HandleWhitelist manages IP whitelist
func (h *TCPProtectionHandler) HandleWhitelist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		// Add IP to whitelist
		ip := r.FormValue("ip")
		if ip == "" {
			http.Error(w, "IP parameter required", http.StatusBadRequest)
			return
		}

		h.protection.AddToWhitelist(ip)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"message": "IP %s added to whitelist"}`, ip)

	case http.MethodDelete:
		// Remove IP from whitelist
		ip := r.FormValue("ip")
		if ip == "" {
			http.Error(w, "IP parameter required", http.StatusBadRequest)
			return
		}

		h.protection.RemoveFromWhitelist(ip)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"message": "IP %s removed from whitelist"}`, ip)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleBlacklist manages IP blacklist
func (h *TCPProtectionHandler) HandleBlacklist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		// Add IP to blacklist
		ip := r.FormValue("ip")
		if ip == "" {
			http.Error(w, "IP parameter required", http.StatusBadRequest)
			return
		}

		h.protection.AddToBlacklist(ip)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"message": "IP %s added to blacklist"}`, ip)

	case http.MethodDelete:
		// Remove IP from blacklist
		ip := r.FormValue("ip")
		if ip == "" {
			http.Error(w, "IP parameter required", http.StatusBadRequest)
			return
		}

		h.protection.RemoveFromBlacklist(ip)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"message": "IP %s removed from blacklist"}`, ip)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
