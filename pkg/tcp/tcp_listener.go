package tcp

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/oarkflow/guard/pkg/store"
)

// ProtectedListener wraps a net.Listener with TCP-level DDoS protection
type ProtectedListener struct {
	listener    net.Listener
	protection  *TCPProtection
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	connHandler ConnectionHandler
}

// ConnectionHandler defines how to handle connections after TCP protection check
type ConnectionHandler interface {
	HandleConnection(conn net.Conn, connInfo *TCPConnectionInfo) error
}

// DefaultConnectionHandler provides a basic connection handler
type DefaultConnectionHandler struct{}

func (h *DefaultConnectionHandler) HandleConnection(conn net.Conn, connInfo *TCPConnectionInfo) error {
	// Default behavior - just close the connection after logging
	log.Printf("Handling connection from %s with action %s", connInfo.IP, connInfo.Action.String())
	return conn.Close()
}

// NewProtectedListener creates a new protected TCP listener
func NewProtectedListener(listener net.Listener, protection *TCPProtection, handler ConnectionHandler) *ProtectedListener {
	ctx, cancel := context.WithCancel(context.Background())

	if handler == nil {
		handler = &DefaultConnectionHandler{}
	}

	return &ProtectedListener{
		listener:    listener,
		protection:  protection,
		ctx:         ctx,
		cancel:      cancel,
		connHandler: handler,
	}
}

// Accept waits for and returns the next connection to the listener with TCP protection
func (pl *ProtectedListener) Accept() (net.Conn, error) {
	for {
		conn, err := pl.listener.Accept()
		if err != nil {
			return nil, err
		}

		// Check connection with TCP protection
		action, connInfo, err := pl.protection.CheckConnection(pl.ctx, conn.RemoteAddr())
		if err != nil {
			log.Printf("TCP protection check failed for %s: %v", conn.RemoteAddr(), err)
			conn.Close()
			continue
		}

		// Handle different actions
		switch action {
		case ActionAllow:
			// Connection is allowed, return it
			return &ProtectedConn{
				Conn:       conn,
				protection: pl.protection,
				connInfo:   connInfo,
			}, nil

		case ActionDrop:
			// Silent drop - close connection without response
			log.Printf("Silently dropping connection from %s (connections: %d)",
				connInfo.IP, connInfo.ConnectionCount)
			conn.Close()
			continue

		case ActionTarpit:
			// Tarpit - delay the connection
			log.Printf("Tarpitting connection from %s (connections: %d)",
				connInfo.IP, connInfo.ConnectionCount)
			pl.wg.Add(1)
			go pl.handleTarpitConnection(conn, connInfo)
			continue

		case ActionBlock:
			// Block - close connection and log
			log.Printf("Blocking connection from %s (connections: %d, failed: %d)",
				connInfo.IP, connInfo.ConnectionCount, connInfo.FailedAttempts)
			conn.Close()
			continue

		default:
			// Unknown action, default to drop
			log.Printf("Unknown action %s for %s, dropping", action.String(), conn.RemoteAddr())
			conn.Close()
			continue
		}
	}
}

// handleTarpitConnection handles a connection in tarpit mode
func (pl *ProtectedListener) handleTarpitConnection(conn net.Conn, connInfo *TCPConnectionInfo) {
	defer pl.wg.Done()
	defer conn.Close()

	// Create a tarpitted connection wrapper
	tarpitConn := &TarpitConn{
		Conn:       conn,
		protection: pl.protection,
		connInfo:   connInfo,
		delay:      pl.protection.config.TarpitDelay,
	}

	// Handle the connection through the handler
	if err := pl.connHandler.HandleConnection(tarpitConn, connInfo); err != nil {
		log.Printf("Error handling tarpit connection from %s: %v", connInfo.IP, err)
	}
}

// Close closes the listener
func (pl *ProtectedListener) Close() error {
	pl.cancel()
	pl.wg.Wait()
	return pl.listener.Close()
}

// Addr returns the listener's network address
func (pl *ProtectedListener) Addr() net.Addr {
	return pl.listener.Addr()
}

// ProtectedConn wraps a net.Conn with TCP protection tracking
type ProtectedConn struct {
	net.Conn
	protection *TCPProtection
	connInfo   *TCPConnectionInfo
	closed     bool
	mu         sync.Mutex
}

// Read implements net.Conn.Read with activity tracking
func (pc *ProtectedConn) Read(b []byte) (n int, err error) {
	n, err = pc.Conn.Read(b)
	if n > 0 {
		pc.protection.UpdateActivity(pc.RemoteAddr())
	}
	return n, err
}

// Write implements net.Conn.Write with activity tracking
func (pc *ProtectedConn) Write(b []byte) (n int, err error) {
	n, err = pc.Conn.Write(b)
	if n > 0 {
		pc.protection.UpdateActivity(pc.RemoteAddr())
	}
	return n, err
}

// Close implements net.Conn.Close with cleanup
func (pc *ProtectedConn) Close() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if pc.closed {
		return nil
	}

	pc.closed = true
	pc.protection.CloseConnection(pc.RemoteAddr())
	return pc.Conn.Close()
}

// GetConnectionInfo returns the TCP connection information
func (pc *ProtectedConn) GetConnectionInfo() *TCPConnectionInfo {
	return pc.connInfo
}

// TarpitConn wraps a connection with tarpit behavior
type TarpitConn struct {
	net.Conn
	protection *TCPProtection
	connInfo   *TCPConnectionInfo
	delay      time.Duration
	closed     bool
	mu         sync.Mutex
}

// Read implements net.Conn.Read with tarpit delay
func (tc *TarpitConn) Read(b []byte) (n int, err error) {
	// Add delay before reading
	time.Sleep(tc.delay)

	n, err = tc.Conn.Read(b)
	if n > 0 {
		tc.protection.UpdateActivity(tc.RemoteAddr())
	}
	return n, err
}

// Write implements net.Conn.Write with tarpit delay
func (tc *TarpitConn) Write(b []byte) (n int, err error) {
	// Add delay before writing
	time.Sleep(tc.delay)

	n, err = tc.Conn.Write(b)
	if n > 0 {
		tc.protection.UpdateActivity(tc.RemoteAddr())
	}
	return n, err
}

// Close implements net.Conn.Close with cleanup
func (tc *TarpitConn) Close() error {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if tc.closed {
		return nil
	}

	tc.closed = true
	tc.protection.CloseConnection(tc.RemoteAddr())
	return tc.Conn.Close()
}

// GetConnectionInfo returns the TCP connection information
func (tc *TarpitConn) GetConnectionInfo() *TCPConnectionInfo {
	return tc.connInfo
}

// HTTPConnectionHandler handles HTTP connections after TCP protection
type HTTPConnectionHandler struct {
	httpHandler func(net.Conn)
}

// NewHTTPConnectionHandler creates a new HTTP connection handler
func NewHTTPConnectionHandler(httpHandler func(net.Conn)) *HTTPConnectionHandler {
	return &HTTPConnectionHandler{
		httpHandler: httpHandler,
	}
}

// HandleConnection handles an HTTP connection
func (h *HTTPConnectionHandler) HandleConnection(conn net.Conn, connInfo *TCPConnectionInfo) error {
	// For allowed connections, pass to HTTP handler
	if connInfo.Action == ActionAllow {
		h.httpHandler(conn)
		return nil
	}

	// For tarpit connections, handle with delay
	if connInfo.Action == ActionTarpit {
		// The delay is already handled by TarpitConn
		h.httpHandler(conn)
		return nil
	}

	// For other actions, close the connection
	return conn.Close()
}

// TCPServer provides a TCP server with DDoS protection
type TCPServer struct {
	listener   *ProtectedListener
	protection *TCPProtection
	handler    ConnectionHandler
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewTCPServer creates a new TCP server with protection
func NewTCPServer(addr string, config TCPProtectionConfig, stateStore store.StateStore, handler ConnectionHandler) (*TCPServer, error) {
	// Create base listener
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	// Create TCP protection
	protection := NewTCPProtection(config, stateStore)

	// Create protected listener
	protectedListener := NewProtectedListener(listener, protection, handler)

	ctx, cancel := context.WithCancel(context.Background())

	return &TCPServer{
		listener:   protectedListener,
		protection: protection,
		handler:    handler,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// Serve starts serving connections
func (s *TCPServer) Serve() error {
	for {
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return s.ctx.Err()
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		// Handle connection in goroutine
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()

			// Get connection info if available
			var connInfo *TCPConnectionInfo
			if pc, ok := conn.(*ProtectedConn); ok {
				connInfo = pc.GetConnectionInfo()
			} else if tc, ok := conn.(*TarpitConn); ok {
				connInfo = tc.GetConnectionInfo()
			}

			// Handle the connection
			if err := s.handler.HandleConnection(conn, connInfo); err != nil {
				log.Printf("Connection handler error: %v", err)
			}
		}()
	}
}

// Shutdown gracefully shuts down the server
func (s *TCPServer) Shutdown() error {
	s.cancel()
	s.listener.Close()
	s.protection.Shutdown()
	s.wg.Wait()
	return nil
}

// GetMetrics returns TCP protection metrics
func (s *TCPServer) GetMetrics() TCPMetrics {
	return s.protection.GetMetrics()
}

// GetActiveConnections returns active connection information
func (s *TCPServer) GetActiveConnections() map[string]*TCPConnectionInfo {
	return s.protection.GetActiveConnections()
}
