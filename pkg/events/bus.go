package events

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/oarkflow/guard/pkg/plugins"
)

// EventBus manages event publishing and subscription
type EventBus struct {
	handlers map[string][]plugins.EventHandler
	registry *plugins.PluginRegistry
	buffer   chan plugins.SecurityEvent
	workers  int
	mu       sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// NewEventBus creates a new event bus
func NewEventBus(registry *plugins.PluginRegistry, bufferSize, workers int) *EventBus {
	ctx, cancel := context.WithCancel(context.Background())

	bus := &EventBus{
		handlers: make(map[string][]plugins.EventHandler),
		registry: registry,
		buffer:   make(chan plugins.SecurityEvent, bufferSize),
		workers:  workers,
		ctx:      ctx,
		cancel:   cancel,
	}

	// Start worker goroutines
	for i := 0; i < workers; i++ {
		bus.wg.Add(1)
		go bus.worker(i)
	}

	return bus
}

// worker processes events from the buffer
func (eb *EventBus) worker(id int) {
	defer eb.wg.Done()

	for {
		select {
		case event := <-eb.buffer:
			eb.processEvent(event)
		case <-eb.ctx.Done():
			// Process remaining events in buffer before shutting down
			eb.drainBuffer()
			return
		}
	}
}

// drainBuffer processes any remaining events in the buffer during shutdown
func (eb *EventBus) drainBuffer() {
	for {
		select {
		case event := <-eb.buffer:
			eb.processEvent(event)
		default:
			return // No more events to process
		}
	}
}

// processEvent handles a single event
func (eb *EventBus) processEvent(event plugins.SecurityEvent) {
	handlers := eb.registry.GetHandlers(event.Type)

	for _, handler := range handlers {
		func(h plugins.EventHandler) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Event handler %s panicked: %v", h.Name(), r)
				}
			}()

			ctx, cancel := context.WithTimeout(eb.ctx, 30*time.Second)
			defer cancel()

			if err := h.Handle(ctx, event); err != nil {
				log.Printf("Event handler %s failed: %v", h.Name(), err)
			}
		}(handler)
	}
}

// Publish publishes an event to the bus
func (eb *EventBus) Publish(event plugins.SecurityEvent) error {
	// Add timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Generate ID if not set
	if event.ID == "" {
		event.ID = generateEventID()
	}

	select {
	case eb.buffer <- event:
		return nil
	case <-eb.ctx.Done():
		return fmt.Errorf("event bus is shutting down")
	default:
		return fmt.Errorf("event buffer is full")
	}
}

// PublishAsync publishes an event asynchronously (non-blocking)
func (eb *EventBus) PublishAsync(event plugins.SecurityEvent) {
	go func() {
		if err := eb.Publish(event); err != nil {
			log.Printf("Failed to publish event: %v", err)
		}
	}()
}

// Subscribe registers a handler for specific event types
func (eb *EventBus) Subscribe(eventType string, handler plugins.EventHandler) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if eb.handlers[eventType] == nil {
		eb.handlers[eventType] = make([]plugins.EventHandler, 0)
	}

	eb.handlers[eventType] = append(eb.handlers[eventType], handler)
}

// Unsubscribe removes a handler from an event type
func (eb *EventBus) Unsubscribe(eventType string, handler plugins.EventHandler) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	handlers := eb.handlers[eventType]
	for i, h := range handlers {
		if h.Name() == handler.Name() {
			eb.handlers[eventType] = append(handlers[:i], handlers[i+1:]...)
			break
		}
	}
}

// GetStats returns statistics about the event bus
func (eb *EventBus) GetStats() map[string]any {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	handlerCount := 0
	for _, handlers := range eb.handlers {
		handlerCount += len(handlers)
	}

	return map[string]any{
		"buffer_size":   cap(eb.buffer),
		"buffer_used":   len(eb.buffer),
		"workers":       eb.workers,
		"handler_count": handlerCount,
		"event_types":   len(eb.handlers),
	}
}

// Shutdown gracefully shuts down the event bus
func (eb *EventBus) Shutdown() error {
	log.Println("Shutting down event bus...")

	// Stop accepting new events
	eb.cancel()

	// Wait for workers to finish processing remaining events
	done := make(chan struct{})
	go func() {
		eb.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("Event bus shutdown complete. Buffer had %d remaining events", len(eb.buffer))
		return nil
	case <-time.After(30 * time.Second):
		return fmt.Errorf("shutdown timeout - %d events may be lost", len(eb.buffer))
	}
}

// generateEventID generates a unique event ID
func generateEventID() string {
	return fmt.Sprintf("evt_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond())
}

// EventPublisher is a helper interface for publishing events
type EventPublisher interface {
	Publish(event plugins.SecurityEvent) error
	PublishAsync(event plugins.SecurityEvent)
}

// EventFactory helps create standardized security events
type EventFactory struct {
	source string
}

// NewEventFactory creates a new event factory
func NewEventFactory(source string) *EventFactory {
	return &EventFactory{source: source}
}

// CreateThreatDetectedEvent creates a threat detection event
func (ef *EventFactory) CreateThreatDetectedEvent(ip, userID, threatType string, severity int, details map[string]any) plugins.SecurityEvent {
	return plugins.SecurityEvent{
		ID:        generateEventID(),
		Type:      "threat_detected",
		Timestamp: time.Now(),
		IP:        ip,
		UserID:    userID,
		Severity:  severity,
		Details: map[string]any{
			"threat_type": threatType,
			"details":     details,
		},
		Source: ef.source,
		Tags:   []string{"security", "threat", threatType},
	}
}

// CreateRuleTriggeredEvent creates a rule triggered event
func (ef *EventFactory) CreateRuleTriggeredEvent(ip, userID, ruleName string, severity int, details map[string]any) plugins.SecurityEvent {
	return plugins.SecurityEvent{
		ID:        generateEventID(),
		Type:      "rule_triggered",
		Timestamp: time.Now(),
		IP:        ip,
		UserID:    userID,
		Severity:  severity,
		Details: map[string]any{
			"rule_name": ruleName,
			"details":   details,
		},
		Source: ef.source,
		Tags:   []string{"security", "rule", ruleName},
	}
}

// CreateActionExecutedEvent creates an action executed event
func (ef *EventFactory) CreateActionExecutedEvent(ip, userID, actionName string, severity int, details map[string]any) plugins.SecurityEvent {
	return plugins.SecurityEvent{
		ID:        generateEventID(),
		Type:      "action_executed",
		Timestamp: time.Now(),
		IP:        ip,
		UserID:    userID,
		Severity:  severity,
		Details: map[string]any{
			"action_name": actionName,
			"details":     details,
		},
		Source: ef.source,
		Tags:   []string{"security", "action", actionName},
	}
}

// CreateSystemEvent creates a system event
func (ef *EventFactory) CreateSystemEvent(eventType string, severity int, details map[string]any) plugins.SecurityEvent {
	return plugins.SecurityEvent{
		ID:        generateEventID(),
		Type:      eventType,
		Timestamp: time.Now(),
		Severity:  severity,
		Details:   details,
		Source:    ef.source,
		Tags:      []string{"system", eventType},
	}
}
