package store

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// MemoryEntry represents an entry in the memory store
type MemoryEntry struct {
	Value      any
	ExpiryTime time.Time
	HasExpiry  bool
}

// MemoryStore implements StateStore using in-memory storage
type MemoryStore struct {
	data   map[string]MemoryEntry
	mu     sync.RWMutex
	prefix string
	stats  struct {
		gets      int64
		sets      int64
		deletes   int64
		hits      int64
		misses    int64
		evictions int64
	}
	stopCleanup chan struct{}
}

// NewMemoryStore creates a new memory-based state store
func NewMemoryStore(config StoreConfig) *MemoryStore {
	store := &MemoryStore{
		data:        make(map[string]MemoryEntry),
		prefix:      config.Prefix,
		stopCleanup: make(chan struct{}),
	}

	// Start cleanup goroutine
	go store.cleanupExpired()

	return store
}

// Get retrieves a value from the store
func (m *MemoryStore) Get(ctx context.Context, key string) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.stats.gets++
	fullKey := m.getFullKey(key)

	entry, exists := m.data[fullKey]
	if !exists {
		m.stats.misses++
		return nil, fmt.Errorf("key not found: %s", key)
	}

	// Check expiry
	if entry.HasExpiry && time.Now().After(entry.ExpiryTime) {
		m.stats.misses++
		// Remove expired entry (upgrade to write lock)
		m.mu.RUnlock()
		m.mu.Lock()
		delete(m.data, fullKey)
		m.stats.evictions++
		m.mu.Unlock()
		m.mu.RLock()
		return nil, fmt.Errorf("key expired: %s", key)
	}

	m.stats.hits++
	return entry.Value, nil
}

// Set stores a value in the store
func (m *MemoryStore) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.stats.sets++
	fullKey := m.getFullKey(key)

	entry := MemoryEntry{
		Value: value,
	}

	if ttl > 0 {
		entry.HasExpiry = true
		entry.ExpiryTime = time.Now().Add(ttl)
	}

	m.data[fullKey] = entry
	return nil
}

// Increment atomically increments a numeric value
func (m *MemoryStore) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Count as a get operation
	m.stats.gets++
	fullKey := m.getFullKey(key)
	entry, exists := m.data[fullKey]

	var currentValue int64
	var hasExpiry bool
	var expiryTime time.Time

	if exists {
		// Check expiry
		if entry.HasExpiry && time.Now().After(entry.ExpiryTime) {
			delete(m.data, fullKey)
			m.stats.evictions++
			m.stats.misses++
			currentValue = 0
			hasExpiry = false
		} else {
			m.stats.hits++
			switch v := entry.Value.(type) {
			case int64:
				currentValue = v
			case int:
				currentValue = int64(v)
			case float64:
				currentValue = int64(v)
			default:
				return 0, fmt.Errorf("value is not numeric: %T", entry.Value)
			}
			hasExpiry = entry.HasExpiry
			expiryTime = entry.ExpiryTime
		}
	} else {
		m.stats.misses++
		currentValue = 0
		hasExpiry = false
	}

	// Count as a set operation
	m.stats.sets++
	newValue := currentValue + delta
	newEntry := MemoryEntry{
		Value:      newValue,
		HasExpiry:  hasExpiry,
		ExpiryTime: expiryTime,
	}

	m.data[fullKey] = newEntry
	return newValue, nil
}

// IncrementWithTTL atomically increments a numeric value and sets TTL if it's a new entry
func (m *MemoryStore) IncrementWithTTL(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Count as a get operation
	m.stats.gets++
	fullKey := m.getFullKey(key)
	entry, exists := m.data[fullKey]

	var currentValue int64
	var hasExpiry bool
	var expiryTime time.Time

	if exists {
		// Check expiry
		if entry.HasExpiry && time.Now().After(entry.ExpiryTime) {
			delete(m.data, fullKey)
			m.stats.evictions++
			m.stats.misses++
			currentValue = 0
			// Set new TTL for expired entry
			if ttl > 0 {
				hasExpiry = true
				expiryTime = time.Now().Add(ttl)
			}
		} else {
			m.stats.hits++
			switch v := entry.Value.(type) {
			case int64:
				currentValue = v
			case int:
				currentValue = int64(v)
			case float64:
				currentValue = int64(v)
			default:
				return 0, fmt.Errorf("value is not numeric: %T", entry.Value)
			}
			// Preserve existing TTL
			hasExpiry = entry.HasExpiry
			expiryTime = entry.ExpiryTime
		}
	} else {
		m.stats.misses++
		currentValue = 0
		// Set TTL for new entry
		if ttl > 0 {
			hasExpiry = true
			expiryTime = time.Now().Add(ttl)
		}
	}

	// Count as a set operation
	m.stats.sets++
	newValue := currentValue + delta
	newEntry := MemoryEntry{
		Value:      newValue,
		HasExpiry:  hasExpiry,
		ExpiryTime: expiryTime,
	}

	m.data[fullKey] = newEntry
	return newValue, nil
}

// Delete removes a key from the store
func (m *MemoryStore) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.stats.deletes++
	fullKey := m.getFullKey(key)
	delete(m.data, fullKey)
	return nil
}

// Exists checks if a key exists in the store
func (m *MemoryStore) Exists(ctx context.Context, key string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.stats.gets++
	fullKey := m.getFullKey(key)
	entry, exists := m.data[fullKey]

	if !exists {
		m.stats.misses++
		return false, nil
	}

	// Check expiry
	if entry.HasExpiry && time.Now().After(entry.ExpiryTime) {
		m.stats.misses++
		// Remove expired entry (upgrade to write lock)
		m.mu.RUnlock()
		m.mu.Lock()
		delete(m.data, fullKey)
		m.stats.evictions++
		m.mu.Unlock()
		m.mu.RLock()
		return false, nil
	}

	m.stats.hits++
	return true, nil
}

// Keys returns all keys matching a pattern
func (m *MemoryStore) Keys(ctx context.Context, pattern string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var keys []string
	fullPattern := m.getFullKey(pattern)

	for key, entry := range m.data {
		// Check expiry
		if entry.HasExpiry && time.Now().After(entry.ExpiryTime) {
			continue
		}

		// Simple pattern matching (supports * wildcard)
		if matchPattern(key, fullPattern) {
			// Remove prefix from key
			cleanKey := strings.TrimPrefix(key, m.prefix)
			keys = append(keys, cleanKey)
		}
	}

	return keys, nil
}

// Close closes the store
func (m *MemoryStore) Close() error {
	close(m.stopCleanup)
	return nil
}

// Health checks the health of the store
func (m *MemoryStore) Health() error {
	return nil // Memory store is always healthy
}

// GetStats returns store statistics
func (m *MemoryStore) GetStats() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]any{
		"type":      "memory",
		"keys":      len(m.data),
		"gets":      m.stats.gets,
		"sets":      m.stats.sets,
		"deletes":   m.stats.deletes,
		"hits":      m.stats.hits,
		"misses":    m.stats.misses,
		"evictions": m.stats.evictions,
		"hit_ratio": float64(m.stats.hits) / float64(m.stats.gets+1),
	}
}

// getFullKey returns the full key with prefix
func (m *MemoryStore) getFullKey(key string) string {
	if m.prefix == "" {
		return key
	}
	return m.prefix + key
}

// cleanupExpired removes expired entries periodically
func (m *MemoryStore) cleanupExpired() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now()
			for key, entry := range m.data {
				if entry.HasExpiry && now.After(entry.ExpiryTime) {
					delete(m.data, key)
					m.stats.evictions++
				}
			}
			m.mu.Unlock()
		case <-m.stopCleanup:
			return
		}
	}
}

// matchPattern performs simple pattern matching with * wildcard
func matchPattern(text, pattern string) bool {
	if pattern == "*" {
		return true
	}

	if !strings.Contains(pattern, "*") {
		return text == pattern
	}

	parts := strings.Split(pattern, "*")
	if len(parts) == 2 {
		prefix, suffix := parts[0], parts[1]
		return strings.HasPrefix(text, prefix) && strings.HasSuffix(text, suffix)
	}

	// More complex pattern matching could be implemented here
	return strings.Contains(text, strings.ReplaceAll(pattern, "*", ""))
}
