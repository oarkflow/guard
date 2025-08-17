package store

import (
	"fmt"
)

// DefaultStoreFactory implements StoreFactory
type DefaultStoreFactory struct{}

// NewStoreFactory creates a new store factory
func NewStoreFactory() *DefaultStoreFactory {
	return &DefaultStoreFactory{}
}

// CreateStore creates a state store based on configuration
func (f *DefaultStoreFactory) CreateStore(config StoreConfig) (StateStore, error) {
	switch config.Type {
	case "memory":
		return NewMemoryStore(config), nil
	case "redis":
		// Redis implementation would go here
		return nil, fmt.Errorf("redis store not implemented yet")
	case "etcd":
		// etcd implementation would go here
		return nil, fmt.Errorf("etcd store not implemented yet")
	default:
		return nil, fmt.Errorf("unsupported store type: %s", config.Type)
	}
}

// SupportedTypes returns the list of supported store types
func (f *DefaultStoreFactory) SupportedTypes() []string {
	return []string{"memory", "redis", "etcd"}
}
