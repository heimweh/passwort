package passwort

import "sync"

// InmemoryStore implements the Store interface using an in-memory map.
// This store is suitable for testing or scenarios where persistence is not required.
type InmemoryStore struct {
	// Holds the mutex to protect concurrent access to the store.
	mu sync.Mutex

	// store is a map that holds passwords in memory.
	store map[string]string
}

func NewInmemoryStore() Store {
	return &InmemoryStore{
		store: make(map[string]string),
	}
}

// Set stores a value for the given key in the in-memory store.
func (s *InmemoryStore) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[key] = value
	return nil
}

// Get retrieves the value for the given key from the in-memory store.
// Returns the value and true if found, or an empty string and false otherwise.
func (s *InmemoryStore) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	val, ok := s.store[key]
	if !ok {
		return "", ErrMissingSecret // or return an error if preferred
	}

	return val, nil
}

// Delete removes the value for the given key from the in-memory store.
func (s *InmemoryStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, key)
	return nil
}

// List returns a slice of all keys in the in-memory store, implementing the Store interface.
func (s *InmemoryStore) List() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.store))
	for k := range s.store {
		keys = append(keys, k)
	}
	return keys, nil
}
