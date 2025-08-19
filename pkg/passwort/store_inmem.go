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
