package vault

import (
	"errors"
	"sync"
)

type MemoryStore struct {
	data   map[string]string
	sealed bool
	mu     sync.RWMutex
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		data:   make(map[string]string),
		sealed: false,
	}
}

func (m *MemoryStore) Get(key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.sealed {
		return "", errors.New("vault is sealed")
	}
	val, ok := m.data[key]
	if !ok {
		return "", errors.New("key not found")
	}
	return val, nil
}

func (m *MemoryStore) Set(key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sealed {
		return errors.New("vault is sealed")
	}
	m.data[key] = value
	return nil
}

func (m *MemoryStore) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sealed {
		return errors.New("vault is sealed")
	}
	if _, ok := m.data[key]; !ok {
		return errors.New("key not found")
	}
	delete(m.data, key)
	return nil
}

func (m *MemoryStore) List() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.sealed {
		return nil, errors.New("vault is sealed")
	}
	keys := make([]string, 0, len(m.data))
	for k := range m.data {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *MemoryStore) Seal() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sealed = true
	return nil
}

func (m *MemoryStore) Unseal(keys ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sealed = false
	return nil
}

func (m *MemoryStore) Status() (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.sealed {
		return "sealed", nil
	}
	return "unsealed", nil
}
