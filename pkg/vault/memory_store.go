package vault

import (
	"errors"
	"sync"

	"github.com/heimweh/passwort/pkg/crypto"
	"golang.org/x/crypto/scrypt"
)

type MemoryStore struct {
	data   map[string]string
	sealed bool
	key    []byte
	mu     sync.RWMutex
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		data:   make(map[string]string),
		sealed: true,
	}
}

func deriveKey(passphrase string) ([]byte, error) {
	return scrypt.Key([]byte(passphrase), []byte("vault_salt"), 1<<15, 8, 1, 32)
}

func (m *MemoryStore) Get(key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.sealed || m.key == nil {
		return "", errors.New("vault is sealed")
	}
	enc, ok := m.data[key]
	if !ok {
		return "", errors.New("key not found")
	}
	return crypto.Decrypt(m.key, enc)
}

func (m *MemoryStore) Set(key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sealed || m.key == nil {
		return errors.New("vault is sealed")
	}
	enc, err := crypto.Encrypt(m.key, []byte(value))
	if err != nil {
		return err
	}
	m.data[key] = enc
	return nil
}

func (m *MemoryStore) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sealed || m.key == nil {
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
	if m.sealed || m.key == nil {
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
	if m.key == nil {
		return errors.New("no key to split")
	}
	_, err := crypto.SplitKey(m.key, 3, 2)
	if err != nil {
		return err
	}
	m.sealed = true
	m.key = nil
	return nil
}

func (m *MemoryStore) Unseal(keys ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(keys) < 2 {
		return errors.New("at least 2 shares required")
	}
	key, err := crypto.CombineShares(keys...)
	if err != nil {
		return err
	}
	m.key = key
	m.sealed = false
	return nil
}

func (m *MemoryStore) GetShares() ([]string, error) {
	return nil, errors.New("shares are not stored; you must save them when sealing")
}

func (m *MemoryStore) Status() (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.sealed {
		return "sealed", nil
	}
	return "unsealed", nil
}

func (m *MemoryStore) SetKey(key []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.key = key
	m.sealed = false
}

func (m *MemoryStore) InitKey(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.key != nil {
		return errors.New("vault already initialized")
	}
	m.key = key
	m.sealed = false
	return nil
}

func (m *MemoryStore) Init() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.key != nil {
		return errors.New("vault already initialized")
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	m.key = key
	m.sealed = true
	return nil
}

func (m *MemoryStore) IsEmpty() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.data) == 0
}
