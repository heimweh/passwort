package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/heimweh/passwort/pkg/crypto"
	"github.com/heimweh/passwort/pkg/vaultutil"
)

type filesystemStoreData struct {
	Data   map[string]string `json:"data"`
	Sealed bool              `json:"sealed"`
}

type FilesystemStore struct {
	filePath string
	data     map[string]string
	sealed   bool
	key      []byte // in-memory only
	mu       sync.RWMutex
}

func NewFilesystemStore(filePath string) *FilesystemStore {
	fs := &FilesystemStore{
		filePath: filePath,
		data:     make(map[string]string),
		sealed:   true,
	}
	fs.load()
	return fs
}

func (f *FilesystemStore) load() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	file, err := os.Open(f.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()
	var d filesystemStoreData
	if err := json.NewDecoder(file).Decode(&d); err != nil {
		return err
	}
	f.data = d.Data
	f.sealed = d.Sealed
	return nil
}

func (f *FilesystemStore) save() error {
	// save() must not take a lock; caller must hold the lock.
	d := filesystemStoreData{
		Data:   f.data,
		Sealed: f.sealed,
	}
	file, err := os.Create(f.filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(d)
}

// The rest of the methods mirror MemoryStore, but call save() after mutating state.

func (f *FilesystemStore) Get(key string) (string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.sealed || f.key == nil {
		return "", errors.New("vault is sealed")
	}
	enc, ok := f.data[key]
	if !ok {
		return "", errors.New("key not found")
	}
	return crypto.Decrypt(f.key, enc)
}

func (f *FilesystemStore) Set(key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sealed || f.key == nil {
		return errors.New("vault is sealed")
	}
	enc, err := crypto.Encrypt(f.key, []byte(value))
	if err != nil {
		return err
	}
	f.data[key] = enc
	return f.save()
}

func (f *FilesystemStore) Delete(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sealed || f.key == nil {
		return errors.New("vault is sealed")
	}
	if _, ok := f.data[key]; !ok {
		return errors.New("key not found")
	}
	delete(f.data, key)
	return f.save()
}

func (f *FilesystemStore) List() ([]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.sealed || f.key == nil {
		return nil, errors.New("vault is sealed")
	}
	keys := make([]string, 0, len(f.data))
	for k := range f.data {
		keys = append(keys, k)
	}
	return keys, nil
}

// Seal seals the vault and clears the key from memory. Does not return shares.
func (f *FilesystemStore) Seal() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.key == nil {
		return errors.New("no key to split")
	}
	f.sealed = true
	f.key = nil
	return f.save()
}

// SealAndGetShares seals the vault and returns the shares (for CLI/init only).
func (f *FilesystemStore) SealAndGetShares() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.key == nil {
		return nil, errors.New("no key to split")
	}
	shares, err := crypto.SplitKey(f.key, 3, 2)
	if err != nil {
		return nil, err
	}
	f.sealed = true
	f.key = nil
	// save() must be called after lock is released
	go f.save() // fire-and-forget, or handle error if needed
	return shares, nil
}

func (f *FilesystemStore) Unseal(keys ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(keys) < 2 {
		return errors.New("at least 2 shares required")
	}
	key, err := crypto.CombineShares(keys...)
	if err != nil {
		return fmt.Errorf("failed to combine shares: %w", err)
	}
	if err := vaultutil.StoreCheckKey(f.data, key); err != nil {
		return fmt.Errorf("invalid shares or wrong vault: %w", err)
	}
	f.key = key
	f.sealed = false
	return nil
}

func (f *FilesystemStore) Init() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.key != nil {
		return errors.New("vault already initialized")
	}
	key, err := vaultutil.StoreInit(f.data)
	if err != nil {
		return err
	}
	f.key = key
	f.sealed = true
	return f.save()
}

func (f *FilesystemStore) GetShares() ([]string, error) {
	return nil, errors.New("shares are not stored; you must save them when sealing")
}

func (f *FilesystemStore) Status() (string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.sealed {
		return "sealed", nil
	}
	return "unsealed", nil
}

func (f *FilesystemStore) SetKey(key []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.key = key
	f.sealed = false
	f.save()
}

func (f *FilesystemStore) InitKey(key []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.key != nil {
		return errors.New("vault already initialized")
	}
	f.key = key
	f.sealed = false
	return f.save()
}

func (f *FilesystemStore) IsEmpty() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.data) == 0
}

// Remove scryptKey helper, use scrypt directly where needed.
