package vault

import (
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/heimweh/passwort/pkg/crypto"
	"github.com/heimweh/passwort/pkg/vaultutil"
)

type jsonStoreData struct {
	Data   map[string]string `json:"data"`
	Sealed bool              `json:"sealed"`
}

type JSONStore struct {
	filePath string
	data     map[string]string
	sealed   bool
	key      []byte // in-memory only
	mu       sync.RWMutex
}

func NewJSONStore(filePath string) *JSONStore {
	js := &JSONStore{
		filePath: filePath,
		data:     make(map[string]string),
		sealed:   true,
	}
	js.load()
	return js
}

func (j *JSONStore) load() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	f, err := os.Open(j.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	var d jsonStoreData
	if err := json.NewDecoder(f).Decode(&d); err != nil {
		return err
	}
	j.data = d.Data
	j.sealed = d.Sealed
	return nil
}

func (j *JSONStore) save() error {
	j.mu.RLock()
	defer j.mu.RUnlock()
	d := jsonStoreData{
		Data:   j.data,
		Sealed: j.sealed,
	}
	f, err := os.Create(j.filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(d)
}

// The rest of the methods mirror MemoryStore, but call save() after mutating state.

func (j *JSONStore) Get(key string) (string, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	if j.sealed || j.key == nil {
		return "", errors.New("vault is sealed")
	}
	enc, ok := j.data[key]
	if !ok {
		return "", errors.New("key not found")
	}
	return crypto.Decrypt(j.key, enc)
}

func (j *JSONStore) Set(key, value string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.sealed || j.key == nil {
		return errors.New("vault is sealed")
	}
	enc, err := crypto.Encrypt(j.key, []byte(value))
	if err != nil {
		return err
	}
	j.data[key] = enc
	return j.save()
}

func (j *JSONStore) Delete(key string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.sealed || j.key == nil {
		return errors.New("vault is sealed")
	}
	if _, ok := j.data[key]; !ok {
		return errors.New("key not found")
	}
	delete(j.data, key)
	return j.save()
}

func (j *JSONStore) List() ([]string, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	if j.sealed || j.key == nil {
		return nil, errors.New("vault is sealed")
	}
	keys := make([]string, 0, len(j.data))
	for k := range j.data {
		keys = append(keys, k)
	}
	return keys, nil
}

// Seal seals the vault and clears the key from memory. Does not return shares.
func (j *JSONStore) Seal() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.key == nil {
		return errors.New("no key to split")
	}
	j.sealed = true
	j.key = nil
	return j.save()
}

// SealAndGetShares seals the vault and returns the shares (for CLI/init only).
func (j *JSONStore) SealAndGetShares() ([]string, error) {
	j.mu.Lock()
	if j.key == nil {
		j.mu.Unlock()
		return nil, errors.New("no key to split")
	}
	shares, err := crypto.SplitKey(j.key, 3, 2)
	if err != nil {
		j.mu.Unlock()
		return nil, err
	}
	j.sealed = true
	j.key = nil
	j.mu.Unlock()
	j.save()
	return shares, nil
}

func (j *JSONStore) Unseal(keys ...string) error {
	j.mu.Lock()
	if len(keys) < 2 {
		j.mu.Unlock()
		return errors.New("at least 2 shares required")
	}
	key, err := crypto.CombineShares(keys...)
	if err != nil {
		j.mu.Unlock()
		return err
	}
	if err := vaultutil.StoreCheckKey(j.data, key); err != nil {
		j.mu.Unlock()
		return err
	}
	j.key = key
	j.sealed = false
	j.mu.Unlock()
	return nil
}

func (j *JSONStore) Init() error {
	j.mu.Lock()
	if j.key != nil {
		j.mu.Unlock()
		return errors.New("vault already initialized")
	}
	key, err := vaultutil.StoreInit(j.data)
	if err != nil {
		j.mu.Unlock()
		return err
	}
	j.key = key
	j.sealed = true
	j.mu.Unlock()
	return j.save()
}

func (j *JSONStore) GetShares() ([]string, error) {
	return nil, errors.New("shares are not stored; you must save them when sealing")
}

func (j *JSONStore) Status() (string, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	if j.sealed {
		return "sealed", nil
	}
	return "unsealed", nil
}

func (j *JSONStore) SetKey(key []byte) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.key = key
	j.sealed = false
	j.save()
}

func (j *JSONStore) InitKey(key []byte) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.key != nil {
		return errors.New("vault already initialized")
	}
	j.key = key
	j.sealed = false
	return j.save()
}

func (j *JSONStore) IsEmpty() bool {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return len(j.data) == 0
}

// Remove scryptKey helper, use scrypt directly where needed.
