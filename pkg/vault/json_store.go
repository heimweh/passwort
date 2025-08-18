package vault

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/hashicorp/vault/shamir"
	"golang.org/x/crypto/scrypt"
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
	return decrypt(j.key, enc)
}

func (j *JSONStore) Set(key, value string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.sealed || j.key == nil {
		return errors.New("vault is sealed")
	}
	enc, err := encrypt(j.key, []byte(value))
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
	shares, err := shamir.Split(j.key, 3, 2)
	if err != nil {
		j.mu.Unlock()
		return nil, err
	}
	j.sealed = true
	j.key = nil
	j.mu.Unlock()
	j.save()
	var out []string
	for _, s := range shares {
		out = append(out, base64.StdEncoding.EncodeToString(s))
	}
	return out, nil
}

func (j *JSONStore) Unseal(keys ...string) error {
	j.mu.Lock()
	if len(keys) < 2 {
		j.mu.Unlock()
		return errors.New("at least 2 shares required")
	}
	var shares [][]byte
	for _, s := range keys {
		share, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			j.mu.Unlock()
			return err
		}
		shares = append(shares, share)
	}
	key, err := shamir.Combine(shares)
	if err != nil {
		j.mu.Unlock()
		return err
	}
	// Check the known value
	enc, ok := j.data[".vault_check"]
	if !ok {
		j.mu.Unlock()
		return errors.New("vault check missing")
	}
	plain, err := decrypt(key, enc)
	if err != nil || plain != "vault-check" {
		j.mu.Unlock()
		return errors.New("invalid shares or wrong vault")
	}
	j.key = key
	j.sealed = false
	j.mu.Unlock()
	return nil
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

func (j *JSONStore) Init() error {
	j.mu.Lock()
	if j.key != nil {
		j.mu.Unlock()
		return errors.New("vault already initialized")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		j.mu.Unlock()
		return err
	}
	j.key = key
	// Store a known encrypted check value
	enc, err := encrypt(key, []byte("vault-check"))
	if err != nil {
		j.mu.Unlock()
		return err
	}
	j.data[".vault_check"] = enc
	j.sealed = true
	j.mu.Unlock()
	return j.save()
}

func (j *JSONStore) IsEmpty() bool {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return len(j.data) == 0
}

// Use encrypt and decrypt from memory_store.go

func scryptKey(password, salt []byte, keyLen, n, r, p int) ([]byte, error) {
	return scrypt.Key(password, salt, n, r, p, keyLen)
}
