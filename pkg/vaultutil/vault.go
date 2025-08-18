package vaultutil

import (
	"errors"

	"github.com/heimweh/passwort/pkg/crypto"
)

const (
	VaultCheckKey   = ".vault_check"
	VaultCheckValue = "vault-check"
)

// StoreInit initializes the vault: generates a key, stores the check value, and returns the key.
func StoreInit(store map[string]string) ([]byte, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	enc, err := crypto.Encrypt(key, []byte(VaultCheckValue))
	if err != nil {
		return nil, err
	}
	store[VaultCheckKey] = enc
	return key, nil
}

// StoreCheckKey checks that the key can decrypt the known value in the store.
func StoreCheckKey(store map[string]string, key []byte) error {
	enc, ok := store[VaultCheckKey]
	if !ok {
		return errors.New("vault check missing")
	}
	plain, err := crypto.Decrypt(key, enc)
	if err != nil || plain != VaultCheckValue {
		return errors.New("invalid shares or wrong vault")
	}
	return nil
}
