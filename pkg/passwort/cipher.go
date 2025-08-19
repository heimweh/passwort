package passwort

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/hashicorp/vault/shamir"
	"golang.org/x/crypto/scrypt"
)

// Cipher defines an interface for encryption and decryption.
type Cipher interface {
	// Encrypt encrypts the plaintext using the given password and returns the ciphertext and shares.
	Encrypt(plaintext []byte, password string) (ciphertext []byte, shares [][]byte, err error)
	// Decrypt decrypts the ciphertext using the shares and password, returning the original plaintext.
	Decrypt(ciphertext []byte, shares [][]byte, password string) ([]byte, error)
}

// ShamirScryptCipher implements Cipher using scrypt for key derivation and Shamir for key splitting.
type ShamirScryptCipher struct {
	ScryptN   int
	ScryptR   int
	ScryptP   int
	KeyLen    int
	Shares    int
	Threshold int
	KeyHMAC   []byte // HMAC of the derived key for password verification
}

// Encrypt encrypts the plaintext using the given password and returns the ciphertext and shares.
func (c *ShamirScryptCipher) Encrypt(plaintext []byte, password string) ([]byte, [][]byte, error) {
	key, err := scrypt.Key([]byte(password), make([]byte, 16), c.ScryptN, c.ScryptR, c.ScryptP, c.KeyLen)
	if err != nil {
		return nil, nil, err
	}
	// Store HMAC of the key for password verification
	h := hmac.New(sha256.New, []byte("passwort-hmac"))
	h.Write(key)
	c.KeyHMAC = h.Sum(nil)

	// Instead of splitting the key, split a random secret and use scrypt(password) XOR secret as the key
	secret := make([]byte, c.KeyLen)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return nil, nil, err
	}
	keyXOR := make([]byte, c.KeyLen)
	for i := range keyXOR {
		keyXOR[i] = key[i] ^ secret[i]
	}
	shares, err := shamir.Split(secret, c.Shares, c.Threshold)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(keyXOR)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, shares, nil
}

// Decrypt decrypts the ciphertext using the shares and password, returning the original plaintext.
func (c *ShamirScryptCipher) Decrypt(ciphertext []byte, shares [][]byte, password string) ([]byte, error) {
	secret, err := shamir.Combine(shares)
	if err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(password), make([]byte, 16), c.ScryptN, c.ScryptR, c.ScryptP, c.KeyLen)
	if err != nil {
		return nil, err
	}
	keyXOR := make([]byte, c.KeyLen)
	for i := range keyXOR {
		keyXOR[i] = key[i] ^ secret[i]
	}
	// Check HMAC of the key for password verification
	h := hmac.New(sha256.New, []byte("passwort-hmac"))
	h.Write(key)
	keyHMAC := h.Sum(nil)
	if !hmac.Equal(keyHMAC, c.KeyHMAC) {
		return nil, errors.New("invalid password or shares")
	}
	block, err := aes.NewCipher(keyXOR)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	enc := ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, enc, nil)
}
