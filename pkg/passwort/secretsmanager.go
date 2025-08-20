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

// SecretsManager defines an interface for encryption and decryption with secret sharing.
type SecretsManager interface {
	// Encrypt encrypts the plaintext using the given password and returns the ciphertext and shares.
	Encrypt(plaintext []byte, password string) (ciphertext []byte, shares [][]byte, err error)
	// Decrypt decrypts the ciphertext using the shares and password, returning the original plaintext.
	Decrypt(ciphertext []byte, shares [][]byte, password string) ([]byte, error)
}

// ShamirScryptSecretsManager implements SecretsManager using scrypt for key derivation and Shamir for key splitting.
type ShamirScryptSecretsManager struct {
	// ScryptN is the cost factor for scrypt.
	ScryptN int
	// ScryptR is the block size for scrypt.
	ScryptR int
	// ScryptP is the parallelization factor for scrypt.
	ScryptP int
	// KeyLen is the length of the derived key.
	KeyLen int
	// Shares is the total number of shares to generate.
	Shares int
	// Threshold is the minimum number of shares required to reconstruct the secret.
	Threshold int

	// KeyHMAC is the HMAC of the derived key for password verification.
	KeyHMAC []byte
}

// Encrypt encrypts the plaintext using the given password and returns the ciphertext and shares.
func (c *ShamirScryptSecretsManager) Encrypt(plaintext []byte, password string) ([]byte, [][]byte, error) {
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
func (c *ShamirScryptSecretsManager) Decrypt(ciphertext []byte, shares [][]byte, password string) ([]byte, error) {
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

// NewShamirScryptSecretsManager creates a new ShamirScryptSecretsManager with the specified parameters.
func NewShamirScryptSecretsManager(scryptN, scryptR, scryptP, keyLen, shares, threshold int) SecretsManager {
	return &ShamirScryptSecretsManager{
		ScryptN:   scryptN,
		ScryptR:   scryptR,
		ScryptP:   scryptP,
		KeyLen:    keyLen,
		Shares:    shares,
		Threshold: threshold,
	}
}
