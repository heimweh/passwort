package passwort

import (
	"bytes"
	"testing"
)

func TestShamirScryptCipher_EncryptDecrypt(t *testing.T) {
	cipher := &ShamirScryptCipher{
		ScryptN:   1 << 15,
		ScryptR:   8,
		ScryptP:   1,
		KeyLen:    32,
		Shares:    5,
		Threshold: 3,
	}

	tests := []struct {
		name      string
		plaintext []byte
		password  string
	}{
		{"basic roundtrip", []byte("hello world"), "password123"},
		{"empty plaintext", []byte{}, "password123"},
		{"unicode", []byte("Grüße, мир!"), "pässwörd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, shares, err := cipher.Encrypt(tt.plaintext, tt.password)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			// Use only threshold shares for decryption
			dec, err := cipher.Decrypt(ciphertext, shares[:cipher.Threshold], tt.password)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
			if !bytes.Equal(dec, tt.plaintext) {
				t.Errorf("Decrypt = %q, want %q", dec, tt.plaintext)
			}
		})
	}
}

func TestShamirScryptCipher_DecryptWrongPassword(t *testing.T) {
	encCipher := &ShamirScryptCipher{
		ScryptN:   1 << 15,
		ScryptR:   8,
		ScryptP:   1,
		KeyLen:    32,
		Shares:    5,
		Threshold: 3,
	}
	plaintext := []byte("secret")
	password := "rightpass"
	ciphertext, shares, err := encCipher.Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	// Simulate loading HMAC from storage
	decCipher := &ShamirScryptCipher{
		ScryptN:   encCipher.ScryptN,
		ScryptR:   encCipher.ScryptR,
		ScryptP:   encCipher.ScryptP,
		KeyLen:    encCipher.KeyLen,
		Shares:    encCipher.Shares,
		Threshold: encCipher.Threshold,
		KeyHMAC:   encCipher.KeyHMAC,
	}
	_, err = decCipher.Decrypt(ciphertext, shares[:decCipher.Threshold], "wrongpass")
	if err == nil {
		t.Error("Decrypt with wrong password should fail")
	}
}
