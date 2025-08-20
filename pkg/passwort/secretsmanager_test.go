package passwort

import (
	"bytes"
	"testing"
)

func TestShamirScryptSecretsManager_EncryptDecrypt(t *testing.T) {
	mgr := &ShamirScryptSecretsManager{
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
			ciphertext, shares, err := mgr.Encrypt(tt.plaintext, tt.password)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			// Use only threshold shares for decryption
			dec, err := mgr.Decrypt(ciphertext, shares[:mgr.Threshold], tt.password)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
			if !bytes.Equal(dec, tt.plaintext) {
				t.Errorf("Decrypt = %q, want %q", dec, tt.plaintext)
			}
		})
	}
}

func TestShamirScryptSecretsManager_DecryptWrongPassword(t *testing.T) {
	encMgr := &ShamirScryptSecretsManager{
		ScryptN:   1 << 15,
		ScryptR:   8,
		ScryptP:   1,
		KeyLen:    32,
		Shares:    5,
		Threshold: 3,
	}
	plaintext := []byte("secret")
	password := "rightpass"
	ciphertext, shares, err := encMgr.Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	// Simulate loading HMAC from storage
	decMgr := &ShamirScryptSecretsManager{
		ScryptN:   encMgr.ScryptN,
		ScryptR:   encMgr.ScryptR,
		ScryptP:   encMgr.ScryptP,
		KeyLen:    encMgr.KeyLen,
		Shares:    encMgr.Shares,
		Threshold: encMgr.Threshold,
		KeyHMAC:   encMgr.KeyHMAC,
	}
	_, err = decMgr.Decrypt(ciphertext, shares[:decMgr.Threshold], "wrongpass")
	if err == nil {
		t.Error("Decrypt with wrong password should fail")
	}
}
