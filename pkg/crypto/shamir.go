package crypto

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/hashicorp/vault/shamir"
)

// SplitKey splits a key into n shares with a threshold of k.
func SplitKey(key []byte, n, k int) ([]string, error) {
	shares, err := shamir.Split(key, n, k)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range shares {
		out = append(out, base64.StdEncoding.EncodeToString(s))
	}
	return out, nil
}

// CombineShares combines base64 shares into a key.
func CombineShares(shares ...string) ([]byte, error) {
	var bshares [][]byte
	for _, s := range shares {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		bshares = append(bshares, b)
	}
	return shamir.Combine(bshares)
}

// GenerateKey returns a new random 32-byte key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}
