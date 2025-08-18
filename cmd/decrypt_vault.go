package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/heimweh/passwort/pkg/crypto"
)

// Minimal struct to match vault.json
// Only the encrypted data is needed

type vaultFile struct {
	Data   map[string]string `json:"data"`
	Sealed bool              `json:"sealed"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if len(os.Args) < 4 {
		logger.Error("invalid arguments", slog.String("usage", fmt.Sprintf("%s <vault.json> <share1> <share2> [<share3> ...] <keyname>", os.Args[0])))
		os.Exit(1)
	}
	vaultPath := os.Args[1]
	shares := os.Args[2 : len(os.Args)-1]
	keyName := os.Args[len(os.Args)-1]

	vaultBytes, err := os.ReadFile(vaultPath)
	if err != nil {
		logger.Error("failed to read vault", slog.String("file", vaultPath), slog.String("error", err.Error()))
		os.Exit(1)
	}
	var vault vaultFile
	if err := json.Unmarshal(vaultBytes, &vault); err != nil {
		logger.Error("failed to parse vault", slog.String("file", vaultPath), slog.String("error", err.Error()))
		os.Exit(1)
	}

	key, err := crypto.CombineShares(shares...)
	if err != nil {
		logger.Error("failed to combine shares", slog.String("error", err.Error()))
		os.Exit(1)
	}

	enc, ok := vault.Data[keyName]
	if !ok {
		logger.Warn("key not found in vault", slog.String("key", keyName))
		os.Exit(1)
	}
	plaintext, err := crypto.Decrypt(key, enc)
	if err != nil {
		logger.Error("failed to decrypt", slog.String("key", keyName), slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.Info("decryption succeeded", slog.String("key", keyName), slog.Time("timestamp", time.Now()))
	fmt.Printf("%s\n", plaintext)
}
