package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/heimweh/passwort/pkg/passwort"
)

func main() {
	flagDebug := flag.Bool("debug", false, "enable debug logging")
	flag.Parse()

	// Init initializes the passwort package, setting up necessary configurations.
	if err := passwort.Init(passwort.InitOptions{Debug: *flagDebug}); err != nil {
		abort(err)
	}
}

// abort is a helper function to log an error and exit the program.
func abort(err error) {
	if err != nil {
		slog.Error("failed to run", "error", err)
		os.Exit(1)
	}
}
