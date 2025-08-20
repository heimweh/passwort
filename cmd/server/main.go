package main

import (
	"errors"
	"flag"
	"log/slog"
	"os"

	"github.com/heimweh/passwort/pkg/passwort"
	"golang.org/x/sync/errgroup"
)

func main() {
	flagDebug := flag.Bool("debug", false, "enable debug logging")
	flagStore := flag.String("store", "inmemory", "store type (inmemory, file, etc.)")
	flagToken := flag.String("token", "", "authentication token for the server")

	flag.Parse()

	// Init initializes the passwort package, setting up necessary configurations.
	if err := passwort.Init(passwort.InitOptions{Debug: *flagDebug}); err != nil {
		abort(err)
	}

	var store passwort.Store

	switch *flagStore {
	case "inmemory":
		store = passwort.NewInmemoryStore()
	// case "file":
	// 	store = passwort.NewFileStore("path/to/store")
	default:
		abort(errors.New("unknown store type: " + *flagStore))
	}

	var group errgroup.Group

	group.Go(func() error {
		server := passwort.NewServer(store, passwort.WithAuthToken(*flagToken))
		slog.Info("server starting", "store", *flagStore)
		return server.Run(":8080")
	})

	if err := group.Wait(); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

// abort is a helper function to log an error and exit the program.
func abort(err error) {
	if err != nil {
		slog.Error("failed to run", "error", err)
		os.Exit(1)
	}
}
