package passwort

import (
	"log/slog"
	"os"
	"runtime/debug"
)

// InitOptions holds the configuration options for initializing the passwort package.
type InitOptions struct {
	// Debug enables debug logging if set to true.
	Debug bool
}

// The init function initializes the logger for the package and other setup tasks.
func Init(options InitOptions) error {
	level := new(slog.LevelVar)
	level.Set(slog.LevelInfo)

	// Create a new logger with the specified handler.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     level,
	}))

	// If build information is available, include it in the logger.
	// This can be useful for debugging and tracking the version of the package.
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		logger = logger.With(
			slog.Group("program_info",
				"level", level.Level().String(),
				"binary", buildInfo.Path,
				"pid", os.Getpid(),
				"go_version", buildInfo.GoVersion,
			),
		)
	}

	logger = logger.With(
		"module", "passwort",
		"version", "1.0.0",
	)

	// Set the default logger for the package to the newly created logger.
	slog.SetDefault(logger)

	if options.Debug {
		// Set the logger to debug level if debug mode is enabled.
		level.Set(slog.LevelDebug)
	}

	slog.Debug("passwort package initialized")

	return nil
}
