package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Niftel/praetor-secrets/app"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config, err := app.LoadConfig(os.LookupEnv)
	if err != nil {
		logSafeFailure(logger, "service configuration rejected", "startup_failed", err)
		os.Exit(1)
	}
	startupContext, cancelStartup := context.WithTimeout(context.Background(), 30*time.Second)
	runtime, err := app.Build(startupContext, config)
	cancelStartup()
	if err != nil {
		logSafeFailure(logger, "service startup rejected", "startup_failed", err)
		os.Exit(1)
	}
	runContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Info("service starting", "event", "service_starting")
	if err := runtime.Run(runContext); err != nil {
		logSafeFailure(logger, "service stopped unexpectedly", "runtime_failed", err)
		os.Exit(1)
	}
	logger.Info("service stopped", "event", "service_stopped")
}

// logSafeFailure deliberately discards the underlying error. Errors in this
// process can carry secret-provider, cryptographic, database, or filesystem
// details and must never cross the service logging boundary.
func logSafeFailure(logger *slog.Logger, message, event string, _ error) {
	logger.Error(message, "event", event)
}
