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
		logger.Error("service configuration rejected", "event", "startup_failed")
		os.Exit(1)
	}
	startupContext, cancelStartup := context.WithTimeout(context.Background(), 30*time.Second)
	runtime, err := app.Build(startupContext, config)
	cancelStartup()
	if err != nil {
		logger.Error("service startup rejected", "event", "startup_failed")
		os.Exit(1)
	}
	runContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Info("service starting", "event", "service_starting")
	if err := runtime.Run(runContext); err != nil {
		logger.Error("service stopped unexpectedly", "event", "runtime_failed")
		os.Exit(1)
	}
	logger.Info("service stopped", "event", "service_stopped")
}
