package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Niftel/praetor-secrets/auditsink"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config, err := auditsink.LoadConfig(os.LookupEnv)
	if err != nil {
		logger.Error("audit sink configuration rejected", "event", "startup_failed")
		os.Exit(1)
	}
	startupContext, cancelStartup := context.WithTimeout(context.Background(), 30*time.Second)
	runtime, err := auditsink.Build(startupContext, config)
	cancelStartup()
	if err != nil {
		logger.Error("audit sink startup rejected", "event", "startup_failed")
		os.Exit(1)
	}
	runContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Info("audit sink starting", "event", "service_starting")
	if runtime.Run(runContext) != nil {
		logger.Error("audit sink stopped unexpectedly", "event", "runtime_failed")
		os.Exit(1)
	}
	logger.Info("audit sink stopped", "event", "service_stopped")
}
