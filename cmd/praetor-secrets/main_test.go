package main

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestFailureLoggingDiscardsSensitiveError(t *testing.T) {
	const sentinel = "SECRET-SENTINEL-DO-NOT-LOG"
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))

	logSafeFailure(logger, "service startup rejected", "startup_failed", errors.New(sentinel))

	if strings.Contains(output.String(), sentinel) {
		t.Fatalf("sensitive error crossed logging boundary: %s", output.String())
	}
	if !strings.Contains(output.String(), `"event":"startup_failed"`) {
		t.Fatalf("stable security event missing: %s", output.String())
	}
}
