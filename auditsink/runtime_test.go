package auditsink

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestRuntimeHealthBeforeStart(t *testing.T) {
	runtime := &Runtime{}
	for _, test := range []struct {
		path   string
		status int
	}{{"/livez", http.StatusOK}, {"/readyz", http.StatusServiceUnavailable}} {
		response := httptest.NewRecorder()
		runtime.healthHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
		if response.Code != test.status || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("path=%s status=%d headers=%v", test.path, response.Code, response.Header())
		}
	}
}

func TestRuntimeRestrictedReadsAndConnectionLimit(t *testing.T) {
	path := writeSinkFile(t, t.TempDir()+"/secret", []byte(" value\n"), 0o400)
	if value, err := readRestrictedText(path, 32); err != nil || value != "value" {
		t.Fatalf("value=%q err=%v", value, err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := requireRestrictedFile(path); !errors.Is(err, ErrStartup) {
		t.Fatalf("public file accepted: %v", err)
	}
	if _, err := readBounded(writeSinkFile(t, t.TempDir()+"/large", bytes.Repeat([]byte{'x'}, 8), 0o400), 4); !errors.Is(err, ErrStartup) {
		t.Fatalf("oversized file accepted: %v", err)
	}
	left, right := net.Pipe()
	defer right.Close()
	token := make(chan struct{}, 1)
	token <- struct{}{}
	connection := &limitedConn{Conn: left, release: func() { <-token }}
	_ = connection.Close()
	_ = connection.Close()
	if len(token) != 0 {
		t.Fatal("connection token not released")
	}
}

func writeSinkFile(t *testing.T, path string, value []byte, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, value, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
