package app

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestRestrictedAndBoundedFileReads(t *testing.T) {
	directory := t.TempDir()
	path := directory + "/secret"
	if err := os.WriteFile(path, []byte(" value\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	value, err := readRestrictedText(path, 32)
	if err != nil || value != "value" {
		t.Fatalf("value=%q err=%v", value, err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := requireRestrictedFile(path); !errors.Is(err, ErrStartup) {
		t.Fatalf("public secret accepted: %v", err)
	}
	boundedPath := writeTemporary(t, []byte("value"), 0o400)
	if _, err := readBounded(boundedPath, 2); !errors.Is(err, ErrStartup) {
		t.Fatalf("oversize accepted: %v", err)
	}
	nulPath := writeTemporary(t, []byte{'x', 0, 'y'}, 0o400)
	if _, err := readRestrictedText(nulPath, 32); !errors.Is(err, ErrStartup) {
		t.Fatalf("NUL accepted: %v", err)
	}
	if _, err := readRestrictedText(directory+"/missing", 32); !errors.Is(err, ErrStartup) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestHealthEndpoints(t *testing.T) {
	runtime := &Runtime{}
	handler := runtime.healthHandler()
	for _, test := range []struct {
		path   string
		status int
	}{{"/livez", http.StatusOK}, {"/readyz", http.StatusServiceUnavailable}} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != test.status || recorder.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("path=%s status=%d headers=%v", test.path, recorder.Code, recorder.Header())
		}
	}
}

func TestLimitedConnectionReleasesTokenOnce(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	tokens := make(chan struct{}, 1)
	tokens <- struct{}{}
	connection := &limitedConn{Conn: left, release: func() { <-tokens }}
	_ = connection.Close()
	_ = connection.Close()
	if len(tokens) != 0 {
		t.Fatal("connection token was not released")
	}
	if _, err := readRestrictedText(writeTemporary(t, bytes.Repeat([]byte{'x'}, 8), 0o400), 4); !errors.Is(err, ErrStartup) {
		t.Fatalf("oversized restricted text accepted: %v", err)
	}
}

func writeTemporary(t *testing.T, value []byte, mode os.FileMode) string {
	t.Helper()
	path := t.TempDir() + "/value"
	if err := os.WriteFile(path, value, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
