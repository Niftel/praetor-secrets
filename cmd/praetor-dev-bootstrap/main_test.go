package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRunGeneratesBootstrap(t *testing.T) {
	root := t.TempDir()
	secretsURL := root + "/secrets-url"
	auditURL := root + "/audit-url"
	for _, path := range []string{secretsURL, auditURL} {
		if err := os.WriteFile(path, []byte("postgres://user:password@localhost/database"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	output := root + "/generated"
	var message bytes.Buffer
	err := run([]string{"--output", output, "--namespace", "security", "--trust-domain", "praetor.local", "--secrets-database-url-file", secretsURL, "--audit-database-url-file", auditURL}, &message)
	if err != nil || !strings.Contains(message.String(), output) {
		t.Fatalf("message=%q err=%v", message.String(), err)
	}
}

func TestRunRejectsArgumentsAndGenerationFailure(t *testing.T) {
	if err := run([]string{"--unknown"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown argument accepted")
	}
	if err := run([]string{"positional"}, &bytes.Buffer{}); err == nil {
		t.Fatal("positional argument accepted")
	}
	if err := run(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("missing required configuration accepted")
	}
}
