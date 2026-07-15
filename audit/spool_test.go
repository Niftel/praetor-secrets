package audit

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"
)

func validEvent() Event {
	return Event{SchemaVersion: SchemaVersion, Timestamp: time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC), EventType: "state_transition", Operation: "credential_created", Result: "success", ReasonCode: "completed", OrganizationID: "org-5", CredentialID: "credential-1"}
}

func TestNewAndEventValidation(t *testing.T) {
	if _, err := New(make([]byte, 31), 1); !errors.Is(err, ErrAudit) {
		t.Fatalf("short key: %v", err)
	}
	if _, err := New(make([]byte, 32), 0); !errors.Is(err, ErrAudit) {
		t.Fatalf("zero bound: %v", err)
	}
	event := validEvent()
	if validate(event) != nil {
		t.Fatal("valid event rejected")
	}
	event.Operation = "Secret Value"
	if !errors.Is(validate(event), ErrEvent) {
		t.Fatal("unsafe token accepted")
	}
	event = validEvent()
	event.HumanActor = "bad\nactor"
	if !errors.Is(validate(event), ErrEvent) {
		t.Fatal("newline accepted")
	}
}

func TestLoadKeyRequiresExactRestrictedFile(t *testing.T) {
	path := t.TempDir() + "/key"
	if err := os.WriteFile(path, bytes.Repeat([]byte{1}, 32), 0o400); err != nil {
		t.Fatal(err)
	}
	key, err := LoadKey(path)
	if err != nil || len(key) != 32 {
		t.Fatalf("key=%d err=%v", len(key), err)
	}
	clear(key)
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); !errors.Is(err, ErrAudit) {
		t.Fatalf("broad key accepted: %v", err)
	}
	short := t.TempDir() + "/short"
	if err := os.WriteFile(short, make([]byte, 31), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(short); !errors.Is(err, ErrAudit) {
		t.Fatalf("short accepted: %v", err)
	}
}

func TestPublicMethodsRejectUnsafeArguments(t *testing.T) {
	spool, err := New(make([]byte, 32), 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Pending(t.Context(), nil, 1); !errors.Is(err, ErrAudit) {
		t.Fatalf("nil pool: %v", err)
	}
	if _, err := spool.Pending(t.Context(), nil, 0); !errors.Is(err, ErrAudit) {
		t.Fatalf("zero batch: %v", err)
	}
	if err := spool.MarkDelivered(t.Context(), nil, 0, nil, time.Time{}); !errors.Is(err, ErrAudit) {
		t.Fatalf("unsafe acknowledgement: %v", err)
	}
	if err := spool.Verify(t.Context(), nil); !errors.Is(err, ErrAudit) {
		t.Fatalf("nil verify: %v", err)
	}
	if err := (*Spool)(nil).Verify(t.Context(), nil); !errors.Is(err, ErrAudit) {
		t.Fatalf("nil spool: %v", err)
	}
	if token("") || token("Uppercase") || token("contains space") || !token("valid_token-1") {
		t.Fatal("token validation mismatch")
	}
}
