package auditsink

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/Niftel/praetor-secrets/audit"
)

func validRecord(sequence int64) audit.Record {
	mac := make([]byte, 32)
	mac[31] = byte(sequence)
	return audit.Record{Sequence: sequence, MAC: mac, Event: audit.Event{
		SchemaVersion: audit.SchemaVersion, Timestamp: time.Date(2026, 7, 15, 18, 0, 0, 0, time.UTC),
		EventType: "state_transition", Operation: "run_binding_canceled", Result: "success", ReasonCode: "run_successful",
	}}
}

func key(record audit.Record) string { return "audit-" + hex.EncodeToString(record.MAC) }

func TestValidateRemoteAuditRecord(t *testing.T) {
	record := validRecord(1)
	if _, err := validate(record, key(record), "praetor-secrets"); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	for _, test := range []struct {
		name     string
		record   audit.Record
		key      string
		identity string
	}{
		{"zero sequence", audit.Record{Event: record.Event, MAC: record.MAC}, key(record), "praetor-secrets"},
		{"short mac", audit.Record{Sequence: 1, Event: record.Event, MAC: []byte("short")}, key(record), "praetor-secrets"},
		{"wrong key", record, "audit-wrong", "praetor-secrets"},
		{"wrong identity", record, key(record), "praetor-scheduler"},
		{"empty operation", audit.Record{Sequence: 1, Event: audit.Event{SchemaVersion: 1, Timestamp: record.Event.Timestamp}, MAC: record.MAC}, key(record), "praetor-secrets"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validate(test.record, test.key, test.identity); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error=%v, want ErrInvalid", err)
			}
		})
	}
}

func TestNewStoreRejectsNilPool(t *testing.T) {
	if _, err := NewStore(nil); !errors.Is(err, ErrStore) {
		t.Fatalf("error=%v, want ErrStore", err)
	}
}
