package masterkey

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Niftel/praetor-secrets/envelope"
)

func writeKey(t *testing.T, name string, value []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, value, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCurrentKeyAndRoundTrip(t *testing.T) {
	path := writeKey(t, "current", bytes.Repeat([]byte{0x31}, keySize), 0o400)
	keys, err := Load(Config{CurrentPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if keys.Current.ID() == "" || keys.Previous != nil || len(keys.Keyring()) != 1 {
		t.Fatalf("unexpected key set: current=%q previous=%v ring=%d", keys.Current.ID(), keys.Previous, len(keys.Keyring()))
	}

	context := envelope.Context{CredentialID: "cred-1", OrganizationID: "org-1", SchemaVersion: 1, CredentialVersion: 1}
	record, err := envelope.Encrypt([]byte("secret"), context, keys.Current, nil)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := envelope.Decrypt(record, context, keys.Keyring())
	if err != nil || !bytes.Equal(plaintext, []byte("secret")) {
		t.Fatalf("round trip: plaintext=%q err=%v", plaintext, err)
	}
}

func TestLoadRotationSetKeepsPreviousDecryptOnly(t *testing.T) {
	currentPath := writeKey(t, "current", bytes.Repeat([]byte{0x41}, keySize), 0o400)
	previousPath := writeKey(t, "previous", bytes.Repeat([]byte{0x42}, keySize), 0o400)
	keys, err := Load(Config{CurrentPath: currentPath, PreviousPath: previousPath})
	if err != nil {
		t.Fatal(err)
	}
	if keys.Previous == nil || len(keys.Keyring()) != 2 {
		t.Fatalf("rotation keyring not loaded")
	}

	context := envelope.Context{CredentialID: "cred-1", OrganizationID: "org-1", SchemaVersion: 1, CredentialVersion: 1}
	oldRecord, err := envelope.Encrypt([]byte("old"), context, *keys.Previous, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Decrypt(oldRecord, context, keys.Keyring()); err != nil {
		t.Fatalf("previous key could not decrypt: %v", err)
	}
	newRecord, err := envelope.Encrypt([]byte("new"), context, keys.Current, nil)
	if err != nil {
		t.Fatal(err)
	}
	if newRecord.MasterKeyID != keys.Current.ID() {
		t.Fatal("new encryption did not use current key")
	}
}

func TestLoadFailsClosed(t *testing.T) {
	valid := bytes.Repeat([]byte{0x51}, keySize)
	tests := []struct {
		name   string
		config func(*testing.T) Config
		want   error
	}{
		{"missing current path", func(t *testing.T) Config { return Config{} }, ErrKeyFile},
		{"missing file", func(t *testing.T) Config { return Config{CurrentPath: filepath.Join(t.TempDir(), "missing")} }, ErrKeyFile},
		{"directory", func(t *testing.T) Config { return Config{CurrentPath: t.TempDir()} }, ErrKeyFile},
		{"short key", func(t *testing.T) Config { return Config{CurrentPath: writeKey(t, "short", valid[:31], 0o400)} }, ErrKeyLength},
		{"long key", func(t *testing.T) Config {
			return Config{CurrentPath: writeKey(t, "long", append(append([]byte(nil), valid...), 0), 0o400)}
		}, ErrKeyLength},
		{"newline encoded key", func(t *testing.T) Config {
			return Config{CurrentPath: writeKey(t, "newline", append(append([]byte(nil), valid...), '\n'), 0o400)}
		}, ErrKeyLength},
		{"group readable", func(t *testing.T) Config { return Config{CurrentPath: writeKey(t, "group", valid, 0o440)} }, ErrKeyPermissions},
		{"world readable", func(t *testing.T) Config { return Config{CurrentPath: writeKey(t, "world", valid, 0o444)} }, ErrKeyPermissions},
		{"missing previous", func(t *testing.T) Config {
			return Config{CurrentPath: writeKey(t, "current", valid, 0o400), PreviousPath: filepath.Join(t.TempDir(), "missing")}
		}, ErrKeyFile},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := test.config(t)
			_, err := Load(config)
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			if (config.CurrentPath != "" && strings.Contains(err.Error(), config.CurrentPath)) ||
				(config.PreviousPath != "" && strings.Contains(err.Error(), config.PreviousPath)) {
				t.Fatalf("error leaked key path: %v", err)
			}
		})
	}
}

func TestLoadRejectsIdenticalRotationKeys(t *testing.T) {
	value := bytes.Repeat([]byte{0x61}, keySize)
	_, err := Load(Config{
		CurrentPath:  writeKey(t, "current", value, 0o400),
		PreviousPath: writeKey(t, "previous", value, 0o400),
	})
	if !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("got %v", err)
	}
}

func TestKeyringReturnsCopy(t *testing.T) {
	keys, err := Load(Config{CurrentPath: writeKey(t, "current", bytes.Repeat([]byte{0x71}, keySize), 0o400)})
	if err != nil {
		t.Fatal(err)
	}
	ring := keys.Keyring()
	delete(ring, keys.Current.ID())
	if len(keys.Keyring()) != 1 {
		t.Fatal("caller mutated internal keyring")
	}
}
