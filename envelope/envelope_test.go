package envelope

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func testKey(t *testing.T, id string, fill byte) MasterKey {
	t.Helper()
	key, err := NewMasterKey(id, bytes.Repeat([]byte{fill}, keySize))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testContext() Context {
	return Context{CredentialID: "cred-1", OrganizationID: "org-5", SchemaVersion: 1, CredentialVersion: 3}
}

func TestRoundTripAndJSON(t *testing.T) {
	master := testKey(t, "mk-2026-01", 0x41)
	for _, plaintext := range [][]byte{nil, {}, []byte("secret"), bytes.Repeat([]byte("x"), 1<<20)} {
		record, err := Encrypt(plaintext, testContext(), master, nil)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, plaintext) && len(plaintext) > 0 {
			t.Fatal("serialized record contains plaintext")
		}
		var decoded Record
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		got, err := Decrypt(decoded, testContext(), map[string]MasterKey{master.ID(): master})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round trip mismatch")
		}
	}
}

func TestEncryptionIsRandomized(t *testing.T) {
	master := testKey(t, "mk-1", 0x42)
	a, err := Encrypt([]byte("same"), testContext(), master, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt([]byte("same"), testContext(), master, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.RecordID == b.RecordID || bytes.Equal(a.PayloadNonce, b.PayloadNonce) ||
		bytes.Equal(a.WrapNonce, b.WrapNonce) || bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("independent encryptions reused randomized material")
	}
}

func TestWrongAndUnknownKeysFail(t *testing.T) {
	master := testKey(t, "mk-1", 0x43)
	record, err := Encrypt([]byte("secret"), testContext(), master, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(record, testContext(), nil); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: got %v", err)
	}
	wrong := testKey(t, "mk-1", 0x44)
	if _, err := Decrypt(record, testContext(), map[string]MasterKey{"mk-1": wrong}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong key: got %v", err)
	}
}

func TestContextSubstitutionFails(t *testing.T) {
	master := testKey(t, "mk-1", 0x45)
	record, err := Encrypt([]byte("secret"), testContext(), master, nil)
	if err != nil {
		t.Fatal(err)
	}
	contexts := []Context{
		{CredentialID: "cred-2", OrganizationID: "org-5", SchemaVersion: 1, CredentialVersion: 3},
		{CredentialID: "cred-1", OrganizationID: "org-6", SchemaVersion: 1, CredentialVersion: 3},
		{CredentialID: "cred-1", OrganizationID: "org-5", SchemaVersion: 2, CredentialVersion: 3},
		{CredentialID: "cred-1", OrganizationID: "org-5", SchemaVersion: 1, CredentialVersion: 4},
	}
	for _, context := range contexts {
		if _, err := Decrypt(record, context, map[string]MasterKey{"mk-1": master}); !errors.Is(err, ErrContextMismatch) {
			t.Fatalf("context %+v: got %v", context, err)
		}
	}
}

func TestTamperingFailsClosed(t *testing.T) {
	master := testKey(t, "mk-1", 0x46)
	original, err := Encrypt([]byte("secret"), testContext(), master, nil)
	if err != nil {
		t.Fatal(err)
	}
	keyring := map[string]MasterKey{"mk-1": master}

	tests := map[string]func(*Record){
		"record id":        func(r *Record) { r.RecordID = "00" + r.RecordID[2:] },
		"payload nonce":    func(r *Record) { r.PayloadNonce[0] ^= 1 },
		"ciphertext":       func(r *Record) { r.Ciphertext[0] ^= 1 },
		"wrap nonce":       func(r *Record) { r.WrapNonce[0] ^= 1 },
		"wrapped data key": func(r *Record) { r.WrappedDataKey[0] ^= 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			record := cloneRecord(original)
			mutate(&record)
			if _, err := Decrypt(record, testContext(), keyring); err == nil {
				t.Fatal("tampered record decrypted")
			}
		})
	}
}

func TestMalformedAndUnsupportedRecordsFail(t *testing.T) {
	master := testKey(t, "mk-1", 0x47)
	record, err := Encrypt([]byte("secret"), testContext(), master, nil)
	if err != nil {
		t.Fatal(err)
	}
	keyring := map[string]MasterKey{"mk-1": master}

	unsupported := cloneRecord(record)
	unsupported.Version++
	if _, err := Decrypt(unsupported, testContext(), keyring); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported: got %v", err)
	}
	malformed := cloneRecord(record)
	malformed.WrapNonce = malformed.WrapNonce[:1]
	if _, err := Decrypt(malformed, testContext(), keyring); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("malformed: got %v", err)
	}
}

func TestEntropyFailureReturnsNoRecord(t *testing.T) {
	master := testKey(t, "mk-1", 0x48)
	if record, err := Encrypt([]byte("secret"), testContext(), master, bytes.NewReader(nil)); err == nil || record.RecordID != "" {
		t.Fatalf("entropy failure returned record=%+v err=%v", record, err)
	}
}

func TestMasterKeyValidation(t *testing.T) {
	for _, tc := range []struct {
		id  string
		key []byte
	}{{"", bytes.Repeat([]byte{1}, keySize)}, {"mk", nil}, {"mk", bytes.Repeat([]byte{1}, keySize-1)}} {
		if _, err := NewMasterKey(tc.id, tc.key); err == nil {
			t.Fatalf("accepted id=%q key length=%d", tc.id, len(tc.key))
		}
	}
}

func TestPayloadAADIsIndependentOfMasterKeyID(t *testing.T) {
	record := Record{
		Version: FormatVersion, Algorithm: Algorithm, RecordID: "record-1",
		MasterKeyID: "old-key", Context: testContext(),
	}
	oldPayload, err := aad("credential-payload", record, testContext())
	if err != nil {
		t.Fatal(err)
	}
	oldWrap, err := aad("data-key-wrap", record, testContext())
	if err != nil {
		t.Fatal(err)
	}
	record.MasterKeyID = "new-key"
	newPayload, err := aad("credential-payload", record, testContext())
	if err != nil {
		t.Fatal(err)
	}
	newWrap, err := aad("data-key-wrap", record, testContext())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldPayload, newPayload) {
		t.Fatal("payload associated data changed with KEK identifier")
	}
	if bytes.Equal(oldWrap, newWrap) {
		t.Fatal("wrapped-key associated data did not bind KEK identifier")
	}
}

func TestRewrapPreservesPayloadAndChangesWrappingKey(t *testing.T) {
	oldKey := testKey(t, "old-key", 0x51)
	newKey := testKey(t, "new-key", 0x52)
	record, err := Encrypt([]byte("secret"), testContext(), oldKey, nil)
	if err != nil {
		t.Fatal(err)
	}

	rewrapped, err := Rewrap(record, testContext(), map[string]MasterKey{oldKey.ID(): oldKey}, newKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rewrapped.MasterKeyID != newKey.ID() || rewrapped.RecordID != record.RecordID ||
		!bytes.Equal(rewrapped.PayloadNonce, record.PayloadNonce) ||
		!bytes.Equal(rewrapped.Ciphertext, record.Ciphertext) ||
		bytes.Equal(rewrapped.WrapNonce, record.WrapNonce) ||
		bytes.Equal(rewrapped.WrappedDataKey, record.WrappedDataKey) {
		t.Fatal("rewrap changed payload identity or reused wrapping material")
	}
	plaintext, err := Decrypt(rewrapped, testContext(), map[string]MasterKey{newKey.ID(): newKey})
	if err != nil || !bytes.Equal(plaintext, []byte("secret")) {
		t.Fatalf("rewrapped decrypt=%q err=%v", plaintext, err)
	}
}

func TestRewrapFailsBeforeMutation(t *testing.T) {
	oldKey := testKey(t, "old-key", 0x53)
	newKey := testKey(t, "new-key", 0x54)
	record, err := Encrypt([]byte("secret"), testContext(), oldKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	tampered := cloneRecord(record)
	tampered.Ciphertext[0] ^= 1
	if rotated, err := Rewrap(tampered, testContext(), map[string]MasterKey{oldKey.ID(): oldKey}, newKey, nil); !errors.Is(err, ErrAuthentication) || rotated.RecordID != "" {
		t.Fatalf("tampered rewrap returned record=%+v err=%v", rotated, err)
	}
	if rotated, err := Rewrap(record, testContext(), map[string]MasterKey{oldKey.ID(): oldKey}, newKey, bytes.NewReader(nil)); err == nil || rotated.RecordID != "" {
		t.Fatalf("entropy failure returned record=%+v err=%v", rotated, err)
	}
}

func TestRotateDataKeyReencryptsCredential(t *testing.T) {
	oldKey := testKey(t, "old-key", 0x55)
	newKey := testKey(t, "new-key", 0x56)
	record, err := Encrypt([]byte("secret"), testContext(), oldKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := RotateDataKey(record, testContext(), map[string]MasterKey{oldKey.ID(): oldKey}, newKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.RecordID == record.RecordID || bytes.Equal(rotated.PayloadNonce, record.PayloadNonce) ||
		bytes.Equal(rotated.Ciphertext, record.Ciphertext) || rotated.MasterKeyID != newKey.ID() {
		t.Fatal("data-key rotation reused record material")
	}
	plaintext, err := Decrypt(rotated, testContext(), map[string]MasterKey{newKey.ID(): newKey})
	if err != nil || !bytes.Equal(plaintext, []byte("secret")) {
		t.Fatalf("rotated decrypt=%q err=%v", plaintext, err)
	}
}
