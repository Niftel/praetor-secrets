package envelope

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func FuzzEnvelopeRejectsMutatedRecords(f *testing.F) {
	key, err := NewMasterKey("fuzz-key", bytes.Repeat([]byte{0x91}, keySize))
	if err != nil {
		f.Fatal(err)
	}
	context := testContext()
	record, err := Encrypt([]byte("CANARY-PLAINTEXT-NEVER-RETURN"), context, key, bytes.NewReader(bytes.Repeat([]byte{0x41}, 128)))
	if err != nil {
		f.Fatal(err)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Fuzz(func(t *testing.T, candidate []byte) {
		var mutated Record
		if json.Unmarshal(candidate, &mutated) != nil {
			return
		}
		plaintext, err := Decrypt(mutated, context, map[string]MasterKey{key.ID(): key})
		if err == nil && !reflect.DeepEqual(mutated, record) {
			t.Fatal("mutated serialized envelope authenticated")
		}
		if bytes.Contains([]byte(errString(err)), []byte("CANARY-PLAINTEXT")) {
			t.Fatal("failure exposed canary plaintext")
		}
		wipe(plaintext)
	})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
