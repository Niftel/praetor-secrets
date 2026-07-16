// Package envelope implements the versioned authenticated-encryption record
// used by the Praetor Secrets Service. It intentionally depends only on the Go
// standard library and composes standard AEAD primitives; it does not implement
// cryptographic algorithms.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	FormatVersion = 1
	Algorithm     = "AES-256-GCM-DEK+AES-256-GCM-KEK"
	keySize       = 32
	recordIDSize  = 16
)

var (
	ErrInvalidRecord   = errors.New("invalid envelope record")
	ErrUnsupported     = errors.New("unsupported envelope format")
	ErrUnknownKey      = errors.New("unknown master key")
	ErrContextMismatch = errors.New("envelope context mismatch")
	ErrAuthentication  = errors.New("envelope authentication failed")
)

// Context is immutable authenticated metadata supplied by the credential
// store, not trusted from the encrypted record. It prevents copying ciphertext
// between credentials, organizations, schema versions, or credential versions.
type Context struct {
	CredentialID      string `json:"credential_id"`
	OrganizationID    string `json:"organization_id"`
	SchemaVersion     uint32 `json:"schema_version"`
	CredentialVersion uint64 `json:"credential_version"`
}

func (c Context) validate() error {
	if c.CredentialID == "" || c.OrganizationID == "" || c.SchemaVersion == 0 || c.CredentialVersion == 0 {
		return ErrContextMismatch
	}
	return nil
}

func (c Context) equal(other Context) bool {
	return c.CredentialID == other.CredentialID &&
		c.OrganizationID == other.OrganizationID &&
		c.SchemaVersion == other.SchemaVersion &&
		c.CredentialVersion == other.CredentialVersion
}

// MasterKey is a named 256-bit key used only to wrap per-record data keys. The
// identifier is stored in each record so rotation can keep a bounded keyring.
type MasterKey struct {
	id  string
	key [keySize]byte
}

func NewMasterKey(id string, raw []byte) (MasterKey, error) {
	if id == "" || len(raw) != keySize {
		return MasterKey{}, fmt.Errorf("master key: %w", ErrUnknownKey)
	}
	var key [keySize]byte
	copy(key[:], raw)
	return MasterKey{id: id, key: key}, nil
}

func (k MasterKey) ID() string { return k.id }

// Record is the complete portable ciphertext format. Byte slices are encoded as
// base64 by encoding/json. Plaintext and unwrapped data keys are never fields.
type Record struct {
	Version        uint32  `json:"version"`
	Algorithm      string  `json:"algorithm"`
	RecordID       string  `json:"record_id"`
	MasterKeyID    string  `json:"master_key_id"`
	Context        Context `json:"context"`
	PayloadNonce   []byte  `json:"payload_nonce"`
	Ciphertext     []byte  `json:"ciphertext"`
	WrapNonce      []byte  `json:"wrap_nonce"`
	WrappedDataKey []byte  `json:"wrapped_data_key"`
}

type associatedData struct {
	Purpose           string `json:"purpose"`
	Version           uint32 `json:"version"`
	Algorithm         string `json:"algorithm"`
	RecordID          string `json:"record_id"`
	MasterKeyID       string `json:"master_key_id"`
	CredentialID      string `json:"credential_id"`
	OrganizationID    string `json:"organization_id"`
	SchemaVersion     uint32 `json:"schema_version"`
	CredentialVersion uint64 `json:"credential_version"`
}

func aad(purpose string, r Record, expected Context) ([]byte, error) {
	masterKeyID := ""
	if purpose == "data-key-wrap" {
		masterKeyID = r.MasterKeyID
	}
	return json.Marshal(associatedData{
		Purpose: purpose, Version: r.Version, Algorithm: r.Algorithm,
		RecordID: r.RecordID, MasterKeyID: masterKeyID,
		CredentialID: expected.CredentialID, OrganizationID: expected.OrganizationID,
		SchemaVersion: expected.SchemaVersion, CredentialVersion: expected.CredentialVersion,
	})
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomBytes(source io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(source, b); err != nil {
		return nil, err
	}
	return b, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Encrypt creates a v1 record using a new random data-encryption key. source may
// be nil to use crypto/rand.Reader; accepting a reader keeps failure paths and
// deterministic structural tests possible without replacing production entropy.
func Encrypt(plaintext []byte, context Context, master MasterKey, source io.Reader) (Record, error) {
	if err := context.validate(); err != nil || master.id == "" {
		return Record{}, ErrContextMismatch
	}
	if source == nil {
		source = rand.Reader
	}

	recordID, err := randomBytes(source, recordIDSize)
	if err != nil {
		return Record{}, fmt.Errorf("record id: %w", err)
	}
	dataKey, err := randomBytes(source, keySize)
	if err != nil {
		return Record{}, fmt.Errorf("data key: %w", err)
	}
	defer wipe(dataKey)

	record := Record{
		Version: FormatVersion, Algorithm: Algorithm,
		RecordID: hex.EncodeToString(recordID), MasterKeyID: master.id,
		Context: context,
	}

	payloadAEAD, err := newGCM(dataKey)
	if err != nil {
		return Record{}, fmt.Errorf("payload cipher: %w", err)
	}
	record.PayloadNonce, err = randomBytes(source, payloadAEAD.NonceSize())
	if err != nil {
		return Record{}, fmt.Errorf("payload nonce: %w", err)
	}
	payloadAAD, err := aad("credential-payload", record, context)
	if err != nil {
		return Record{}, fmt.Errorf("payload context: %w", err)
	}
	record.Ciphertext = payloadAEAD.Seal(nil, record.PayloadNonce, plaintext, payloadAAD)

	wrapAEAD, err := newGCM(master.key[:])
	if err != nil {
		return Record{}, fmt.Errorf("wrapping cipher: %w", err)
	}
	record.WrapNonce, err = randomBytes(source, wrapAEAD.NonceSize())
	if err != nil {
		return Record{}, fmt.Errorf("wrap nonce: %w", err)
	}
	wrapAAD, err := aad("data-key-wrap", record, context)
	if err != nil {
		return Record{}, fmt.Errorf("wrap context: %w", err)
	}
	record.WrappedDataKey = wrapAEAD.Seal(nil, record.WrapNonce, dataKey, wrapAAD)
	return record, nil
}

// Decrypt authenticates the record against context supplied by authoritative
// storage. It deliberately collapses all AEAD failures into ErrAuthentication.
func Decrypt(record Record, expected Context, keyring map[string]MasterKey) ([]byte, error) {
	dataKey, err := unwrapDataKey(record, expected, keyring)
	if err != nil {
		return nil, err
	}
	defer wipe(dataKey)
	return decryptPayload(record, expected, dataKey)
}

func unwrapDataKey(record Record, expected Context, keyring map[string]MasterKey) ([]byte, error) {
	if err := expected.validate(); err != nil {
		return nil, ErrContextMismatch
	}
	if record.Version != FormatVersion || record.Algorithm != Algorithm {
		return nil, ErrUnsupported
	}
	if record.RecordID == "" || record.MasterKeyID == "" || !record.Context.equal(expected) {
		return nil, ErrContextMismatch
	}
	master, ok := keyring[record.MasterKeyID]
	if !ok || master.id != record.MasterKeyID {
		return nil, ErrUnknownKey
	}
	if len(record.PayloadNonce) == 0 || len(record.Ciphertext) == 0 || len(record.WrapNonce) == 0 || len(record.WrappedDataKey) == 0 {
		return nil, ErrInvalidRecord
	}

	wrapAEAD, err := newGCM(master.key[:])
	if err != nil || len(record.WrapNonce) != wrapAEAD.NonceSize() {
		return nil, ErrInvalidRecord
	}
	wrapAAD, err := aad("data-key-wrap", record, expected)
	if err != nil {
		return nil, ErrInvalidRecord
	}
	dataKey, err := wrapAEAD.Open(nil, record.WrapNonce, record.WrappedDataKey, wrapAAD)
	if err != nil || len(dataKey) != keySize {
		wipe(dataKey)
		return nil, ErrAuthentication
	}
	return dataKey, nil
}

func decryptPayload(record Record, expected Context, dataKey []byte) ([]byte, error) {
	payloadAEAD, err := newGCM(dataKey)
	if err != nil || len(record.PayloadNonce) != payloadAEAD.NonceSize() {
		return nil, ErrInvalidRecord
	}
	payloadAAD, err := aad("credential-payload", record, expected)
	if err != nil {
		return nil, ErrInvalidRecord
	}
	plaintext, err := payloadAEAD.Open(nil, record.PayloadNonce, record.Ciphertext, payloadAAD)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

// Rewrap authenticates the existing wrapped DEK and payload, then wraps the
// same DEK with target and a fresh nonce. The credential ciphertext, payload
// nonce, record ID, and immutable context do not change.
func Rewrap(record Record, expected Context, keyring map[string]MasterKey, target MasterKey, source io.Reader) (Record, error) {
	if target.id == "" {
		return Record{}, ErrUnknownKey
	}
	dataKey, err := unwrapDataKey(record, expected, keyring)
	if err != nil {
		return Record{}, err
	}
	defer wipe(dataKey)
	plaintext, err := decryptPayload(record, expected, dataKey)
	if err != nil {
		return Record{}, err
	}
	wipe(plaintext)
	if source == nil {
		source = rand.Reader
	}
	rewrapped := cloneRecord(record)
	rewrapped.MasterKeyID = target.id
	wrapAEAD, err := newGCM(target.key[:])
	if err != nil {
		return Record{}, ErrAuthentication
	}
	rewrapped.WrapNonce, err = randomBytes(source, wrapAEAD.NonceSize())
	if err != nil {
		return Record{}, fmt.Errorf("wrap nonce: %w", err)
	}
	wrapAAD, err := aad("data-key-wrap", rewrapped, expected)
	if err != nil {
		return Record{}, ErrInvalidRecord
	}
	rewrapped.WrappedDataKey = wrapAEAD.Seal(nil, rewrapped.WrapNonce, dataKey, wrapAAD)
	return rewrapped, nil
}

// RotateDataKey authenticates and decrypts the record internally, then creates
// a new independently randomized envelope for the same immutable context.
func RotateDataKey(record Record, expected Context, keyring map[string]MasterKey, target MasterKey, source io.Reader) (Record, error) {
	plaintext, err := Decrypt(record, expected, keyring)
	if err != nil {
		return Record{}, err
	}
	defer wipe(plaintext)
	return Encrypt(plaintext, expected, target, source)
}

func cloneRecord(in Record) Record {
	out := in
	out.PayloadNonce = append([]byte(nil), in.PayloadNonce...)
	out.Ciphertext = append([]byte(nil), in.Ciphertext...)
	out.WrapNonce = append([]byte(nil), in.WrapNonce...)
	out.WrappedDataKey = append([]byte(nil), in.WrappedDataKey...)
	return out
}
