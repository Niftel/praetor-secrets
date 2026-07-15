// Package credential owns encrypted credential versions and exposes only
// redacted metadata to administrative callers.
package credential

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Niftel/praetor-secrets/envelope"
	"github.com/Niftel/praetor-secrets/masterkey"
)

const (
	maxNameLength       = 255
	maxCredentialType   = 128
	maxOrganizationID   = 255
	maxInputFields      = 128
	maxFieldNameLength  = 128
	maxPlaintextPayload = 1 << 20
)

var (
	ErrInvalidInput        = errors.New("invalid credential input")
	ErrNotFound            = errors.New("credential not found")
	ErrVersionConflict     = errors.New("credential version conflict")
	ErrIdempotencyConflict = errors.New("idempotency key conflict")
	ErrEncryption          = errors.New("credential encryption failed")
)

type State string

const StateActive State = "active"

// Metadata is the complete administrative read model. It cannot represent
// plaintext or ciphertext, so both are structurally excluded from responses.
type Metadata struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Name           string    `json:"name"`
	CredentialType string    `json:"credential_type"`
	SchemaVersion  uint32    `json:"schema_version"`
	Version        uint64    `json:"version"`
	State          State     `json:"state"`
	SecretFields   []string  `json:"secret_fields"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type CreateRequest struct {
	OrganizationID string
	Name           string
	CredentialType string
	SchemaVersion  uint32
	Inputs         map[string]string
	IdempotencyKey string
}

type ReplaceInputsRequest struct {
	CredentialID    string
	OrganizationID  string
	ExpectedVersion uint64
	Inputs          map[string]string
}

type UpdateMetadataRequest struct {
	CredentialID    string
	OrganizationID  string
	ExpectedVersion uint64
	Name            string
}

// SchemaRegistry is the reviewed boundary between credential-type ownership
// and encrypted storage. Implementations must return the populated secret field
// names or ErrInvalidInput; value-bearing validation errors must not cross it.
type SchemaRegistry interface {
	Validate(credentialType string, schemaVersion uint32, inputs map[string]string) ([]string, error)
}

type storedCredential struct {
	metadata Metadata
	records  map[uint64]envelope.Record
}

type idempotencyEntry struct {
	digest   [sha256.Size]byte
	response Metadata
}

// Manager provides atomic in-process lifecycle semantics. Durable persistence
// can replace its storage boundary without changing the redacted API model.
type Manager struct {
	mu          sync.RWMutex
	keys        masterkey.Set
	schemas     SchemaRegistry
	credentials map[string]*storedCredential
	idempotency map[string]idempotencyEntry
	now         func() time.Time
	newID       func() (string, error)
}

func NewManager(keys masterkey.Set, schemas SchemaRegistry) (*Manager, error) {
	if keys.Current.ID() == "" || schemas == nil {
		return nil, ErrInvalidInput
	}
	return &Manager{
		keys: keys, schemas: schemas,
		credentials: make(map[string]*storedCredential),
		idempotency: make(map[string]idempotencyEntry),
		now:         func() time.Time { return time.Now().UTC() },
		newID:       newUUID,
	}, nil
}

func (m *Manager) Create(request CreateRequest) (Metadata, error) {
	if err := validateCreate(request); err != nil {
		return Metadata{}, err
	}
	secretFields, err := m.validateSchema(request.CredentialType, request.SchemaVersion, request.Inputs)
	if err != nil {
		return Metadata{}, err
	}
	digest, err := requestDigest(request)
	if err != nil {
		return Metadata{}, ErrInvalidInput
	}
	idempotencyID := request.OrganizationID + "\x00" + request.IdempotencyKey

	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.idempotency[idempotencyID]; ok {
		if existing.digest != digest {
			return Metadata{}, ErrIdempotencyConflict
		}
		return cloneMetadata(existing.response), nil
	}

	id, err := m.newID()
	if err != nil {
		return Metadata{}, ErrEncryption
	}
	now := m.now()
	metadata := Metadata{
		ID: id, OrganizationID: request.OrganizationID, Name: request.Name,
		CredentialType: request.CredentialType, SchemaVersion: request.SchemaVersion,
		Version: 1, State: StateActive, SecretFields: secretFields,
		CreatedAt: now, UpdatedAt: now,
	}
	record, err := m.encrypt(metadata, request.Inputs)
	if err != nil {
		return Metadata{}, err
	}
	m.credentials[id] = &storedCredential{metadata: metadata, records: map[uint64]envelope.Record{1: record}}
	m.idempotency[idempotencyID] = idempotencyEntry{digest: digest, response: cloneMetadata(metadata)}
	return cloneMetadata(metadata), nil
}

// Get returns redacted metadata only and requires the immutable organization
// owner. Cross-organization lookups are indistinguishable from missing records.
func (m *Manager) Get(organizationID, credentialID string) (Metadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	stored, ok := m.credentials[credentialID]
	if !ok || stored.metadata.OrganizationID != organizationID {
		return Metadata{}, ErrNotFound
	}
	return cloneMetadata(stored.metadata), nil
}

func (m *Manager) ReplaceInputs(request ReplaceInputsRequest) (Metadata, error) {
	if request.CredentialID == "" || request.OrganizationID == "" || request.ExpectedVersion == 0 {
		return Metadata{}, ErrInvalidInput
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	stored, ok := m.credentials[request.CredentialID]
	if !ok || stored.metadata.OrganizationID != request.OrganizationID {
		return Metadata{}, ErrNotFound
	}
	if stored.metadata.Version != request.ExpectedVersion {
		return Metadata{}, ErrVersionConflict
	}
	secretFields, err := m.validateSchema(stored.metadata.CredentialType, stored.metadata.SchemaVersion, request.Inputs)
	if err != nil {
		return Metadata{}, err
	}

	next := cloneMetadata(stored.metadata)
	next.Version++
	next.SecretFields = secretFields
	next.UpdatedAt = m.now()
	record, err := m.encrypt(next, request.Inputs)
	if err != nil {
		return Metadata{}, err
	}
	stored.records[next.Version] = record
	stored.metadata = next
	return cloneMetadata(next), nil
}

func (m *Manager) UpdateMetadata(request UpdateMetadataRequest) (Metadata, error) {
	if request.CredentialID == "" || request.OrganizationID == "" || request.ExpectedVersion == 0 || !validName(request.Name) {
		return Metadata{}, ErrInvalidInput
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	stored, ok := m.credentials[request.CredentialID]
	if !ok || stored.metadata.OrganizationID != request.OrganizationID {
		return Metadata{}, ErrNotFound
	}
	if stored.metadata.Version != request.ExpectedVersion {
		return Metadata{}, ErrVersionConflict
	}
	if stored.metadata.Name == request.Name {
		return cloneMetadata(stored.metadata), nil
	}

	currentRecord := stored.records[stored.metadata.Version]
	plaintext, err := envelope.Decrypt(currentRecord, envelopeContext(stored.metadata), m.keys.Keyring())
	if err != nil {
		return Metadata{}, ErrEncryption
	}
	defer wipe(plaintext)
	var inputs map[string]string
	if err := json.Unmarshal(plaintext, &inputs); err != nil {
		return Metadata{}, ErrEncryption
	}

	next := cloneMetadata(stored.metadata)
	next.Name = request.Name
	next.Version++
	next.UpdatedAt = m.now()
	record, err := m.encrypt(next, inputs)
	clear(inputs)
	if err != nil {
		return Metadata{}, err
	}
	stored.records[next.Version] = record
	stored.metadata = next
	return cloneMetadata(next), nil
}

func (m *Manager) encrypt(metadata Metadata, inputs map[string]string) (envelope.Record, error) {
	plaintext, err := json.Marshal(inputs)
	if err != nil || len(plaintext) > maxPlaintextPayload {
		wipe(plaintext)
		return envelope.Record{}, ErrInvalidInput
	}
	defer wipe(plaintext)
	record, err := envelope.Encrypt(plaintext, envelopeContext(metadata), m.keys.Current, nil)
	if err != nil {
		return envelope.Record{}, ErrEncryption
	}
	return record, nil
}

func (m *Manager) validateSchema(credentialType string, schemaVersion uint32, inputs map[string]string) ([]string, error) {
	if err := validateInputs(inputs); err != nil {
		return nil, err
	}
	schemaInputs := cloneInputs(inputs)
	fields, err := m.schemas.Validate(credentialType, schemaVersion, schemaInputs)
	clear(schemaInputs)
	if err != nil {
		return nil, ErrInvalidInput
	}
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		if _, ok := inputs[field]; !ok || field == "" {
			return nil, ErrInvalidInput
		}
		if _, ok := seen[field]; ok {
			return nil, ErrInvalidInput
		}
		seen[field] = struct{}{}
	}
	sort.Strings(fields)
	return append([]string(nil), fields...), nil
}

func validateCreate(request CreateRequest) error {
	if request.OrganizationID == "" || len(request.OrganizationID) > maxOrganizationID ||
		!validName(request.Name) || request.CredentialType == "" || len(request.CredentialType) > maxCredentialType ||
		request.SchemaVersion == 0 || request.IdempotencyKey == "" || len(request.IdempotencyKey) > 255 {
		return ErrInvalidInput
	}
	return nil
}

func validateInputs(inputs map[string]string) error {
	if len(inputs) == 0 || len(inputs) > maxInputFields {
		return ErrInvalidInput
	}
	for name := range inputs {
		if name == "" || len(name) > maxFieldNameLength || strings.TrimSpace(name) != name {
			return ErrInvalidInput
		}
	}
	return nil
}

func validName(name string) bool {
	return name != "" && len(name) <= maxNameLength && strings.TrimSpace(name) == name
}

func envelopeContext(metadata Metadata) envelope.Context {
	return envelope.Context{
		CredentialID: metadata.ID, OrganizationID: metadata.OrganizationID,
		SchemaVersion: metadata.SchemaVersion, CredentialVersion: metadata.Version,
	}
}

func requestDigest(request CreateRequest) ([sha256.Size]byte, error) {
	canonical := struct {
		OrganizationID string            `json:"organization_id"`
		Name           string            `json:"name"`
		CredentialType string            `json:"credential_type"`
		SchemaVersion  uint32            `json:"schema_version"`
		Inputs         map[string]string `json:"inputs"`
	}{request.OrganizationID, request.Name, request.CredentialType, request.SchemaVersion, request.Inputs}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer wipe(encoded)
	return sha256.Sum256(encoded), nil
}

func newUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

func cloneMetadata(metadata Metadata) Metadata {
	metadata.SecretFields = append([]string(nil), metadata.SecretFields...)
	return metadata
}

func cloneInputs(inputs map[string]string) map[string]string {
	out := make(map[string]string, len(inputs))
	for name, value := range inputs {
		out[name] = value
	}
	return out
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
