// Package credential owns encrypted credential versions and exposes only
// redacted metadata to administrative callers.
package credential

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Niftel/praetor-secrets/audit"
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
	ErrCredentialNotActive = errors.New("credential is not active")
	ErrIdempotencyConflict = errors.New("idempotency key conflict")
	ErrEncryption          = errors.New("credential encryption failed")
)

type State string

const (
	StateActive  State = "active"
	StateRetired State = "retired"
)

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

type RetireRequest struct {
	CredentialID    string
	OrganizationID  string
	ExpectedVersion uint64
}

// SchemaRegistry is the reviewed boundary between credential-type ownership
// and encrypted storage. Implementations must return the populated secret field
// names or ErrInvalidInput; value-bearing validation errors must not cross it.
type SchemaRegistry interface {
	Validate(credentialType string, schemaVersion uint32, inputs map[string]string) ([]string, error)
}

type idempotencyEntry struct {
	digest   [sha256.Size]byte
	response Metadata
}

// Manager provides encrypted lifecycle semantics over either the development
// memory backend or transactional PostgreSQL storage.
type Manager struct {
	keys            masterkey.Set
	schemas         SchemaRegistry
	injector        InjectorRegistry
	configurationMu sync.RWMutex
	policy          ResolutionPolicy
	backend         backend
	now             func() time.Time
	newID           func() (string, error)
}

func NewManager(keys masterkey.Set, schemas SchemaRegistry, injectors ...InjectorRegistry) (*Manager, error) {
	if keys.Current.ID() == "" || schemas == nil || len(injectors) > 1 {
		return nil, ErrInvalidInput
	}
	var injector InjectorRegistry
	if len(injectors) == 1 {
		injector = injectors[0]
	}
	return &Manager{
		keys: keys, schemas: schemas, injector: injector,
		policy:  DefaultResolutionPolicy(),
		backend: newMemoryBackend(),
		now:     func() time.Time { return time.Now().UTC() },
		newID:   newUUID,
	}, nil
}

func (m *Manager) Create(request CreateRequest) (Metadata, error) {
	return m.CreateContext(context.Background(), request)
}

func (m *Manager) CreateContext(ctx context.Context, request CreateRequest) (Metadata, error) {
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
	return m.backend.Create(ctx, idempotencyID, digest, metadata, record)
}

// Get returns redacted metadata only and requires the immutable organization
// owner. Cross-organization lookups are indistinguishable from missing records.
func (m *Manager) Get(organizationID, credentialID string) (Metadata, error) {
	return m.GetContext(context.Background(), organizationID, credentialID)
}

func (m *Manager) GetContext(ctx context.Context, organizationID, credentialID string) (Metadata, error) {
	metadata, _, err := m.backend.Get(ctx, organizationID, credentialID)
	return metadata, err
}

func (m *Manager) ReplaceInputs(request ReplaceInputsRequest) (Metadata, error) {
	return m.ReplaceInputsContext(context.Background(), request)
}

func (m *Manager) ReplaceInputsContext(ctx context.Context, request ReplaceInputsRequest) (Metadata, error) {
	if request.CredentialID == "" || request.OrganizationID == "" || request.ExpectedVersion == 0 {
		return Metadata{}, ErrInvalidInput
	}

	current, _, err := m.backend.Get(ctx, request.OrganizationID, request.CredentialID)
	if err != nil {
		return Metadata{}, err
	}
	if current.Version != request.ExpectedVersion {
		return Metadata{}, ErrVersionConflict
	}
	if current.State != StateActive {
		return Metadata{}, ErrCredentialNotActive
	}
	secretFields, err := m.validateSchema(current.CredentialType, current.SchemaVersion, request.Inputs)
	if err != nil {
		return Metadata{}, err
	}

	next := cloneMetadata(current)
	next.Version++
	next.SecretFields = secretFields
	next.UpdatedAt = m.now()
	record, err := m.encrypt(next, request.Inputs)
	if err != nil {
		return Metadata{}, err
	}
	return m.backend.Update(ctx, request.OrganizationID, request.CredentialID, request.ExpectedVersion, next, record, audit.OperationCredentialInputsReplaced)
}

func (m *Manager) UpdateMetadata(request UpdateMetadataRequest) (Metadata, error) {
	return m.UpdateMetadataContext(context.Background(), request)
}

func (m *Manager) UpdateMetadataContext(ctx context.Context, request UpdateMetadataRequest) (Metadata, error) {
	if request.CredentialID == "" || request.OrganizationID == "" || request.ExpectedVersion == 0 || !validName(request.Name) {
		return Metadata{}, ErrInvalidInput
	}

	current, currentRecord, err := m.backend.Get(ctx, request.OrganizationID, request.CredentialID)
	if err != nil {
		return Metadata{}, err
	}
	if current.Version != request.ExpectedVersion {
		return Metadata{}, ErrVersionConflict
	}
	if current.State != StateActive {
		return Metadata{}, ErrCredentialNotActive
	}
	if current.Name == request.Name {
		return cloneMetadata(current), nil
	}

	plaintext, err := envelope.Decrypt(currentRecord, envelopeContext(current), m.keys.Keyring())
	if err != nil {
		return Metadata{}, ErrEncryption
	}
	defer wipe(plaintext)
	var inputs map[string]string
	if err := json.Unmarshal(plaintext, &inputs); err != nil {
		return Metadata{}, ErrEncryption
	}

	next := cloneMetadata(current)
	next.Name = request.Name
	next.Version++
	next.UpdatedAt = m.now()
	record, err := m.encrypt(next, inputs)
	clear(inputs)
	if err != nil {
		return Metadata{}, err
	}
	return m.backend.Update(ctx, request.OrganizationID, request.CredentialID, request.ExpectedVersion, next, record, audit.OperationCredentialMetadataUpdated)
}

func (m *Manager) Retire(request RetireRequest) (Metadata, error) {
	return m.RetireContext(context.Background(), request)
}

// RetireContext prevents new bindings without destroying versions that an
// already-authorized run or retention policy may still require. Replays are
// idempotent: once retired, the current redacted metadata is returned.
func (m *Manager) RetireContext(ctx context.Context, request RetireRequest) (Metadata, error) {
	if request.CredentialID == "" || request.OrganizationID == "" || request.ExpectedVersion == 0 {
		return Metadata{}, ErrInvalidInput
	}
	current, currentRecord, err := m.backend.Get(ctx, request.OrganizationID, request.CredentialID)
	if err != nil {
		return Metadata{}, err
	}
	if current.State == StateRetired {
		return cloneMetadata(current), nil
	}
	if current.State != StateActive {
		return Metadata{}, ErrCredentialNotActive
	}
	if current.Version != request.ExpectedVersion {
		return Metadata{}, ErrVersionConflict
	}
	plaintext, err := envelope.Decrypt(currentRecord, envelopeContext(current), m.keys.Keyring())
	if err != nil {
		return Metadata{}, ErrEncryption
	}
	defer wipe(plaintext)
	var inputs map[string]string
	if err := json.Unmarshal(plaintext, &inputs); err != nil {
		return Metadata{}, ErrEncryption
	}
	next := cloneMetadata(current)
	next.Version++
	next.State = StateRetired
	next.UpdatedAt = m.now()
	record, err := m.encrypt(next, inputs)
	clear(inputs)
	if err != nil {
		return Metadata{}, err
	}
	return m.backend.Update(ctx, request.OrganizationID, request.CredentialID, request.ExpectedVersion, next, record, audit.OperationCredentialRetired)
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
