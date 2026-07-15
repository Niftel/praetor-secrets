package credential

import (
	"context"
	"sync"
	"time"

	"github.com/Niftel/praetor-secrets/envelope"
)

type backend interface {
	Create(context.Context, string, [32]byte, Metadata, envelope.Record) (Metadata, error)
	Get(context.Context, string, string) (Metadata, envelope.Record, error)
	Update(context.Context, string, string, uint64, Metadata, envelope.Record, string) (Metadata, error)
	RegisterBinding(context.Context, bindingRegistration) (Binding, error)
	GetBinding(context.Context, string) (Binding, error)
	CancelBinding(context.Context, string, string, string, time.Time) (Binding, error)
	ClaimResolution(context.Context, resolutionClaim, func(Binding, boundRecord) error) (Binding, time.Time, error)
}

type memoryCredential struct {
	metadata Metadata
	records  map[uint64]envelope.Record
}

type memoryBackend struct {
	mu          sync.RWMutex
	credentials map[string]*memoryCredential
	idempotency map[string]idempotencyEntry
	bindings    map[string]*memoryBinding
	attempts    map[string]memoryAttempt
}

func newMemoryBackend() *memoryBackend {
	return &memoryBackend{
		credentials: make(map[string]*memoryCredential),
		idempotency: make(map[string]idempotencyEntry),
		bindings:    make(map[string]*memoryBinding),
		attempts:    make(map[string]memoryAttempt),
	}
}

func (b *memoryBackend) Create(_ context.Context, idempotencyID string, digest [32]byte, metadata Metadata, record envelope.Record) (Metadata, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if existing, ok := b.idempotency[idempotencyID]; ok {
		if existing.digest != digest {
			return Metadata{}, ErrIdempotencyConflict
		}
		return cloneMetadata(existing.response), nil
	}
	b.credentials[metadata.ID] = &memoryCredential{
		metadata: cloneMetadata(metadata),
		records:  map[uint64]envelope.Record{metadata.Version: record},
	}
	b.idempotency[idempotencyID] = idempotencyEntry{digest: digest, response: cloneMetadata(metadata)}
	return cloneMetadata(metadata), nil
}

func (b *memoryBackend) Get(_ context.Context, organizationID, credentialID string) (Metadata, envelope.Record, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	stored, ok := b.credentials[credentialID]
	if !ok || stored.metadata.OrganizationID != organizationID {
		return Metadata{}, envelope.Record{}, ErrNotFound
	}
	return cloneMetadata(stored.metadata), stored.records[stored.metadata.Version], nil
}

func (b *memoryBackend) Update(_ context.Context, organizationID, credentialID string, expectedVersion uint64, metadata Metadata, record envelope.Record, _ string) (Metadata, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	stored, ok := b.credentials[credentialID]
	if !ok || stored.metadata.OrganizationID != organizationID {
		return Metadata{}, ErrNotFound
	}
	if stored.metadata.Version != expectedVersion {
		return Metadata{}, ErrVersionConflict
	}
	stored.records[metadata.Version] = record
	stored.metadata = cloneMetadata(metadata)
	return cloneMetadata(metadata), nil
}
