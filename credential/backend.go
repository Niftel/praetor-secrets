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
	StartRotation(context.Context, Rotation) (Rotation, error)
	GetRotation(context.Context, string) (Rotation, error)
	RotateBatch(context.Context, string, int, func(rotationRecord) (envelope.Record, error)) (Rotation, error)
	FinalizeRotation(context.Context, string, time.Time) (Rotation, error)
	RotateCredential(context.Context, CredentialRotationRequest, func(rotationRecord) (envelope.Record, error), time.Time) error
	KeyStatus(context.Context, string, string) (KeyStatus, error)
	ValidateRecovery(context.Context, int, func(rotationRecord) error) (RecoveryValidation, error)
	RegisterBackup(context.Context, BackupSet, time.Time) (BackupSet, error)
	ExpireBackup(context.Context, string, time.Time) (BackupSet, error)
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
	rotations   map[string]*Rotation
	backups     map[string]*BackupSet
}

func newMemoryBackend() *memoryBackend {
	return &memoryBackend{
		credentials: make(map[string]*memoryCredential),
		idempotency: make(map[string]idempotencyEntry),
		bindings:    make(map[string]*memoryBinding),
		attempts:    make(map[string]memoryAttempt),
		rotations:   make(map[string]*Rotation),
		backups:     make(map[string]*BackupSet),
	}
}

func (b *memoryBackend) StartRotation(_ context.Context, rotation Rotation) (Rotation, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, existing := range b.rotations {
		if existing.State != RotationFinalized {
			return Rotation{}, ErrRotationConflict
		}
	}
	for _, credential := range b.credentials {
		for _, record := range credential.records {
			if record.MasterKeyID == rotation.SourceKeyID {
				rotation.TotalRecords++
			}
		}
	}
	if rotation.TotalRecords == 0 {
		rotation.State = RotationReady
	}
	stored := rotation
	b.rotations[rotation.ID] = &stored
	return stored, nil
}

func (b *memoryBackend) GetRotation(_ context.Context, id string) (Rotation, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	rotation, ok := b.rotations[id]
	if !ok {
		return Rotation{}, ErrNotFound
	}
	return *rotation, nil
}

func (b *memoryBackend) RotateBatch(_ context.Context, id string, limit int, transform func(rotationRecord) (envelope.Record, error)) (Rotation, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	rotation, ok := b.rotations[id]
	if !ok {
		return Rotation{}, ErrNotFound
	}
	if rotation.State == RotationFinalized {
		return *rotation, nil
	}
	type replacement struct {
		credential *memoryCredential
		version    uint64
		record     envelope.Record
	}
	var replacements []replacement
	for _, credential := range b.credentials {
		for version, record := range credential.records {
			if len(replacements) == limit {
				break
			}
			if record.MasterKeyID != rotation.SourceKeyID {
				continue
			}
			rotated, err := transform(rotationRecord{metadata: credential.metadata, version: version, record: record})
			if err != nil {
				return Rotation{}, err
			}
			replacements = append(replacements, replacement{credential: credential, version: version, record: rotated})
		}
	}
	for _, replacement := range replacements {
		replacement.credential.records[replacement.version] = replacement.record
		rotation.ProcessedRecords++
	}
	rotation.State = RotationRunning
	if rotation.ProcessedRecords == rotation.TotalRecords {
		rotation.State = RotationReady
	}
	rotation.UpdatedAt = time.Now().UTC()
	return *rotation, nil
}

func (b *memoryBackend) KeyStatus(_ context.Context, current, previous string) (KeyStatus, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	status := KeyStatus{CurrentKeyID: current, PreviousKeyID: previous, RecordCounts: map[string]int64{}}
	status.RetainedBackupReferences = map[string]int64{}
	for _, credential := range b.credentials {
		for _, record := range credential.records {
			status.RecordCounts[record.MasterKeyID]++
		}
	}
	for _, rotation := range b.rotations {
		if rotation.State != RotationFinalized {
			copy := *rotation
			status.ActiveRotation = &copy
			break
		}
	}
	status.DatabaseReferencesCleared = previous != "" && status.RecordCounts[previous] == 0 &&
		(status.ActiveRotation == nil || status.ActiveRotation.State == RotationFinalized)
	for _, backup := range b.backups {
		if backup.ExpiredAt.IsZero() {
			for _, id := range backup.KeyIDs {
				status.RetainedBackupReferences[id]++
			}
		}
	}
	status.BackupReferencesCleared = previous != "" && status.RetainedBackupReferences[previous] == 0
	return status, nil
}

func (b *memoryBackend) FinalizeRotation(_ context.Context, id string, now time.Time) (Rotation, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	rotation, ok := b.rotations[id]
	if !ok {
		return Rotation{}, ErrNotFound
	}
	if rotation.State == RotationFinalized {
		return *rotation, nil
	}
	for _, credential := range b.credentials {
		for _, record := range credential.records {
			if record.MasterKeyID == rotation.SourceKeyID {
				return Rotation{}, ErrRotationNotReady
			}
		}
	}
	rotation.State, rotation.FinalizedAt, rotation.UpdatedAt = RotationFinalized, now, now
	return *rotation, nil
}

func (b *memoryBackend) RotateCredential(_ context.Context, request CredentialRotationRequest, transform func(rotationRecord) (envelope.Record, error), _ time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	credential, ok := b.credentials[request.CredentialID]
	if !ok || credential.metadata.OrganizationID != request.OrganizationID {
		return ErrNotFound
	}
	record, ok := credential.records[request.Version]
	if !ok {
		return ErrNotFound
	}
	rotated, err := transform(rotationRecord{metadata: credential.metadata, version: request.Version, record: record})
	if err != nil {
		return err
	}
	credential.records[request.Version] = rotated
	return nil
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
