package credential

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

func (b *memoryBackend) ValidateRecovery(_ context.Context, limit int, validate func(rotationRecord) error) (RecoveryValidation, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var items []rotationRecord
	for _, credential := range b.credentials {
		for version, record := range credential.records {
			items = append(items, rotationRecord{metadata: credential.metadata, version: version, record: record})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].metadata.ID == items[j].metadata.ID {
			return items[i].version < items[j].version
		}
		return items[i].metadata.ID < items[j].metadata.ID
	})
	result := RecoveryValidation{TotalRecords: int64(len(items)), KeyCounts: map[string]int64{}, CompletedAt: time.Now().UTC()}
	hash := sha256.New()
	for _, item := range items {
		result.KeyCounts[item.record.MasterKeyID]++
	}
	if limit > len(items) {
		limit = len(items)
	}
	for _, item := range items[:limit] {
		if err := validate(item); err != nil {
			return RecoveryValidation{}, err
		}
		fmt.Fprintf(hash, "%s\x00%s\x00%d\x00%d\n", item.metadata.OrganizationID, item.metadata.ID, item.version, item.metadata.SchemaVersion)
		result.ValidatedRecords++
	}
	result.MetadataSHA256 = hex.EncodeToString(hash.Sum(nil))
	return result, nil
}

func (b *memoryBackend) RegisterBackup(_ context.Context, backup BackupSet, _ time.Time) (BackupSet, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if existing, ok := b.backups[backup.ID]; ok {
		if existing.ArtifactSHA256 != backup.ArtifactSHA256 {
			return BackupSet{}, ErrBackupConflict
		}
		return *existing, nil
	}
	copy := backup
	copy.KeyIDs = append([]string(nil), backup.KeyIDs...)
	b.backups[backup.ID] = &copy
	return copy, nil
}

func (b *memoryBackend) ExpireBackup(_ context.Context, id string, now time.Time) (BackupSet, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	backup, ok := b.backups[id]
	if !ok {
		return BackupSet{}, ErrNotFound
	}
	if backup.ExpiredAt.IsZero() {
		backup.ExpiredAt = now
	}
	return *backup, nil
}
