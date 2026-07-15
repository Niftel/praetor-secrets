package credential

import (
	"context"
	"time"
)

func (b *memoryBackend) RegisterBinding(_ context.Context, registration bindingRegistration) (Binding, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	request := registration.request
	for _, existing := range b.bindings {
		if existing.binding.OrganizationID == request.OrganizationID && existing.idempotencyKey == request.IdempotencyKey {
			if existing.digest != registration.digest {
				return Binding{}, ErrBindingConflict
			}
			return existing.binding, nil
		}
		if existing.binding.RunID == request.RunID || existing.binding.DispatchID == request.DispatchID {
			return Binding{}, ErrBindingConflict
		}
	}
	credential, ok := b.credentials[request.CredentialID]
	if !ok || credential.metadata.OrganizationID != request.OrganizationID || credential.metadata.State != StateActive {
		return Binding{}, ErrNotFound
	}
	state := BindingPending
	if !registration.now.Before(request.NotBefore) {
		state = BindingActive
	}
	binding := Binding{
		RunID: request.RunID, DispatchID: request.DispatchID, OrganizationID: request.OrganizationID,
		CredentialID: request.CredentialID, CredentialVersion: credential.metadata.Version,
		ExecutorIdentity: request.ExecutorIdentity, State: state, NotBefore: request.NotBefore,
		ExpiresAt: request.ExpiresAt, MaxResolutions: request.MaxResolutions,
		CreatedAt: registration.now, UpdatedAt: registration.now,
	}
	b.bindings[request.RunID] = &memoryBinding{binding: binding, idempotencyKey: request.IdempotencyKey, digest: registration.digest}
	return binding, nil
}

func (b *memoryBackend) GetBinding(_ context.Context, runID string) (Binding, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	stored, ok := b.bindings[runID]
	if !ok {
		return Binding{}, ErrBindingNotFound
	}
	return stored.binding, nil
}

func (b *memoryBackend) CancelBinding(_ context.Context, runID, dispatchID, reason string, now time.Time) (Binding, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	stored, ok := b.bindings[runID]
	if !ok {
		return Binding{}, ErrBindingNotFound
	}
	if stored.binding.DispatchID != dispatchID {
		return Binding{}, ErrBindingConflict
	}
	if stored.binding.State == BindingCanceled || stored.binding.State == BindingExpired || stored.binding.State == BindingExhausted {
		return stored.binding, nil
	}
	stored.binding.State = BindingCanceled
	stored.binding.CancelReason = reason
	stored.binding.UpdatedAt = now
	return stored.binding, nil
}

func (b *memoryBackend) ClaimResolution(_ context.Context, claim resolutionClaim, validate func(Binding, boundRecord) error) (Binding, time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	stored, ok := b.bindings[claim.runID]
	if !ok {
		return Binding{}, time.Time{}, ErrBindingNotFound
	}
	binding := &stored.binding
	if binding.ExecutorIdentity != claim.executorIdentity {
		return Binding{}, time.Time{}, ErrUnauthorized
	}
	if binding.State == BindingCanceled {
		return Binding{}, time.Time{}, ErrBindingNotActive
	}
	if binding.State == BindingExpired {
		return Binding{}, time.Time{}, ErrBindingExpired
	}
	if !claim.now.Before(binding.ExpiresAt) {
		if binding.State != BindingExhausted {
			binding.State = BindingExpired
			binding.UpdatedAt = claim.now
		}
		return Binding{}, time.Time{}, ErrBindingExpired
	}
	if claim.now.Before(binding.NotBefore) {
		return Binding{}, time.Time{}, ErrBindingNotActive
	}
	version, err := b.boundVersion(*binding)
	if err != nil {
		return Binding{}, time.Time{}, err
	}
	if err := validate(*binding, version); err != nil {
		return Binding{}, time.Time{}, err
	}

	if attempt, exists := b.attempts[claim.attemptID]; exists {
		if attempt.runID != claim.runID || attempt.executorIdentity != claim.executorIdentity || attempt.digest != claim.digest {
			return Binding{}, time.Time{}, ErrAttemptConflict
		}
		if !claim.now.Before(attempt.expiresAt) {
			return Binding{}, time.Time{}, ErrAttemptConflict
		}
		return *binding, attempt.expiresAt, nil
	}
	if binding.ResolutionCount >= binding.MaxResolutions || binding.State == BindingExhausted {
		binding.State = BindingExhausted
		binding.UpdatedAt = claim.now
		return Binding{}, time.Time{}, ErrBindingExhausted
	}

	attemptExpiry := claim.now.Add(claim.retryWindow)
	if attemptExpiry.After(binding.ExpiresAt) {
		attemptExpiry = binding.ExpiresAt
	}
	b.attempts[claim.attemptID] = memoryAttempt{
		runID: claim.runID, executorIdentity: claim.executorIdentity,
		digest: claim.digest, expiresAt: attemptExpiry,
	}
	binding.ResolutionCount++
	binding.State = BindingActive
	if binding.ResolutionCount == binding.MaxResolutions {
		binding.State = BindingExhausted
	}
	binding.UpdatedAt = claim.now
	return *binding, attemptExpiry, nil
}

func (b *memoryBackend) boundVersion(binding Binding) (boundRecord, error) {
	credential, ok := b.credentials[binding.CredentialID]
	if !ok {
		return boundRecord{}, ErrResolution
	}
	record, ok := credential.records[binding.CredentialVersion]
	if !ok {
		return boundRecord{}, ErrResolution
	}
	return boundRecord{
		record: record, credentialType: credential.metadata.CredentialType,
		schemaVersion: credential.metadata.SchemaVersion,
	}, nil
}
