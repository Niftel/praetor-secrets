package credential

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/Niftel/praetor-secrets/envelope"
)

var (
	ErrUnauthorized     = errors.New("workload identity is not authorized")
	ErrBindingNotFound  = errors.New("run binding not found")
	ErrBindingConflict  = errors.New("run binding conflict")
	ErrBindingNotActive = errors.New("run binding is not active")
	ErrBindingExpired   = errors.New("run binding expired")
	ErrBindingExhausted = errors.New("run binding exhausted")
	ErrAttemptConflict  = errors.New("resolution attempt conflict")
	ErrResolution       = errors.New("credential resolution failed")
)

type WorkloadRole string

const (
	RoleScheduler WorkloadRole = "praetor-scheduler"
	RoleExecutor  WorkloadRole = "praetor-executor"
)

type WorkloadIdentity struct {
	Role    WorkloadRole
	Subject string
}

type BindingState string

const (
	BindingPending   BindingState = "pending"
	BindingActive    BindingState = "active"
	BindingCanceled  BindingState = "canceled"
	BindingExpired   BindingState = "expired"
	BindingExhausted BindingState = "exhausted"
)

type Binding struct {
	RunID             string       `json:"run_id"`
	DispatchID        string       `json:"dispatch_id"`
	OrganizationID    string       `json:"organization_id"`
	CredentialID      string       `json:"credential_id"`
	CredentialVersion uint64       `json:"credential_version"`
	ExecutorIdentity  string       `json:"executor_identity"`
	State             BindingState `json:"state"`
	NotBefore         time.Time    `json:"not_before"`
	ExpiresAt         time.Time    `json:"expires_at"`
	MaxResolutions    uint32       `json:"max_resolutions"`
	ResolutionCount   uint32       `json:"resolution_count"`
	CreatedAt         time.Time    `json:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
	CancelReason      string       `json:"cancel_reason,omitempty"`
}

type RegisterBindingRequest struct {
	RunID            string
	DispatchID       string
	OrganizationID   string
	CredentialID     string
	ExecutorIdentity string
	NotBefore        time.Time
	ExpiresAt        time.Time
	MaxResolutions   uint32
	IdempotencyKey   string
}

type ResolveRequest struct {
	RunID       string
	AttemptID   string
	RequestedAt time.Time
}

type ResolvedFile struct {
	Name    string `json:"name"`
	Mode    string `json:"mode"`
	Content string `json:"content"`
}

type ResolvedCredential struct {
	RunID       string            `json:"run_id"`
	AttemptID   string            `json:"attempt_id"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Environment map[string]string `json:"environment,omitempty"`
	Files       []ResolvedFile    `json:"files,omitempty"`
}

type InjectorResult struct {
	Environment map[string]string
	Files       []ResolvedFile
}

type InjectorRegistry interface {
	Render(credentialType string, schemaVersion uint32, inputs map[string]string) (InjectorResult, error)
}

type ResolutionPolicy struct {
	MaxBindingLifetime time.Duration
	MaxFutureStart     time.Duration
	MaxResolutions     uint32
	AttemptRetryWindow time.Duration
	MaxResponseBytes   int
}

func DefaultResolutionPolicy() ResolutionPolicy {
	return ResolutionPolicy{
		MaxBindingLifetime: 24 * time.Hour,
		MaxFutureStart:     15 * time.Minute,
		MaxResolutions:     3,
		AttemptRetryWindow: 5 * time.Minute,
		MaxResponseBytes:   1 << 20,
	}
}

func (m *Manager) SetResolutionPolicy(policy ResolutionPolicy) error {
	if policy.MaxBindingLifetime <= 0 || policy.MaxFutureStart < 0 || policy.MaxResolutions == 0 ||
		policy.AttemptRetryWindow <= 0 || policy.MaxResponseBytes <= 0 {
		return ErrInvalidInput
	}
	m.configurationMu.Lock()
	defer m.configurationMu.Unlock()
	m.policy = policy
	return nil
}

func (m *Manager) resolutionPolicy() ResolutionPolicy {
	m.configurationMu.RLock()
	defer m.configurationMu.RUnlock()
	return m.policy
}

type bindingRegistration struct {
	request RegisterBindingRequest
	digest  [sha256.Size]byte
	now     time.Time
}

type resolutionClaim struct {
	runID            string
	attemptID        string
	executorIdentity string
	digest           [sha256.Size]byte
	now              time.Time
	retryWindow      time.Duration
}

type boundRecord struct {
	record         envelope.Record
	credentialType string
	schemaVersion  uint32
}

type memoryBinding struct {
	binding        Binding
	idempotencyKey string
	digest         [sha256.Size]byte
}

type memoryAttempt struct {
	runID            string
	executorIdentity string
	digest           [sha256.Size]byte
	expiresAt        time.Time
}

func (m *Manager) RegisterBinding(ctx context.Context, caller WorkloadIdentity, request RegisterBindingRequest) (Binding, error) {
	now := m.now()
	policy := m.resolutionPolicy()
	if !isScheduler(caller) || !validBindingRequest(request, now, policy) {
		if !isScheduler(caller) {
			return Binding{}, ErrUnauthorized
		}
		return Binding{}, ErrInvalidInput
	}
	digest, err := bindingDigest(request)
	if err != nil {
		return Binding{}, ErrInvalidInput
	}
	return m.backend.RegisterBinding(ctx, bindingRegistration{request: request, digest: digest, now: now})
}

func (m *Manager) InspectBinding(ctx context.Context, caller WorkloadIdentity, runID string) (Binding, error) {
	if !isScheduler(caller) {
		return Binding{}, ErrUnauthorized
	}
	if !validUUID(runID) {
		return Binding{}, ErrInvalidInput
	}
	return m.backend.GetBinding(ctx, runID)
}

func (m *Manager) CancelBinding(ctx context.Context, caller WorkloadIdentity, runID, reason string) (Binding, error) {
	if !isScheduler(caller) {
		return Binding{}, ErrUnauthorized
	}
	if !validUUID(runID) || !validReason(reason) {
		return Binding{}, ErrInvalidInput
	}
	return m.backend.CancelBinding(ctx, runID, reason, m.now())
}

func (m *Manager) Resolve(ctx context.Context, caller WorkloadIdentity, request ResolveRequest) (ResolvedCredential, error) {
	if caller.Role != RoleExecutor || !validExecutorIdentity(caller.Subject) {
		return ResolvedCredential{}, ErrUnauthorized
	}
	if m.injector == nil || !validUUID(request.RunID) || !validUUID(request.AttemptID) || request.RequestedAt.IsZero() {
		return ResolvedCredential{}, ErrInvalidInput
	}
	digest := sha256.Sum256([]byte(request.RunID + "\x00" + request.AttemptID + "\x00" + request.RequestedAt.UTC().Format(time.RFC3339Nano)))
	policy := m.resolutionPolicy()
	var rendered InjectorResult
	_, attemptExpiry, err := m.backend.ClaimResolution(ctx, resolutionClaim{
		runID: request.RunID, attemptID: request.AttemptID, executorIdentity: caller.Subject,
		digest: digest, now: m.now(), retryWindow: policy.AttemptRetryWindow,
	}, func(binding Binding, version boundRecord) error {
		context := envelope.Context{
			CredentialID: binding.CredentialID, OrganizationID: binding.OrganizationID,
			SchemaVersion: version.schemaVersion, CredentialVersion: binding.CredentialVersion,
		}
		plaintext, decryptErr := envelope.Decrypt(version.record, context, m.keys.Keyring())
		if decryptErr != nil {
			return ErrResolution
		}
		defer wipe(plaintext)
		var inputs map[string]string
		if decodeErr := json.Unmarshal(plaintext, &inputs); decodeErr != nil {
			return ErrResolution
		}
		result, renderErr := m.injector.Render(version.credentialType, version.schemaVersion, cloneInputs(inputs))
		clear(inputs)
		if renderErr != nil || !validInjectorResult(result, policy.MaxResponseBytes) {
			return ErrResolution
		}
		rendered = result
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrBindingNotFound) || errors.Is(err, ErrUnauthorized) ||
			errors.Is(err, ErrBindingExpired) || errors.Is(err, ErrBindingExhausted) {
			return ResolvedCredential{}, ErrBindingNotActive
		}
		return ResolvedCredential{}, err
	}
	return ResolvedCredential{
		RunID: request.RunID, AttemptID: request.AttemptID, ExpiresAt: attemptExpiry,
		Environment: cloneInputs(rendered.Environment), Files: append([]ResolvedFile(nil), rendered.Files...),
	}, nil
}

func isScheduler(identity WorkloadIdentity) bool {
	return identity.Role == RoleScheduler && identity.Subject == string(RoleScheduler)
}

func validBindingRequest(request RegisterBindingRequest, now time.Time, policy ResolutionPolicy) bool {
	return validUUID(request.RunID) && validUUID(request.DispatchID) && validUUID(request.CredentialID) &&
		request.OrganizationID != "" && validExecutorIdentity(request.ExecutorIdentity) &&
		!request.NotBefore.Before(now.Add(-time.Minute)) && !request.NotBefore.After(now.Add(policy.MaxFutureStart)) &&
		request.ExpiresAt.After(now) && request.ExpiresAt.After(request.NotBefore) && request.ExpiresAt.Sub(request.NotBefore) <= policy.MaxBindingLifetime &&
		request.MaxResolutions > 0 && request.MaxResolutions <= policy.MaxResolutions &&
		request.IdempotencyKey != "" && len(request.IdempotencyKey) <= 255
}

func validExecutorIdentity(value string) bool {
	return strings.HasPrefix(value, string(RoleExecutor)+":") && len(value) > len(string(RoleExecutor))+1 && len(value) <= 255 &&
		!strings.ContainsAny(value, " \t\r\n\x00")
}

func validReason(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !(unicode.IsLower(character) || unicode.IsDigit(character) || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func bindingDigest(request RegisterBindingRequest) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer wipe(encoded)
	return sha256.Sum256(encoded), nil
}

func validInjectorResult(result InjectorResult, limit int) bool {
	total := 0
	for name, value := range result.Environment {
		if !validEnvironmentName(name) {
			return false
		}
		total += len(name) + len(value)
	}
	names := make(map[string]struct{}, len(result.Files))
	for _, file := range result.Files {
		if !validEnvironmentName(file.Name) || file.Mode != "0600" || strings.Contains(file.Name, "..") {
			return false
		}
		if _, exists := names[file.Name]; exists {
			return false
		}
		names[file.Name] = struct{}{}
		total += len(file.Name) + len(file.Content)
	}
	return total <= limit
}

func validEnvironmentName(name string) bool {
	if name == "" || len(name) > 128 || name[0] < 'A' || name[0] > 'Z' {
		return false
	}
	for _, character := range name {
		if !((character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_') {
			return false
		}
	}
	return true
}
