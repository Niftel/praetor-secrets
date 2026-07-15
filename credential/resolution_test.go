package credential

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testInjector struct {
	invalid bool
	err     error
}

func (injector testInjector) Render(credentialType string, schemaVersion uint32, inputs map[string]string) (InjectorResult, error) {
	if injector.err != nil {
		return InjectorResult{}, injector.err
	}
	if credentialType != "machine" || schemaVersion != 1 {
		return InjectorResult{}, ErrResolution
	}
	if injector.invalid {
		return InjectorResult{Files: []ResolvedFile{{Name: "../../escape", Mode: "0644", Content: inputs["password"]}}}, nil
	}
	return InjectorResult{
		Environment: map[string]string{"ANSIBLE_REMOTE_USER": inputs["username"]},
		Files:       []ResolvedFile{{Name: "ANSIBLE_PASSWORD_FILE", Mode: "0600", Content: inputs["password"]}},
	}, nil
}

func resolutionManager(t *testing.T) (*Manager, *time.Time) {
	t.Helper()
	manager := newTestManager(t)
	manager.injector = testInjector{}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	return manager, &now
}

func testBinding(now time.Time, credentialID string) RegisterBindingRequest {
	return RegisterBindingRequest{
		RunID:          "32b9fc25-fd71-47e6-b0e8-45db87df9f65",
		DispatchID:     "ae8d16d8-e58d-4ec3-953a-4ddd10c65962",
		OrganizationID: "org-5", CredentialID: credentialID,
		ExecutorIdentity: "praetor-executor:worker-7",
		NotBefore:        now, ExpiresAt: now.Add(time.Hour), MaxResolutions: 2,
		IdempotencyKey: "binding-request-1",
	}
}

func schedulerIdentity() WorkloadIdentity {
	return WorkloadIdentity{Role: RoleScheduler, Subject: string(RoleScheduler)}
}

func executorIdentity(name string) WorkloadIdentity {
	return WorkloadIdentity{Role: RoleExecutor, Subject: "praetor-executor:" + name}
}

func TestRunScopedResolutionSnapshotsCredentialVersion(t *testing.T) {
	manager, now := resolutionManager(t)
	created, err := manager.Create(validCreate())
	if err != nil {
		t.Fatal(err)
	}
	binding, err := manager.RegisterBinding(context.Background(), schedulerIdentity(), testBinding(*now, created.ID))
	if err != nil {
		t.Fatal(err)
	}
	if binding.CredentialVersion != 1 || binding.ResolutionCount != 0 || binding.State != BindingActive {
		t.Fatalf("unexpected binding: %+v", binding)
	}
	if _, err := manager.ReplaceInputs(ReplaceInputsRequest{
		CredentialID: created.ID, OrganizationID: "org-5", ExpectedVersion: 1,
		Inputs: map[string]string{"username": "new-user", "password": "new-password"},
	}); err != nil {
		t.Fatal(err)
	}

	request := ResolveRequest{
		RunID: binding.RunID, AttemptID: "31024db7-0db8-446a-b049-dd9d172cde94", RequestedAt: *now,
	}
	resolved, err := manager.Resolve(context.Background(), executorIdentity("worker-7"), request)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Environment["ANSIBLE_REMOTE_USER"] != "automation" ||
		len(resolved.Files) != 1 || resolved.Files[0].Content != "very-secret-value" {
		t.Fatalf("resolution did not use snapshotted version: %+v", resolved)
	}
	if resolved.ExpiresAt != now.Add(5*time.Minute) {
		t.Fatalf("unexpected attempt expiry: %v", resolved.ExpiresAt)
	}

	retry, err := manager.Resolve(context.Background(), executorIdentity("worker-7"), request)
	if err != nil || retry.Files[0].Content != resolved.Files[0].Content {
		t.Fatalf("idempotent retry: %+v %v", retry, err)
	}
	inspected, _ := manager.InspectBinding(context.Background(), schedulerIdentity(), binding.RunID)
	if inspected.ResolutionCount != 1 {
		t.Fatalf("retry consumed resolution: %+v", inspected)
	}
}

func TestResolutionRejectsWrongExecutorReplayAndExhaustion(t *testing.T) {
	manager, now := resolutionManager(t)
	created, _ := manager.Create(validCreate())
	binding, _ := manager.RegisterBinding(context.Background(), schedulerIdentity(), testBinding(*now, created.ID))
	first := ResolveRequest{RunID: binding.RunID, AttemptID: "31024db7-0db8-446a-b049-dd9d172cde94", RequestedAt: *now}
	if _, err := manager.Resolve(context.Background(), executorIdentity("other"), first); !errors.Is(err, ErrBindingNotActive) {
		t.Fatalf("wrong executor: %v", err)
	}
	if _, err := manager.Resolve(context.Background(), executorIdentity("worker-7"), first); err != nil {
		t.Fatal(err)
	}
	conflict := first
	conflict.RequestedAt = now.Add(time.Second)
	if _, err := manager.Resolve(context.Background(), executorIdentity("worker-7"), conflict); !errors.Is(err, ErrAttemptConflict) {
		t.Fatalf("attempt conflict: %v", err)
	}
	second := ResolveRequest{RunID: binding.RunID, AttemptID: "41024db7-0db8-446a-b049-dd9d172cde95", RequestedAt: *now}
	if _, err := manager.Resolve(context.Background(), executorIdentity("worker-7"), second); err != nil {
		t.Fatal(err)
	}
	third := ResolveRequest{RunID: binding.RunID, AttemptID: "51024db7-0db8-446a-b049-dd9d172cde96", RequestedAt: *now}
	if _, err := manager.Resolve(context.Background(), executorIdentity("worker-7"), third); !errors.Is(err, ErrBindingNotActive) {
		t.Fatalf("exhaustion: %v", err)
	}
	if _, err := manager.Resolve(context.Background(), executorIdentity("worker-7"), second); err != nil {
		t.Fatalf("retry after exhaustion failed: %v", err)
	}
}

func TestCancellationAndExpiryPreventResolution(t *testing.T) {
	manager, now := resolutionManager(t)
	created, _ := manager.Create(validCreate())
	bindingRequest := testBinding(*now, created.ID)
	binding, _ := manager.RegisterBinding(context.Background(), schedulerIdentity(), bindingRequest)
	if _, err := manager.CancelBinding(context.Background(), schedulerIdentity(), CancelBindingRequest{
		RunID: binding.RunID, DispatchID: "ffffffff-ffff-4fff-8fff-ffffffffffff", Reason: "stale_dispatch",
	}); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("stale dispatch canceled binding: %v", err)
	}
	canceled, err := manager.CancelBinding(context.Background(), schedulerIdentity(), CancelBindingRequest{RunID: binding.RunID, DispatchID: binding.DispatchID, Reason: "run_canceled"})
	if err != nil || canceled.State != BindingCanceled {
		t.Fatalf("cancel: %+v %v", canceled, err)
	}
	request := ResolveRequest{RunID: binding.RunID, AttemptID: "31024db7-0db8-446a-b049-dd9d172cde94", RequestedAt: *now}
	if _, err := manager.Resolve(context.Background(), executorIdentity("worker-7"), request); !errors.Is(err, ErrBindingNotActive) {
		t.Fatalf("canceled resolve: %v", err)
	}

	second := testBinding(*now, created.ID)
	second.RunID = "62b9fc25-fd71-47e6-b0e8-45db87df9f66"
	second.DispatchID = "be8d16d8-e58d-4ec3-953a-4ddd10c65963"
	second.IdempotencyKey = "binding-request-2"
	expiring, err := manager.RegisterBinding(context.Background(), schedulerIdentity(), second)
	if err != nil {
		t.Fatal(err)
	}
	*now = second.ExpiresAt
	request.RunID = expiring.RunID
	request.AttemptID = "71024db7-0db8-446a-b049-dd9d172cde97"
	if _, err := manager.Resolve(context.Background(), executorIdentity("worker-7"), request); !errors.Is(err, ErrBindingNotActive) {
		t.Fatalf("expired resolve: %v", err)
	}
}

func TestBindingRegistrationAuthorizationAndConflicts(t *testing.T) {
	manager, now := resolutionManager(t)
	created, _ := manager.Create(validCreate())
	request := testBinding(*now, created.ID)
	if _, err := manager.RegisterBinding(context.Background(), executorIdentity("worker-7"), request); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("executor registered binding: %v", err)
	}
	first, err := manager.RegisterBinding(context.Background(), schedulerIdentity(), request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := manager.RegisterBinding(context.Background(), schedulerIdentity(), request)
	if err != nil || replay.RunID != first.RunID {
		t.Fatalf("idempotent registration: %+v %v", replay, err)
	}
	request.ExecutorIdentity = "praetor-executor:other"
	if _, err := manager.RegisterBinding(context.Background(), schedulerIdentity(), request); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("conflicting registration: %v", err)
	}
}

func TestInjectorFailureConsumesNoResolution(t *testing.T) {
	manager, now := resolutionManager(t)
	created, _ := manager.Create(validCreate())
	binding, _ := manager.RegisterBinding(context.Background(), schedulerIdentity(), testBinding(*now, created.ID))
	manager.injector = testInjector{invalid: true}
	request := ResolveRequest{RunID: binding.RunID, AttemptID: "31024db7-0db8-446a-b049-dd9d172cde94", RequestedAt: *now}
	if _, err := manager.Resolve(context.Background(), executorIdentity("worker-7"), request); !errors.Is(err, ErrResolution) {
		t.Fatalf("invalid injector: %v", err)
	}
	inspected, _ := manager.InspectBinding(context.Background(), schedulerIdentity(), binding.RunID)
	if inspected.ResolutionCount != 0 {
		t.Fatal("failed injector consumed a resolution")
	}
}

func TestResolutionInputValidation(t *testing.T) {
	manager, now := resolutionManager(t)
	created, _ := manager.Create(validCreate())
	request := testBinding(*now, created.ID)
	request.ExecutorIdentity = "invalid"
	if _, err := manager.RegisterBinding(context.Background(), schedulerIdentity(), request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid executor accepted: %v", err)
	}
	if _, err := manager.InspectBinding(context.Background(), executorIdentity("worker"), request.RunID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("executor inspected binding: %v", err)
	}
	if err := manager.SetResolutionPolicy(ResolutionPolicy{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid policy: %v", err)
	}
	policy := DefaultResolutionPolicy()
	policy.MaxResolutions = 4
	if err := manager.SetResolutionPolicy(policy); err != nil || manager.resolutionPolicy().MaxResolutions != 4 {
		t.Fatalf("valid policy: %v", err)
	}
	if _, err := manager.CancelBinding(context.Background(), schedulerIdentity(), CancelBindingRequest{RunID: request.RunID, DispatchID: request.DispatchID, Reason: "UPPERCASE"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid cancellation reason: %v", err)
	}
	if _, err := manager.CancelBinding(context.Background(), schedulerIdentity(), CancelBindingRequest{RunID: request.RunID, DispatchID: request.DispatchID, Reason: "not_found"}); !errors.Is(err, ErrBindingNotFound) {
		t.Fatalf("missing cancellation: %v", err)
	}
	if _, err := manager.InspectBinding(context.Background(), schedulerIdentity(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"); !errors.Is(err, ErrBindingNotFound) {
		t.Fatalf("missing inspection: %v", err)
	}
}

func TestPendingAndMissingBindingsCannotResolve(t *testing.T) {
	manager, now := resolutionManager(t)
	created, _ := manager.Create(validCreate())
	registration := testBinding(*now, created.ID)
	registration.NotBefore = now.Add(10 * time.Minute)
	registration.ExpiresAt = registration.NotBefore.Add(time.Hour)
	binding, err := manager.RegisterBinding(context.Background(), schedulerIdentity(), registration)
	if err != nil || binding.State != BindingPending {
		t.Fatalf("pending registration: %+v %v", binding, err)
	}
	request := ResolveRequest{RunID: binding.RunID, AttemptID: "31024db7-0db8-446a-b049-dd9d172cde94", RequestedAt: *now}
	if _, err := manager.Resolve(context.Background(), executorIdentity("worker-7"), request); !errors.Is(err, ErrBindingNotActive) {
		t.Fatalf("pending resolve: %v", err)
	}
	request.RunID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if _, err := manager.Resolve(context.Background(), executorIdentity("worker-7"), request); !errors.Is(err, ErrBindingNotActive) {
		t.Fatalf("missing resolve: %v", err)
	}
	if _, err := NewManager(manager.keys, testSchemas{}, testInjector{}, testInjector{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("multiple injectors accepted: %v", err)
	}
}

func TestInjectorResultValidation(t *testing.T) {
	if validInjectorResult(InjectorResult{Files: []ResolvedFile{
		{Name: "DUPLICATE", Mode: "0600", Content: "a"},
		{Name: "DUPLICATE", Mode: "0600", Content: "b"},
	}}, 100) {
		t.Fatal("duplicate logical files accepted")
	}
	if validInjectorResult(InjectorResult{Environment: map[string]string{"lowercase": "value"}}, 100) {
		t.Fatal("invalid environment name accepted")
	}
	if validInjectorResult(InjectorResult{Environment: map[string]string{"VALID": "too-large"}}, 2) {
		t.Fatal("oversized injector result accepted")
	}
}
