package credential

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryAndPostgresBackendsMatchRunAuthorizationSemantics(t *testing.T) {
	pool := postgresTestPool(t)
	if err := ApplyPostgresMigrations(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	memory := newTestManager(t)
	memory.injector = testInjector{}
	postgres := postgresTestManager(t, pool)
	postgres.injector = testInjector{}

	for name, manager := range map[string]*Manager{"memory": memory, "postgres": postgres} {
		t.Run(name, func(t *testing.T) {
			created, err := manager.Create(validCreate())
			if err != nil {
				t.Fatal(err)
			}
			now := manager.now()
			request := testBinding(now, created.ID)
			binding, err := manager.RegisterBinding(context.Background(), schedulerIdentity(), request)
			if err != nil || binding.CredentialVersion != created.Version {
				t.Fatalf("binding=%+v err=%v", binding, err)
			}
			resolve := ResolveRequest{
				RunID: request.RunID, AttemptID: "31024db7-0db8-446a-b049-dd9d172cde94",
				RequestedAt: now.Add(time.Second),
			}
			if _, err := manager.Resolve(context.Background(), WorkloadIdentity{
				Role: RoleExecutor, Subject: "praetor-executor:other",
			}, resolve); !errors.Is(err, ErrBindingNotActive) {
				t.Fatalf("wrong executor result=%v", err)
			}
			result, err := manager.Resolve(context.Background(), executorIdentity("worker-7"), resolve)
			if err != nil || result.RunID != request.RunID || len(result.Files) == 0 {
				t.Fatalf("authorized resolution=%+v err=%v", result, err)
			}
			if _, err := manager.CancelBinding(context.Background(), schedulerIdentity(), CancelBindingRequest{
				RunID: request.RunID, DispatchID: request.DispatchID, Reason: "run_canceled",
			}); err != nil {
				t.Fatal(err)
			}
			resolve.AttemptID = "41024db7-0db8-446a-b049-dd9d172cde94"
			if _, err := manager.Resolve(context.Background(), executorIdentity("worker-7"), resolve); !errors.Is(err, ErrBindingNotActive) {
				t.Fatalf("canceled binding result=%v", err)
			}
		})
	}
}
