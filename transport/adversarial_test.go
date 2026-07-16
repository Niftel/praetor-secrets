package transport

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEveryWorkloadRoleIsDeniedRepresentativeUnauthorizedRoute(t *testing.T) {
	server := newTestServer(t, &fakeService{})
	tests := []struct {
		name, identity, method, path, body string
	}{
		{"api resolution", "spiffe://praetor.local/workload/praetor-api", http.MethodPost, "/internal/v1/runs/32b9fc25-fd71-47e6-b0e8-45db87df9f65/credential:resolve", `{"attempt_id":"31024db7-0db8-446a-b049-dd9d172cde94","requested_at":"2026-07-15T12:00:00Z"}`},
		{"scheduler credential admin", "spiffe://praetor.local/workload/praetor-scheduler", http.MethodPost, "/internal/v1/credentials", `{}`},
		{"executor operations", "spiffe://praetor.local/workload/praetor-executor/worker-7", http.MethodGet, "/internal/v1/operations/key-status", ""},
		{"operator credential admin", "spiffe://praetor.local/workload/praetor-secrets-operator", http.MethodPost, "/internal/v1/credentials", `{}`},
		{"auditor mutation", "spiffe://praetor.local/workload/praetor-secrets-auditor", http.MethodPost, "/internal/v1/operations/rotations", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := verifiedRequest(t, test.method, test.path, test.body, test.identity)
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestExecutorCannotSelectCredentialInResolutionBody(t *testing.T) {
	server := newTestServer(t, &fakeService{})
	body := `{"attempt_id":"31024db7-0db8-446a-b049-dd9d172cde94","requested_at":"2026-07-15T12:00:00Z","credential_id":"98d977e4-3f0a-44cd-81cb-8965d5522996"}`
	request := verifiedRequest(t, http.MethodPost, "/internal/v1/runs/32b9fc25-fd71-47e6-b0e8-45db87df9f65/credential:resolve", body, "spiffe://praetor.local/workload/praetor-executor/worker-7")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("credential selector accepted: %d %s", recorder.Code, recorder.Body.String())
	}
}
