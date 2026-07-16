package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Niftel/praetor-secrets/audit"
	"github.com/Niftel/praetor-secrets/credential"
)

type fakeAuditor struct {
	events []audit.Event
	status audit.SecurityStatus
	err    error
}

func (auditor *fakeAuditor) Record(_ context.Context, event audit.Event) error {
	auditor.events = append(auditor.events, event)
	return auditor.err
}
func (auditor *fakeAuditor) Status(context.Context) (audit.SecurityStatus, error) {
	return auditor.status, auditor.err
}

type fakeService struct {
	caller             credential.WorkloadIdentity
	registration       credential.RegisterBindingRequest
	cancel             credential.CancelBindingRequest
	resolve            credential.ResolveRequest
	err                error
	rotation           credential.Rotation
	rotationID         string
	batchSize          int
	credentialRotation credential.CredentialRotationRequest
	keyStatus          credential.KeyStatus
	recovery           credential.RecoveryValidation
	backup             credential.BackupSet
}

func (service *fakeService) KeyStatus(context.Context) (credential.KeyStatus, error) {
	return service.keyStatus, service.err
}
func (service *fakeService) ValidateRecovery(context.Context, int) (credential.RecoveryValidation, error) {
	return service.recovery, service.err
}
func (service *fakeService) RegisterBackup(_ context.Context, b credential.BackupSet) (credential.BackupSet, error) {
	service.backup = b
	return b, service.err
}
func (service *fakeService) ExpireBackup(_ context.Context, id string) (credential.BackupSet, error) {
	service.backup = credential.BackupSet{ID: id}
	return credential.BackupSet{ID: id}, service.err
}

func (service *fakeService) StartMasterKeyRotation(context.Context) (credential.Rotation, error) {
	return service.rotation, service.err
}
func (service *fakeService) GetMasterKeyRotation(_ context.Context, id string) (credential.Rotation, error) {
	service.rotationID = id
	return service.rotation, service.err
}
func (service *fakeService) ResumeMasterKeyRotation(_ context.Context, id string, batchSize int) (credential.Rotation, error) {
	service.rotationID, service.batchSize = id, batchSize
	return service.rotation, service.err
}
func (service *fakeService) FinalizeMasterKeyRotation(_ context.Context, id string) (credential.Rotation, error) {
	service.rotationID = id
	return service.rotation, service.err
}
func (service *fakeService) RotateCredentialKey(_ context.Context, request credential.CredentialRotationRequest) error {
	service.credentialRotation = request
	return service.err
}

func (service *fakeService) CreateContext(_ context.Context, request credential.CreateRequest) (credential.Metadata, error) {
	return credential.Metadata{ID: "98d977e4-3f0a-44cd-81cb-8965d5522996", OrganizationID: request.OrganizationID, Name: request.Name, CredentialType: request.CredentialType, Version: 1}, service.err
}
func (service *fakeService) GetContext(_ context.Context, organizationID, credentialID string) (credential.Metadata, error) {
	return credential.Metadata{ID: credentialID, OrganizationID: organizationID}, service.err
}
func (service *fakeService) ReplaceInputsContext(_ context.Context, request credential.ReplaceInputsRequest) (credential.Metadata, error) {
	return credential.Metadata{ID: request.CredentialID, OrganizationID: request.OrganizationID, Version: request.ExpectedVersion + 1}, service.err
}
func (service *fakeService) UpdateMetadataContext(_ context.Context, request credential.UpdateMetadataRequest) (credential.Metadata, error) {
	return credential.Metadata{ID: request.CredentialID, OrganizationID: request.OrganizationID, Name: request.Name, Version: request.ExpectedVersion + 1}, service.err
}
func (service *fakeService) RetireContext(_ context.Context, request credential.RetireRequest) (credential.Metadata, error) {
	return credential.Metadata{ID: request.CredentialID, OrganizationID: request.OrganizationID, Version: request.ExpectedVersion + 1, State: credential.StateRetired}, service.err
}

func (service *fakeService) RegisterBinding(_ context.Context, caller credential.WorkloadIdentity, request credential.RegisterBindingRequest) (credential.Binding, error) {
	service.caller, service.registration = caller, request
	return credential.Binding{RunID: request.RunID}, service.err
}

func (service *fakeService) InspectBinding(_ context.Context, caller credential.WorkloadIdentity, runID string) (credential.Binding, error) {
	service.caller = caller
	return credential.Binding{RunID: runID}, service.err
}

func (service *fakeService) CancelBinding(_ context.Context, caller credential.WorkloadIdentity, request credential.CancelBindingRequest) (credential.Binding, error) {
	service.caller, service.cancel = caller, request
	return credential.Binding{RunID: request.RunID, DispatchID: request.DispatchID}, service.err
}

func (service *fakeService) Resolve(_ context.Context, caller credential.WorkloadIdentity, request credential.ResolveRequest) (credential.ResolvedCredential, error) {
	service.caller, service.resolve = caller, request
	return credential.ResolvedCredential{
		RunID: request.RunID, AttemptID: request.AttemptID,
		Environment: map[string]string{"SECRET_VALUE": "must-not-appear-in-errors"},
	}, service.err
}

func verifiedRequest(t *testing.T, method, path, body, identityURI string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	certificate := certificateWithURI(t, identityURI)
	request.TLS = &tls.ConnectionState{
		Version: tls.VersionTLS13, HandshakeComplete: true,
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
	return request
}

func newTestServer(t *testing.T, service *fakeService) *Server {
	t.Helper()
	server, err := NewServer(service, SPIFFEMapper{TrustDomain: "praetor.local"})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestSchedulerRegistrationUsesCertificateIdentity(t *testing.T) {
	service := &fakeService{}
	server := newTestServer(t, service)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	body := `{
      "run_id":"32b9fc25-fd71-47e6-b0e8-45db87df9f65",
      "dispatch_id":"ae8d16d8-e58d-4ec3-953a-4ddd10c65962",
      "organization_id":"org-5",
      "credential_id":"98d977e4-3f0a-44cd-81cb-8965d5522996",
      "executor_identity":"praetor-executor:worker-7",
      "not_before":"` + now.Format(time.RFC3339) + `",
      "expires_at":"` + now.Add(time.Hour).Format(time.RFC3339) + `",
      "max_resolutions":2
    }`
	request := verifiedRequest(t, http.MethodPost, "/internal/v1/run-bindings", body, "spiffe://praetor.local/workload/praetor-scheduler")
	request.Header.Set("Idempotency-Key", "binding-1")
	request.Header.Set("X-Workload-Identity", "praetor-executor:forged")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || service.caller.Role != credential.RoleScheduler || service.registration.IdempotencyKey != "binding-1" {
		t.Fatalf("status=%d caller=%+v registration=%+v body=%s", recorder.Code, service.caller, service.registration, recorder.Body.String())
	}
	if recorder.Header().Get("Location") == "" || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing safe headers: %v", recorder.Header())
	}
}

func TestExecutorResolutionAndRouteSeparation(t *testing.T) {
	service := &fakeService{}
	server := newTestServer(t, service)
	body := `{"attempt_id":"31024db7-0db8-446a-b049-dd9d172cde94","requested_at":"2026-07-15T12:00:00Z"}`
	path := "/internal/v1/runs/32b9fc25-fd71-47e6-b0e8-45db87df9f65/credential:resolve"
	request := verifiedRequest(t, http.MethodPost, path, body, "spiffe://praetor.local/workload/praetor-executor/worker-7")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || service.caller.Subject != "praetor-executor:worker-7" ||
		recorder.Header().Get("Connection") != "close" || recorder.Header().Get("Content-Encoding") != "identity" ||
		recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("status=%d caller=%+v headers=%v body=%s", recorder.Code, service.caller, recorder.Header(), recorder.Body.String())
	}
	scheduler := verifiedRequest(t, http.MethodPost, path, body, "spiffe://praetor.local/workload/praetor-scheduler")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, scheduler)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("scheduler resolved credential: %d", recorder.Code)
	}
}

func TestUnauthenticatedAndUnverifiedRequestsFail(t *testing.T) {
	server := newTestServer(t, &fakeService{})
	request := httptest.NewRequest(http.MethodGet, "/internal/v1/run-bindings/32b9fc25-fd71-47e6-b0e8-45db87df9f65", nil)
	request.Header.Set("X-Workload-Identity", "praetor-scheduler")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("header identity authenticated: %d", recorder.Code)
	}
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificateWithURI(t, "spiffe://praetor.local/workload/praetor-scheduler")}}
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unverified certificate authenticated: %d", recorder.Code)
	}
}

func TestCancellationIncludesDispatchID(t *testing.T) {
	service := &fakeService{}
	server := newTestServer(t, service)
	path := "/internal/v1/run-bindings/32b9fc25-fd71-47e6-b0e8-45db87df9f65/cancel"
	body := `{"dispatch_id":"ae8d16d8-e58d-4ec3-953a-4ddd10c65962","reason":"run_canceled"}`
	request := verifiedRequest(t, http.MethodPost, path, body, "spiffe://praetor.local/workload/praetor-scheduler")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || service.cancel.DispatchID != "ae8d16d8-e58d-4ec3-953a-4ddd10c65962" {
		t.Fatalf("status=%d cancel=%+v", recorder.Code, service.cancel)
	}
}

func TestStrictRequestAndSecretSafeErrors(t *testing.T) {
	service := &fakeService{err: credential.ErrResolution}
	server := newTestServer(t, service)
	path := "/internal/v1/runs/32b9fc25-fd71-47e6-b0e8-45db87df9f65/credential:resolve"
	body := `{"attempt_id":"31024db7-0db8-446a-b049-dd9d172cde94","attempt_id":"duplicate","requested_at":"2026-07-15T12:00:00Z"}`
	request := verifiedRequest(t, http.MethodPost, path, body, "spiffe://praetor.local/workload/praetor-executor/worker-7")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("duplicate JSON accepted: %d", recorder.Code)
	}
	body = `{"attempt_id":"31024db7-0db8-446a-b049-dd9d172cde94","requested_at":"2026-07-15T12:00:00Z"}`
	request = verifiedRequest(t, http.MethodPost, path, body, "spiffe://praetor.local/workload/praetor-executor/worker-7")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError || strings.Contains(recorder.Body.String(), "must-not-appear") {
		t.Fatalf("unsafe error status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &problem); err != nil || problem.Code != "secure_operation_failed" {
		t.Fatalf("problem=%+v err=%v", problem, err)
	}
}

func TestSecretSentinelNeverCrossesHTTPOrAuditBoundary(t *testing.T) {
	const sentinel = "SECRET-SENTINEL-DO-NOT-EMIT"
	auditor := &fakeAuditor{}
	server, err := NewServer(
		&fakeService{err: errors.New(sentinel)},
		SPIFFEMapper{TrustDomain: "praetor.local"},
		auditor,
	)
	if err != nil {
		t.Fatal(err)
	}
	path := "/internal/v1/runs/32b9fc25-fd71-47e6-b0e8-45db87df9f65/credential:resolve"
	body := `{"attempt_id":"31024db7-0db8-446a-b049-dd9d172cde94","requested_at":"2026-07-15T12:00:00Z"}`
	request := verifiedRequest(t, http.MethodPost, path, body, "spiffe://praetor.local/workload/praetor-executor/worker-7")
	recorder := httptest.NewRecorder()

	server.ServeHTTP(recorder, request)

	events, marshalErr := json.Marshal(auditor.events)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(recorder.Body.String(), sentinel) || strings.Contains(string(events), sentinel) {
		t.Fatalf("secret crossed boundary: response=%s audit=%s", recorder.Body.String(), events)
	}
	if recorder.Code != http.StatusInternalServerError || len(auditor.events) != 1 {
		t.Fatalf("status=%d events=%s", recorder.Code, events)
	}
}

func TestServiceErrorMapping(t *testing.T) {
	tests := []struct {
		err    error
		status int
	}{
		{credential.ErrInvalidInput, 400},
		{credential.ErrUnauthorized, 403},
		{credential.ErrBindingNotActive, 403},
		{credential.ErrBindingNotFound, 404},
		{credential.ErrBindingConflict, 409},
		{credential.ErrAttemptConflict, 409},
		{credential.ErrRotationConflict, 409},
		{credential.ErrRotationNotReady, 409},
		{credential.ErrRotationUnavailable, 503},
		{credential.ErrStorage, 503},
		{errors.New("internal detail"), 500},
	}
	for _, test := range tests {
		recorder := httptest.NewRecorder()
		writeServiceProblem(recorder, test.err)
		if recorder.Code != test.status || strings.Contains(recorder.Body.String(), test.err.Error()) {
			t.Fatalf("err=%v status=%d body=%s", test.err, recorder.Code, recorder.Body.String())
		}
	}
}

func TestInspectAndUnknownRoutes(t *testing.T) {
	service := &fakeService{}
	server := newTestServer(t, service)
	path := "/internal/v1/run-bindings/32b9fc25-fd71-47e6-b0e8-45db87df9f65"
	request := verifiedRequest(t, http.MethodGet, path, "", "spiffe://praetor.local/workload/praetor-scheduler")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || service.caller.Role != credential.RoleScheduler {
		t.Fatalf("inspect status=%d caller=%+v", recorder.Code, service.caller)
	}
	request = verifiedRequest(t, http.MethodGet, path, "", "spiffe://praetor.local/workload/praetor-executor/worker-7")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("executor inspected binding: %d", recorder.Code)
	}
	request = verifiedRequest(t, http.MethodGet, "/internal/v1/unknown", "", "spiffe://praetor.local/workload/praetor-scheduler")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown route: %d", recorder.Code)
	}
}

func TestProtectedRequestCompletionAndSecurityStatus(t *testing.T) {
	auditor := &fakeAuditor{status: audit.SecurityStatus{AuditIntegrityHealthy: true, PendingAuditEvents: 2, MaximumPendingAuditEvents: 100}}
	server, err := NewServer(&fakeService{}, SPIFFEMapper{TrustDomain: "praetor.local"}, auditor)
	if err != nil {
		t.Fatal(err)
	}
	request := verifiedRequest(t, http.MethodGet, "/internal/v1/run-bindings/32b9fc25-fd71-47e6-b0e8-45db87df9f65", "", "spiffe://praetor.local/workload/praetor-executor/worker-7")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || recorder.Header().Get("X-Request-ID") == "" || len(auditor.events) != 1 {
		t.Fatalf("status=%d headers=%v events=%+v", recorder.Code, recorder.Header(), auditor.events)
	}
	event := auditor.events[0]
	if event.EventType != "request_completed" || event.Operation != "run_binding_inspected" || event.Result != "denied" || event.RequestID == "" || event.WorkloadIdentity != "praetor-executor:worker-7" {
		t.Fatalf("event=%+v", event)
	}
	request = verifiedRequest(t, http.MethodGet, "/internal/v1/security-status", "", "spiffe://praetor.local/workload/praetor-secrets-auditor")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"pending_audit_events":2`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	request = verifiedRequest(t, http.MethodGet, "/internal/v1/security-status", "", "spiffe://praetor.local/workload/praetor-scheduler")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("scheduler status=%d", recorder.Code)
	}
}

func TestProblemIncludesRequestID(t *testing.T) {
	server := newTestServer(t, &fakeService{})
	request := httptest.NewRequest(http.MethodGet, "/internal/v1/unknown", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), "request_id") || recorder.Header().Get("X-Request-ID") == "" {
		t.Fatalf("headers=%v body=%s", recorder.Header(), recorder.Body.String())
	}
}

func TestRotationOperationsRequireOperatorIdentity(t *testing.T) {
	rotationID := "68d977e4-3f0a-44cd-81cb-8965d5522996"
	service := &fakeService{rotation: credential.Rotation{
		ID: rotationID, SourceKeyID: "old-key", TargetKeyID: "new-key",
		State: credential.RotationPending, TotalRecords: 2,
	}, keyStatus: credential.KeyStatus{
		CurrentKeyID: "new-key", PreviousKeyID: "old-key",
		RecordCounts: map[string]int64{"old-key": 2},
	}}
	server := newTestServer(t, service)

	request := verifiedRequest(t, http.MethodGet, "/internal/v1/operations/key-status", "", "spiffe://praetor.local/workload/praetor-secrets-operator")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"current_key_id":"new-key"`) {
		t.Fatalf("key status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	request = verifiedRequest(t, http.MethodPost, "/internal/v1/operations/rotations", "", "spiffe://praetor.local/workload/praetor-secrets-operator")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || recorder.Header().Get("Location") == "" {
		t.Fatalf("start status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}

	request = verifiedRequest(t, http.MethodPost, "/internal/v1/operations/rotations/"+rotationID+"/resume", `{"batch_size":25}`, "spiffe://praetor.local/workload/praetor-secrets-operator")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || service.rotationID != rotationID || service.batchSize != 25 {
		t.Fatalf("resume status=%d id=%q batch=%d body=%s", recorder.Code, service.rotationID, service.batchSize, recorder.Body.String())
	}

	request = verifiedRequest(t, http.MethodGet, "/internal/v1/operations/rotations/"+rotationID, "", "spiffe://praetor.local/workload/praetor-secrets-operator")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || service.rotationID != rotationID {
		t.Fatalf("inspect status=%d id=%q body=%s", recorder.Code, service.rotationID, recorder.Body.String())
	}

	request = verifiedRequest(t, http.MethodPost, "/internal/v1/operations/rotations/"+rotationID+"/finalize", "", "spiffe://praetor.local/workload/praetor-secrets-operator")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || service.rotationID != rotationID {
		t.Fatalf("finalize status=%d id=%q body=%s", recorder.Code, service.rotationID, recorder.Body.String())
	}

	path := "/internal/v1/operations/credentials/98d977e4-3f0a-44cd-81cb-8965d5522996/versions/3/rotate"
	request = verifiedRequest(t, http.MethodPost, path, `{"organization_id":"org-5"}`, "spiffe://praetor.local/workload/praetor-secrets-operator")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || service.credentialRotation.Version != 3 || service.credentialRotation.OrganizationID != "org-5" {
		t.Fatalf("credential rotation status=%d request=%+v body=%s", recorder.Code, service.credentialRotation, recorder.Body.String())
	}

	request = verifiedRequest(t, http.MethodPost, "/internal/v1/operations/rotations", "", "spiffe://praetor.local/workload/praetor-api")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("API started rotation: %d", recorder.Code)
	}
}

func TestRotationRoutesRejectMalformedRequests(t *testing.T) {
	server := newTestServer(t, &fakeService{})
	identity := "spiffe://praetor.local/workload/praetor-secrets-operator"
	tests := []struct {
		method, path, body string
		status             int
	}{
		{http.MethodPost, "/internal/v1/operations/rotations/id/resume", `{"batch_size":0}`, http.StatusBadRequest},
		{http.MethodPost, "/internal/v1/operations/rotations/id/resume", `{`, http.StatusBadRequest},
		{http.MethodGet, "/internal/v1/operations/rotations/id/extra", "", http.StatusNotFound},
		{http.MethodPost, "/internal/v1/operations/credentials/id/versions/not-a-version/rotate", `{"organization_id":"org"}`, http.StatusBadRequest},
		{http.MethodPost, "/internal/v1/operations/credentials/id/bad/1/rotate", `{"organization_id":"org"}`, http.StatusNotFound},
		{http.MethodGet, "/internal/v1/operations/unknown", "", http.StatusNotFound},
	}
	for _, test := range tests {
		request := verifiedRequest(t, test.method, test.path, test.body, identity)
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		if recorder.Code != test.status {
			t.Fatalf("%s %s status=%d want=%d body=%s", test.method, test.path, recorder.Code, test.status, recorder.Body.String())
		}
	}
}

func TestRecoveryAndBackupOperatorRoutes(t *testing.T) {
	service := &fakeService{recovery: credential.RecoveryValidation{ValidatedRecords: 2, TotalRecords: 3, MetadataSHA256: strings.Repeat("a", 64)}}
	server := newTestServer(t, service)
	identity := "spiffe://praetor.local/workload/praetor-secrets-operator"
	request := verifiedRequest(t, http.MethodPost, "/internal/v1/operations/recovery-validations", `{"sample_size":2}`, identity)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"validated_records":2`) {
		t.Fatalf("recovery=%d %s", recorder.Code, recorder.Body.String())
	}
	body := `{"id":"backup-1","artifact_sha256":"` + strings.Repeat("b", 64) + `","key_ids":["key-1"],"created_at":"2026-07-16T12:00:00Z","retain_until":"2026-07-17T12:00:00Z"}`
	request = verifiedRequest(t, http.MethodPost, "/internal/v1/operations/backups", body, identity)
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || service.backup.ID != "backup-1" {
		t.Fatalf("backup=%d %+v", recorder.Code, service.backup)
	}
	request = verifiedRequest(t, http.MethodPost, "/internal/v1/operations/backups/backup-1/expire", "", identity)
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || service.backup.ID != "backup-1" {
		t.Fatalf("expire=%d %+v", recorder.Code, service.backup)
	}
	request = verifiedRequest(t, http.MethodPost, "/internal/v1/operations/recovery-validations", `{"sample_size":2}`, "spiffe://praetor.local/workload/praetor-api")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("api recovery=%d", recorder.Code)
	}
}

func TestRecoveryAndBackupRouteFailures(t *testing.T) {
	identity := "spiffe://praetor.local/workload/praetor-secrets-operator"
	tests := []struct {
		path, body string
		err        error
		status     int
	}{
		{"/internal/v1/operations/recovery-validations", "{", nil, 400},
		{"/internal/v1/operations/recovery-validations", `{"sample_size":0}`, nil, 400},
		{"/internal/v1/operations/recovery-validations", `{"sample_size":1}`, credential.ErrRecoveryValidation, 409},
		{"/internal/v1/operations/backups", "{", nil, 400},
		{"/internal/v1/operations/backups", `{"id":"x"}`, credential.ErrBackupConflict, 409},
		{"/internal/v1/operations/backups//expire", "", nil, 404},
		{"/internal/v1/operations/backups/a/b/expire", "", nil, 404},
	}
	for _, test := range tests {
		server := newTestServer(t, &fakeService{err: test.err})
		request := verifiedRequest(t, http.MethodPost, test.path, test.body, identity)
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		if recorder.Code != test.status {
			t.Fatalf("%s status=%d want=%d body=%s", test.path, recorder.Code, test.status, recorder.Body.String())
		}
	}
}

func TestRotationRequestOperationVocabulary(t *testing.T) {
	rotationID := "68d977e4-3f0a-44cd-81cb-8965d5522996"
	tests := []struct {
		method, path, operation string
	}{
		{http.MethodPost, "/internal/v1/operations/rotations", audit.OperationMasterKeyRotationStarted},
		{http.MethodGet, "/internal/v1/operations/key-status", audit.OperationKeyStatusRead},
		{http.MethodGet, "/internal/v1/operations/rotations/" + rotationID, audit.OperationMasterKeyRotationInspected},
		{http.MethodPost, "/internal/v1/operations/rotations/" + rotationID + "/resume", audit.OperationMasterKeyRotationResumed},
		{http.MethodPost, "/internal/v1/operations/rotations/" + rotationID + "/finalize", audit.OperationMasterKeyRotationFinalized},
		{http.MethodPost, "/internal/v1/operations/credentials/cred/versions/1/rotate", audit.OperationCredentialKeyRotated},
	}
	for _, test := range tests {
		if got := requestOperation(test.method, test.path); got != test.operation {
			t.Fatalf("%s %s operation=%q want=%q", test.method, test.path, got, test.operation)
		}
	}
}

func TestCredentialAdministrationRoutesAreAPIOnlyAndRedacted(t *testing.T) {
	server := newTestServer(t, &fakeService{})
	body := `{"organization_id":"5","name":"machine","credential_type":"machine","schema_version":1,"inputs":{"username":"automation","password":"super-secret"},"actor":{"user_id":"104","username":"operator"}}`
	request := verifiedRequest(t, http.MethodPost, "/internal/v1/credentials", body, "spiffe://praetor.local/workload/praetor-api")
	request.Header.Set("Idempotency-Key", "create-1")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || strings.Contains(recorder.Body.String(), "super-secret") || recorder.Header().Get("Location") == "" {
		t.Fatalf("status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	request = verifiedRequest(t, http.MethodGet, "/internal/v1/credentials/98d977e4-3f0a-44cd-81cb-8965d5522996", "", "spiffe://praetor.local/workload/praetor-api")
	request.Header.Set("X-Praetor-Organization-ID", "5")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	request = verifiedRequest(t, http.MethodGet, "/internal/v1/credentials/98d977e4-3f0a-44cd-81cb-8965d5522996", "", "spiffe://praetor.local/workload/praetor-scheduler")
	request.Header.Set("X-Praetor-Organization-ID", "5")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("scheduler status=%d", recorder.Code)
	}
	request = verifiedRequest(t, http.MethodGet, "/internal/v1/credentials/98d977e4-3f0a-44cd-81cb-8965d5522996", "", "spiffe://praetor.local/workload/praetor-api")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("missing org status=%d", recorder.Code)
	}
}

func TestCredentialReplacementRenameAndValidation(t *testing.T) {
	server := newTestServer(t, &fakeService{})
	credentialPath := "/internal/v1/credentials/98d977e4-3f0a-44cd-81cb-8965d5522996"
	replace := `{"expected_version":1,"inputs":{"username":"new-user","password":"new-secret"},"actor":{"user_id":"104"}}`
	request := verifiedRequest(t, http.MethodPut, credentialPath+"/inputs", replace, "spiffe://praetor.local/workload/praetor-api")
	request.Header.Set("X-Praetor-Organization-ID", "5")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "new-secret") {
		t.Fatalf("replace status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	rename := `{"expected_version":2,"name":"renamed","actor":{"user_id":"104","authorization_decision_id":"decision-1"}}`
	request = verifiedRequest(t, http.MethodPatch, credentialPath, rename, "spiffe://praetor.local/workload/praetor-api")
	request.Header.Set("X-Praetor-Organization-ID", "5")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "renamed") {
		t.Fatalf("rename status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	invalid := `{"expected_version":2,"name":"renamed","actor":{"user_id":"bad\nactor"}}`
	request = verifiedRequest(t, http.MethodPatch, credentialPath, invalid, "spiffe://praetor.local/workload/praetor-api")
	request.Header.Set("X-Praetor-Organization-ID", "5")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid actor status=%d", recorder.Code)
	}
	request = verifiedRequest(t, http.MethodDelete, credentialPath, "", "spiffe://praetor.local/workload/praetor-api")
	request.Header.Set("X-Praetor-Organization-ID", "5")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unsupported method status=%d", recorder.Code)
	}
}

func TestCredentialRetirementRouteIsAPIOnly(t *testing.T) {
	server := newTestServer(t, &fakeService{})
	path := "/internal/v1/credentials/98d977e4-3f0a-44cd-81cb-8965d5522996/retire"
	body := `{"expected_version":3,"actor":{"user_id":"104","username":"operator"}}`
	request := verifiedRequest(t, http.MethodPost, path, body, "spiffe://praetor.local/workload/praetor-api")
	request.Header.Set("X-Praetor-Organization-ID", "5")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"state":"retired"`) || !strings.Contains(recorder.Body.String(), `"version":4`) {
		t.Fatalf("retire status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	request = verifiedRequest(t, http.MethodPost, path, body, "spiffe://praetor.local/workload/praetor-scheduler")
	request.Header.Set("X-Praetor-Organization-ID", "5")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("scheduler retirement status=%d", recorder.Code)
	}
}

func TestCredentialConflictMappings(t *testing.T) {
	for _, test := range []struct {
		err  error
		code string
	}{{credential.ErrIdempotencyConflict, "idempotency_conflict"}, {credential.ErrVersionConflict, "version_conflict"}} {
		recorder := httptest.NewRecorder()
		writeServiceProblem(recorder, test.err)
		if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), test.code) {
			t.Fatalf("err=%v status=%d body=%s", test.err, recorder.Code, recorder.Body.String())
		}
	}
}

func TestNewHTTPServerEnforcesSafeTimeouts(t *testing.T) {
	handler := newTestServer(t, &fakeService{})
	config := &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert}
	server, err := NewHTTPServer(":8443", handler, config)
	if err != nil {
		t.Fatal(err)
	}
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 ||
		server.IdleTimeout <= 0 || server.MaxHeaderBytes > 16<<10 {
		t.Fatalf("unsafe HTTP server: %+v", server)
	}
	if _, err := NewHTTPServer("", handler, config); !errors.Is(err, credential.ErrInvalidInput) {
		t.Fatalf("empty address: %v", err)
	}
	if _, err := NewHTTPServer(":8443", handler, &tls.Config{MinVersion: tls.VersionTLS12}); !errors.Is(err, credential.ErrInvalidInput) {
		t.Fatalf("unsafe TLS accepted: %v", err)
	}
	if _, err := NewServer(nil, SPIFFEMapper{TrustDomain: "praetor.local"}); !errors.Is(err, credential.ErrInvalidInput) {
		t.Fatalf("nil service: %v", err)
	}
}

func TestOversizedRequestIsRejected(t *testing.T) {
	service := &fakeService{}
	server := newTestServer(t, service)
	path := "/internal/v1/runs/32b9fc25-fd71-47e6-b0e8-45db87df9f65/credential:resolve"
	body := `{"attempt_id":"` + strings.Repeat("a", maxRequestBody) + `"}`
	request := verifiedRequest(t, http.MethodPost, path, body, "spiffe://praetor.local/workload/praetor-executor/worker-7")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
