package transport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Niftel/praetor-secrets/audit"
	"github.com/Niftel/praetor-secrets/credential"
)

type CredentialService interface {
	CreateContext(context.Context, credential.CreateRequest) (credential.Metadata, error)
	GetContext(context.Context, string, string) (credential.Metadata, error)
	ReplaceInputsContext(context.Context, credential.ReplaceInputsRequest) (credential.Metadata, error)
	UpdateMetadataContext(context.Context, credential.UpdateMetadataRequest) (credential.Metadata, error)
	RetireContext(context.Context, credential.RetireRequest) (credential.Metadata, error)
	RegisterBinding(context.Context, credential.WorkloadIdentity, credential.RegisterBindingRequest) (credential.Binding, error)
	InspectBinding(context.Context, credential.WorkloadIdentity, string) (credential.Binding, error)
	CancelBinding(context.Context, credential.WorkloadIdentity, credential.CancelBindingRequest) (credential.Binding, error)
	Resolve(context.Context, credential.WorkloadIdentity, credential.ResolveRequest) (credential.ResolvedCredential, error)
	StartMasterKeyRotation(context.Context) (credential.Rotation, error)
	GetMasterKeyRotation(context.Context, string) (credential.Rotation, error)
	ResumeMasterKeyRotation(context.Context, string, int) (credential.Rotation, error)
	FinalizeMasterKeyRotation(context.Context, string) (credential.Rotation, error)
	RotateCredentialKey(context.Context, credential.CredentialRotationRequest) error
	KeyStatus(context.Context) (credential.KeyStatus, error)
	ValidateRecovery(context.Context, int) (credential.RecoveryValidation, error)
	RegisterBackup(context.Context, credential.BackupSet) (credential.BackupSet, error)
	ExpireBackup(context.Context, string) (credential.BackupSet, error)
}

type Server struct {
	service CredentialService
	mapper  SPIFFEMapper
	auditor AuditRecorder
}

type AuditRecorder interface {
	Record(context.Context, audit.Event) error
	Status(context.Context) (audit.SecurityStatus, error)
}

func NewServer(service CredentialService, mapper SPIFFEMapper, auditors ...AuditRecorder) (*Server, error) {
	if service == nil || mapper.TrustDomain == "" || len(auditors) > 1 {
		return nil, credential.ErrInvalidInput
	}
	server := &Server{service: service, mapper: mapper}
	if len(auditors) == 1 {
		server.auditor = auditors[0]
	}
	return server, nil
}

func NewHTTPServer(address string, handler *Server, tlsConfig *tls.Config) (*http.Server, error) {
	if address == "" || handler == nil || tlsConfig == nil || tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || tlsConfig.MinVersion < tls.VersionTLS13 {
		return nil, credential.ErrInvalidInput
	}
	return &http.Server{
		Addr: address, Handler: handler, TLSConfig: tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}, nil
}

func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	observed := &observedWriter{ResponseWriter: writer, status: http.StatusOK, requestID: newRequestID()}
	writer = observed
	secureHeaders(writer)
	writer.Header().Set("X-Request-ID", observed.requestID)
	operation := requestOperation(request.Method, request.URL.EscapedPath())
	started := time.Now().UTC()
	identity, err := server.requestIdentity(request)
	workload := ""
	if err == nil {
		workload = identity.Subject
	}
	request = request.WithContext(audit.WithRequest(request.Context(), audit.Request{ID: observed.requestID, WorkloadIdentity: workload, Operation: operation, StartedAt: started}))
	defer func() {
		if server.auditor != nil {
			if observed.status >= 200 && observed.status < 300 && transactionallyAudited(operation) {
				return
			}
			result, reason := audit.StableResult(observed.status)
			if observed.reason != "" {
				reason = observed.reason
			}
			event := audit.Completion(request.Context(), result, reason, time.Now().UTC())
			event.RunID = requestRunID(request.URL.EscapedPath())
			event.RotationID = requestRotationID(request.URL.EscapedPath())
			_ = server.auditor.Record(request.Context(), event)
		}
	}()
	if err != nil {
		writeProblem(writer, http.StatusUnauthorized, "workload_authentication_failed")
		return
	}
	path := request.URL.EscapedPath()
	switch {
	case request.Method == http.MethodGet && path == "/internal/v1/security-status":
		server.securityStatus(writer, request, identity)
	case strings.HasPrefix(path, "/internal/v1/operations/"):
		server.operationRoute(writer, request, identity, path)
	case request.Method == http.MethodPost && path == "/internal/v1/credentials":
		server.createCredential(writer, request, identity)
	case strings.HasPrefix(path, "/internal/v1/credentials/"):
		server.credentialRoute(writer, request, identity, path)
	case request.Method == http.MethodPost && path == "/internal/v1/run-bindings":
		server.registerBinding(writer, request, identity)
	case request.Method == http.MethodGet && strings.HasPrefix(path, "/internal/v1/run-bindings/"):
		runID := strings.TrimPrefix(path, "/internal/v1/run-bindings/")
		if strings.Contains(runID, "/") || runID == "" {
			writeProblem(writer, http.StatusNotFound, "resource_not_found")
			return
		}
		server.inspectBinding(writer, request, identity, runID)
	case request.Method == http.MethodPost && strings.HasPrefix(path, "/internal/v1/run-bindings/") && strings.HasSuffix(path, "/cancel"):
		runID := strings.TrimSuffix(strings.TrimPrefix(path, "/internal/v1/run-bindings/"), "/cancel")
		if strings.Contains(runID, "/") || runID == "" {
			writeProblem(writer, http.StatusNotFound, "resource_not_found")
			return
		}
		server.cancelBinding(writer, request, identity, runID)
	case request.Method == http.MethodPost && strings.HasPrefix(path, "/internal/v1/runs/") && strings.HasSuffix(path, "/credential:resolve"):
		runID := strings.TrimSuffix(strings.TrimPrefix(path, "/internal/v1/runs/"), "/credential:resolve")
		if strings.Contains(runID, "/") || runID == "" {
			writeProblem(writer, http.StatusNotFound, "resource_not_found")
			return
		}
		server.resolve(writer, request, identity, runID)
	default:
		writeProblem(writer, http.StatusNotFound, "resource_not_found")
	}
}

type observedWriter struct {
	http.ResponseWriter
	status    int
	requestID string
	reason    string
}

func (writer *observedWriter) WriteHeader(status int) {
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}
func newRequestID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "request-unavailable"
	}
	return hex.EncodeToString(value[:])
}
func requestOperation(method, path string) string {
	switch {
	case method == http.MethodPost && path == "/internal/v1/run-bindings":
		return audit.OperationRunBindingRegistered
	case method == http.MethodGet && path == "/internal/v1/security-status":
		return audit.OperationSecurityStatusRead
	case method == http.MethodGet && path == "/internal/v1/operations/key-status":
		return audit.OperationKeyStatusRead
	case method == http.MethodPost && path == "/internal/v1/operations/recovery-validations":
		return audit.OperationRecoveryValidationFinished
	case method == http.MethodPost && path == "/internal/v1/operations/backups":
		return audit.OperationBackupRegistered
	case method == http.MethodPost && strings.HasSuffix(path, "/expire"):
		return audit.OperationBackupExpired
	case method == http.MethodPost && path == "/internal/v1/operations/rotations":
		return audit.OperationMasterKeyRotationStarted
	case method == http.MethodGet && strings.HasPrefix(path, "/internal/v1/operations/rotations/"):
		return audit.OperationMasterKeyRotationInspected
	case method == http.MethodPost && strings.HasSuffix(path, "/resume"):
		return audit.OperationMasterKeyRotationResumed
	case method == http.MethodPost && strings.HasSuffix(path, "/finalize"):
		return audit.OperationMasterKeyRotationFinalized
	case method == http.MethodPost && strings.HasPrefix(path, "/internal/v1/operations/credentials/") && strings.HasSuffix(path, "/rotate"):
		return audit.OperationCredentialKeyRotated
	case method == http.MethodPost && path == "/internal/v1/credentials":
		return audit.OperationCredentialCreated
	case method == http.MethodGet && strings.HasPrefix(path, "/internal/v1/credentials/"):
		return audit.OperationCredentialRead
	case method == http.MethodPut && strings.HasSuffix(path, "/inputs"):
		return audit.OperationCredentialInputsReplaced
	case method == http.MethodPatch && strings.HasPrefix(path, "/internal/v1/credentials/"):
		return audit.OperationCredentialMetadataUpdated
	case method == http.MethodPost && strings.HasSuffix(path, "/retire"):
		return audit.OperationCredentialRetired
	case method == http.MethodGet && strings.HasPrefix(path, "/internal/v1/run-bindings/"):
		return audit.OperationRunBindingInspected
	case method == http.MethodPost && strings.HasSuffix(path, "/cancel"):
		return audit.OperationRunBindingCanceled
	case method == http.MethodPost && strings.HasSuffix(path, "/credential:resolve"):
		return audit.OperationCredentialResolved
	default:
		return audit.OperationUnknownRoute
	}
}

func transactionallyAudited(operation string) bool {
	return operation == audit.OperationRunBindingRegistered ||
		operation == audit.OperationRunBindingCanceled ||
		operation == audit.OperationCredentialResolved ||
		operation == audit.OperationCredentialCreated ||
		operation == audit.OperationCredentialInputsReplaced ||
		operation == audit.OperationCredentialMetadataUpdated ||
		operation == audit.OperationCredentialRetired ||
		operation == audit.OperationMasterKeyRotationStarted ||
		operation == audit.OperationMasterKeyRotationResumed ||
		operation == audit.OperationMasterKeyRotationFinalized ||
		operation == audit.OperationCredentialKeyRotated ||
		operation == audit.OperationRecoveryValidationFinished ||
		operation == audit.OperationBackupRegistered ||
		operation == audit.OperationBackupExpired
}

type actorBody struct {
	UserID                  string `json:"user_id"`
	Username                string `json:"username,omitempty"`
	AuthorizationDecisionID string `json:"authorization_decision_id,omitempty"`
}

func validActor(actor actorBody) bool {
	combined := len(actor.UserID)
	if actor.Username != "" {
		combined += 1 + len(actor.Username)
	}
	return actor.UserID != "" && combined <= 255 && !strings.ContainsAny(actor.UserID+actor.Username+actor.AuthorizationDecisionID, "\x00\r\n") && len(actor.AuthorizationDecisionID) <= 255
}
func actorContext(ctx context.Context, actor actorBody) context.Context {
	request, ok := audit.RequestFromContext(ctx)
	if !ok {
		return ctx
	}
	request.HumanActor = actor.UserID
	if actor.Username != "" {
		request.HumanActor = actor.UserID + ":" + actor.Username
	}
	return audit.WithRequest(ctx, request)
}

type createCredentialBody struct {
	OrganizationID string            `json:"organization_id"`
	Name           string            `json:"name"`
	CredentialType string            `json:"credential_type"`
	SchemaVersion  uint32            `json:"schema_version"`
	Inputs         map[string]string `json:"inputs"`
	Actor          actorBody         `json:"actor"`
}

func (server *Server) createCredential(writer http.ResponseWriter, request *http.Request, identity credential.WorkloadIdentity) {
	if identity.Role != credential.RoleAPI {
		writeProblem(writer, http.StatusForbidden, "operation_not_permitted")
		return
	}
	var body createCredentialBody
	if err := decodeJSON(request, &body); err != nil || !validActor(body.Actor) {
		writeProblem(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	keys := request.Header.Values("Idempotency-Key")
	if len(keys) != 1 || keys[0] == "" {
		writeProblem(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	ctx := actorContext(request.Context(), body.Actor)
	result, err := server.service.CreateContext(ctx, credential.CreateRequest{OrganizationID: body.OrganizationID, Name: body.Name, CredentialType: body.CredentialType, SchemaVersion: body.SchemaVersion, Inputs: body.Inputs, IdempotencyKey: keys[0]})
	clear(body.Inputs)
	if err != nil {
		writeServiceProblem(writer, err)
		return
	}
	writer.Header().Set("Location", "/internal/v1/credentials/"+result.ID)
	writeJSON(writer, http.StatusCreated, result)
}

type replaceCredentialBody struct {
	ExpectedVersion uint64            `json:"expected_version"`
	Inputs          map[string]string `json:"inputs"`
	Actor           actorBody         `json:"actor"`
}
type updateCredentialBody struct {
	ExpectedVersion uint64    `json:"expected_version"`
	Name            string    `json:"name"`
	Actor           actorBody `json:"actor"`
}
type retireCredentialBody struct {
	ExpectedVersion uint64    `json:"expected_version"`
	Actor           actorBody `json:"actor"`
}

func (server *Server) credentialRoute(writer http.ResponseWriter, request *http.Request, identity credential.WorkloadIdentity, path string) {
	if identity.Role != credential.RoleAPI {
		writeProblem(writer, http.StatusForbidden, "operation_not_permitted")
		return
	}
	relative := strings.TrimPrefix(path, "/internal/v1/credentials/")
	inputsRoute := strings.HasSuffix(relative, "/inputs")
	retireRoute := strings.HasSuffix(relative, "/retire")
	credentialID := strings.TrimSuffix(strings.TrimSuffix(relative, "/inputs"), "/retire")
	if credentialID == "" || strings.Contains(credentialID, "/") {
		writeProblem(writer, http.StatusNotFound, "resource_not_found")
		return
	}
	organizationID := strings.TrimSpace(request.Header.Get("X-Praetor-Organization-ID"))
	if organizationID == "" || len(organizationID) > 255 {
		writeProblem(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	switch {
	case request.Method == http.MethodGet && !inputsRoute && !retireRoute:
		result, err := server.service.GetContext(request.Context(), organizationID, credentialID)
		if err != nil {
			writeServiceProblem(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, result)
	case request.Method == http.MethodPut && inputsRoute:
		var body replaceCredentialBody
		if err := decodeJSON(request, &body); err != nil || !validActor(body.Actor) {
			writeProblem(writer, http.StatusBadRequest, "invalid_request")
			return
		}
		ctx := actorContext(request.Context(), body.Actor)
		result, err := server.service.ReplaceInputsContext(ctx, credential.ReplaceInputsRequest{CredentialID: credentialID, OrganizationID: organizationID, ExpectedVersion: body.ExpectedVersion, Inputs: body.Inputs})
		clear(body.Inputs)
		if err != nil {
			writeServiceProblem(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, result)
	case request.Method == http.MethodPatch && !inputsRoute && !retireRoute:
		var body updateCredentialBody
		if err := decodeJSON(request, &body); err != nil || !validActor(body.Actor) {
			writeProblem(writer, http.StatusBadRequest, "invalid_request")
			return
		}
		ctx := actorContext(request.Context(), body.Actor)
		result, err := server.service.UpdateMetadataContext(ctx, credential.UpdateMetadataRequest{CredentialID: credentialID, OrganizationID: organizationID, ExpectedVersion: body.ExpectedVersion, Name: body.Name})
		if err != nil {
			writeServiceProblem(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, result)
	case request.Method == http.MethodPost && retireRoute:
		var body retireCredentialBody
		if err := decodeJSON(request, &body); err != nil || !validActor(body.Actor) {
			writeProblem(writer, http.StatusBadRequest, "invalid_request")
			return
		}
		ctx := actorContext(request.Context(), body.Actor)
		result, err := server.service.RetireContext(ctx, credential.RetireRequest{CredentialID: credentialID, OrganizationID: organizationID, ExpectedVersion: body.ExpectedVersion})
		if err != nil {
			writeServiceProblem(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, result)
	default:
		writeProblem(writer, http.StatusNotFound, "resource_not_found")
	}
}

func requestRunID(path string) string {
	trimmed := ""
	switch {
	case strings.HasPrefix(path, "/internal/v1/run-bindings/"):
		trimmed = strings.TrimPrefix(path, "/internal/v1/run-bindings/")
		trimmed = strings.TrimSuffix(trimmed, "/cancel")
	case strings.HasPrefix(path, "/internal/v1/runs/"):
		trimmed = strings.TrimPrefix(path, "/internal/v1/runs/")
		trimmed = strings.TrimSuffix(trimmed, "/credential:resolve")
	}
	if strings.Contains(trimmed, "/") || len(trimmed) != 36 {
		return ""
	}
	return trimmed
}

func (server *Server) securityStatus(writer http.ResponseWriter, request *http.Request, identity credential.WorkloadIdentity) {
	if identity.Role != credential.RoleSecretsOperator && identity.Role != credential.RoleSecretsAuditor {
		writeProblem(writer, http.StatusForbidden, "operation_not_permitted")
		return
	}
	if server.auditor == nil {
		writeProblem(writer, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	status, err := server.auditor.Status(request.Context())
	if err != nil {
		writeProblem(writer, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, status)
}

func (server *Server) requestIdentity(request *http.Request) (credential.WorkloadIdentity, error) {
	if request.TLS == nil || !request.TLS.HandshakeComplete || request.TLS.Version != tls.VersionTLS13 ||
		len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return credential.WorkloadIdentity{}, ErrWorkloadIdentity
	}
	return server.mapper.Identity(request.TLS.VerifiedChains[0][0])
}

type registerBindingBody struct {
	RunID            string    `json:"run_id"`
	DispatchID       string    `json:"dispatch_id"`
	OrganizationID   string    `json:"organization_id"`
	CredentialID     string    `json:"credential_id"`
	ExecutorIdentity string    `json:"executor_identity"`
	NotBefore        time.Time `json:"not_before"`
	ExpiresAt        time.Time `json:"expires_at"`
	MaxResolutions   uint32    `json:"max_resolutions"`
}

func (server *Server) registerBinding(writer http.ResponseWriter, request *http.Request, identity credential.WorkloadIdentity) {
	if identity.Role != credential.RoleScheduler {
		writeProblem(writer, http.StatusForbidden, "operation_not_permitted")
		return
	}
	var body registerBindingBody
	if err := decodeJSON(request, &body); err != nil {
		writeDecodeProblem(writer, err)
		return
	}
	idempotencyKeys := request.Header.Values("Idempotency-Key")
	if len(idempotencyKeys) != 1 || idempotencyKeys[0] == "" {
		writeProblem(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	result, err := server.service.RegisterBinding(request.Context(), identity, credential.RegisterBindingRequest{
		RunID: body.RunID, DispatchID: body.DispatchID, OrganizationID: body.OrganizationID,
		CredentialID: body.CredentialID, ExecutorIdentity: body.ExecutorIdentity,
		NotBefore: body.NotBefore, ExpiresAt: body.ExpiresAt, MaxResolutions: body.MaxResolutions,
		IdempotencyKey: idempotencyKeys[0],
	})
	if err != nil {
		writeServiceProblem(writer, err)
		return
	}
	writer.Header().Set("Location", "/internal/v1/run-bindings/"+result.RunID)
	writeJSON(writer, http.StatusCreated, result)
}

func (server *Server) inspectBinding(writer http.ResponseWriter, request *http.Request, identity credential.WorkloadIdentity, runID string) {
	if identity.Role != credential.RoleScheduler {
		writeProblem(writer, http.StatusForbidden, "operation_not_permitted")
		return
	}
	result, err := server.service.InspectBinding(request.Context(), identity, runID)
	if err != nil {
		writeServiceProblem(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

type cancelBindingBody struct {
	DispatchID string `json:"dispatch_id"`
	Reason     string `json:"reason"`
}

func (server *Server) cancelBinding(writer http.ResponseWriter, request *http.Request, identity credential.WorkloadIdentity, runID string) {
	if identity.Role != credential.RoleScheduler {
		writeProblem(writer, http.StatusForbidden, "operation_not_permitted")
		return
	}
	var body cancelBindingBody
	if err := decodeJSON(request, &body); err != nil {
		writeDecodeProblem(writer, err)
		return
	}
	result, err := server.service.CancelBinding(request.Context(), identity, credential.CancelBindingRequest{
		RunID: runID, DispatchID: body.DispatchID, Reason: body.Reason,
	})
	if err != nil {
		writeServiceProblem(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

type resolveBody struct {
	AttemptID   string    `json:"attempt_id"`
	RequestedAt time.Time `json:"requested_at"`
}

func (server *Server) resolve(writer http.ResponseWriter, request *http.Request, identity credential.WorkloadIdentity, runID string) {
	if identity.Role != credential.RoleExecutor {
		writeProblem(writer, http.StatusForbidden, "operation_not_permitted")
		return
	}
	var body resolveBody
	if err := decodeJSON(request, &body); err != nil {
		writeDecodeProblem(writer, err)
		return
	}
	result, err := server.service.Resolve(request.Context(), identity, credential.ResolveRequest{
		RunID: runID, AttemptID: body.AttemptID, RequestedAt: body.RequestedAt,
	})
	if err != nil {
		writeServiceProblem(writer, err)
		return
	}
	writer.Header().Set("Content-Encoding", "identity")
	writer.Header().Set("Connection", "close")
	writeJSON(writer, http.StatusOK, result)
}

func secureHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
}

func writeDecodeProblem(writer http.ResponseWriter, err error) {
	if errors.Is(err, errTooLarge) {
		writeProblem(writer, http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	writeProblem(writer, http.StatusBadRequest, "invalid_request")
}

func writeServiceProblem(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, credential.ErrInvalidInput):
		writeProblem(writer, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, credential.ErrUnauthorized):
		writeProblem(writer, http.StatusForbidden, "operation_not_permitted")
	case errors.Is(err, credential.ErrBindingNotActive):
		writeProblem(writer, http.StatusForbidden, "run_binding_not_active")
	case errors.Is(err, credential.ErrNotFound), errors.Is(err, credential.ErrBindingNotFound):
		writeProblem(writer, http.StatusNotFound, "resource_not_found")
	case errors.Is(err, credential.ErrBindingConflict):
		writeProblem(writer, http.StatusConflict, "run_binding_conflict")
	case errors.Is(err, credential.ErrIdempotencyConflict):
		writeProblem(writer, http.StatusConflict, "idempotency_conflict")
	case errors.Is(err, credential.ErrVersionConflict):
		writeProblem(writer, http.StatusConflict, "version_conflict")
	case errors.Is(err, credential.ErrCredentialNotActive):
		writeProblem(writer, http.StatusConflict, "credential_not_active")
	case errors.Is(err, credential.ErrAttemptConflict):
		writeProblem(writer, http.StatusConflict, "attempt_conflict")
	case errors.Is(err, credential.ErrRotationConflict):
		writeProblem(writer, http.StatusConflict, "rotation_conflict")
	case errors.Is(err, credential.ErrRotationNotReady):
		writeProblem(writer, http.StatusConflict, "rotation_not_ready")
	case errors.Is(err, credential.ErrRotationUnavailable):
		writeProblem(writer, http.StatusServiceUnavailable, "rotation_unavailable")
	case errors.Is(err, credential.ErrBackupConflict):
		writeProblem(writer, http.StatusConflict, "backup_conflict")
	case errors.Is(err, credential.ErrRecoveryValidation):
		writeProblem(writer, http.StatusConflict, "recovery_validation_failed")
	case errors.Is(err, credential.ErrStorage):
		writeProblem(writer, http.StatusServiceUnavailable, "service_unavailable")
	default:
		writeProblem(writer, http.StatusInternalServerError, "secure_operation_failed")
	}
}

func writeProblem(writer http.ResponseWriter, status int, code string) {
	if observed, ok := writer.(*observedWriter); ok {
		observed.reason = code
	}
	writer.Header().Set("Content-Type", "application/problem+json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(struct {
		Code      string `json:"code"`
		Status    int    `json:"status"`
		RequestID string `json:"request_id"`
	}{Code: code, Status: status, RequestID: requestIDFromWriter(writer)})
}

func requestIDFromWriter(writer http.ResponseWriter) string {
	if observed, ok := writer.(*observedWriter); ok {
		return observed.requestID
	}
	return ""
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
