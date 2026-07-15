package transport

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Niftel/praetor-secrets/credential"
)

type CredentialService interface {
	RegisterBinding(context.Context, credential.WorkloadIdentity, credential.RegisterBindingRequest) (credential.Binding, error)
	InspectBinding(context.Context, credential.WorkloadIdentity, string) (credential.Binding, error)
	CancelBinding(context.Context, credential.WorkloadIdentity, credential.CancelBindingRequest) (credential.Binding, error)
	Resolve(context.Context, credential.WorkloadIdentity, credential.ResolveRequest) (credential.ResolvedCredential, error)
}

type Server struct {
	service CredentialService
	mapper  SPIFFEMapper
}

func NewServer(service CredentialService, mapper SPIFFEMapper) (*Server, error) {
	if service == nil || mapper.TrustDomain == "" {
		return nil, credential.ErrInvalidInput
	}
	return &Server{service: service, mapper: mapper}, nil
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
	secureHeaders(writer)
	identity, err := server.requestIdentity(request)
	if err != nil {
		writeProblem(writer, http.StatusUnauthorized, "workload_authentication_failed")
		return
	}
	path := request.URL.EscapedPath()
	switch {
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
	case errors.Is(err, credential.ErrAttemptConflict):
		writeProblem(writer, http.StatusConflict, "attempt_conflict")
	case errors.Is(err, credential.ErrStorage):
		writeProblem(writer, http.StatusServiceUnavailable, "service_unavailable")
	default:
		writeProblem(writer, http.StatusInternalServerError, "secure_operation_failed")
	}
}

func writeProblem(writer http.ResponseWriter, status int, code string) {
	writer.Header().Set("Content-Type", "application/problem+json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(struct {
		Code   string `json:"code"`
		Status int    `json:"status"`
	}{Code: code, Status: status})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
