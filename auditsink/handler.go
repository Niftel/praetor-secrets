package auditsink

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/Niftel/praetor-secrets/audit"
)

const (
	IngestionPath   = "/internal/v1/audit/events"
	maxRequestBytes = 64 << 10
)

type Appender interface {
	Append(context.Context, audit.Record, string, string) (AppendResult, error)
}

type Handler struct {
	appender    Appender
	trustDomain string
}

func NewHandler(appender Appender, trustDomain string) (*Handler, error) {
	if appender == nil || !validSinkTrustDomain(trustDomain) {
		return nil, ErrInvalid
	}
	return &Handler{appender: appender, trustDomain: trustDomain}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Method != http.MethodPost || request.URL.Path != IngestionPath || request.URL.RawQuery != "" {
		handler.problem(writer, http.StatusNotFound, "resource_not_found")
		return
	}
	if !handler.authenticated(request) {
		handler.problem(writer, http.StatusUnauthorized, "workload_authentication_failed")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		handler.problem(writer, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var record audit.Record
	if decoder.Decode(&record) != nil {
		handler.problem(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		handler.problem(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	idempotencyKey := request.Header.Get("Idempotency-Key")
	if len(record.MAC) != 32 || idempotencyKey != "audit-"+hex.EncodeToString(record.MAC) {
		handler.problem(writer, http.StatusBadRequest, "invalid_idempotency_key")
		return
	}
	result, err := handler.appender.Append(request.Context(), record, idempotencyKey, "praetor-secrets")
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalid):
			handler.problem(writer, http.StatusBadRequest, "invalid_request")
		case errors.Is(err, ErrConflict):
			handler.problem(writer, http.StatusConflict, "stream_conflict")
		default:
			handler.problem(writer, http.StatusServiceUnavailable, "service_unavailable")
		}
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	switch result {
	case Created:
		writer.WriteHeader(http.StatusCreated)
	case Replayed:
		writer.WriteHeader(http.StatusOK)
	default:
		handler.problem(writer, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	_, _ = writer.Write([]byte(`{"accepted":true}`))
}

func (handler *Handler) authenticated(request *http.Request) bool {
	if request.TLS == nil || !request.TLS.HandshakeComplete || request.TLS.Version != tls.VersionTLS13 ||
		len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return false
	}
	return secretsServiceIdentity(request.TLS.VerifiedChains[0][0], handler.trustDomain)
}

func secretsServiceIdentity(certificate *x509.Certificate, trustDomain string) bool {
	if certificate == nil || len(certificate.URIs) != 1 {
		return false
	}
	identity := certificate.URIs[0]
	return identity.Scheme == "spiffe" && identity.Host == trustDomain && identity.EscapedPath() == "/workload/praetor-secrets" &&
		identity.RawQuery == "" && identity.Fragment == ""
}

func validSinkTrustDomain(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || strings.ContainsAny(value, "/:@ \t\r\n") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-') {
				return false
			}
		}
	}
	return true
}

func (handler *Handler) problem(writer http.ResponseWriter, status int, code string) {
	writer.Header().Set("Content-Type", "application/problem+json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"status": status, "code": code})
}
