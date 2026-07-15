package auditsink

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Niftel/praetor-secrets/audit"
)

type fakeAppender struct {
	result      AppendResult
	err         error
	record      audit.Record
	key         string
	identity    string
	appendCalls int
}

func (appender *fakeAppender) Append(_ context.Context, record audit.Record, key, identity string) (AppendResult, error) {
	appender.appendCalls++
	appender.record, appender.key, appender.identity = record, key, identity
	return appender.result, appender.err
}

func authenticatedAuditRequest(t *testing.T, body []byte, identity string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, IngestionPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	parsed, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{URIs: []*url.URL{parsed}}
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, VerifiedChains: [][]*x509.Certificate{{certificate}}}
	return request
}

func encodedAuditRecord(t *testing.T) ([]byte, audit.Record) {
	t.Helper()
	record := validRecord(1)
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return body, record
}

func TestHandlerAcceptsCreatedAndReplayedRecords(t *testing.T) {
	for _, test := range []struct {
		result AppendResult
		status int
	}{{Created, http.StatusCreated}, {Replayed, http.StatusOK}} {
		appender := &fakeAppender{result: test.result}
		handler, err := NewHandler(appender, "praetor.local")
		if err != nil {
			t.Fatal(err)
		}
		body, record := encodedAuditRecord(t)
		request := authenticatedAuditRequest(t, body, "spiffe://praetor.local/workload/praetor-secrets")
		request.Header.Set("Idempotency-Key", key(record))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status || appender.appendCalls != 1 || appender.identity != "praetor-secrets" || appender.key != key(record) {
			t.Fatalf("status=%d appender=%+v", response.Code, appender)
		}
		if response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), record.Event.Operation) {
			t.Fatalf("unsafe response headers=%v body=%s", response.Header(), response.Body.String())
		}
	}
}

func TestHandlerRejectsUnauthenticatedAndWrongWorkload(t *testing.T) {
	body, record := encodedAuditRecord(t)
	for _, identity := range []string{"", "spiffe://praetor.local/workload/praetor-scheduler", "spiffe://other.local/workload/praetor-secrets"} {
		appender := &fakeAppender{result: Created}
		handler, _ := NewHandler(appender, "praetor.local")
		var request *http.Request
		if identity == "" {
			request = httptest.NewRequest(http.MethodPost, IngestionPath, bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
		} else {
			request = authenticatedAuditRequest(t, body, identity)
		}
		request.Header.Set("Idempotency-Key", key(record))
		request.Header.Set("X-Praetor-Identity", "praetor-secrets")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || appender.appendCalls != 0 {
			t.Fatalf("identity=%q status=%d calls=%d", identity, response.Code, appender.appendCalls)
		}
	}
}

func TestHandlerRejectsAmbiguousCertificateIdentity(t *testing.T) {
	body, record := encodedAuditRecord(t)
	request := authenticatedAuditRequest(t, body, "spiffe://praetor.local/workload/praetor-secrets")
	extra, err := url.Parse("spiffe://praetor.local/workload/praetor-scheduler")
	if err != nil {
		t.Fatal(err)
	}
	request.TLS.VerifiedChains[0][0].URIs = append(request.TLS.VerifiedChains[0][0].URIs, extra)
	request.Header.Set("Idempotency-Key", key(record))
	appender := &fakeAppender{result: Created}
	handler, _ := NewHandler(appender, "praetor.local")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || appender.appendCalls != 0 {
		t.Fatalf("status=%d calls=%d", response.Code, appender.appendCalls)
	}
}

func TestHandlerRejectsMalformedRequestsBeforeAppend(t *testing.T) {
	body, record := encodedAuditRecord(t)
	tests := []struct {
		name, contentType, key string
		body                   []byte
		status                 int
	}{
		{"wrong content type", "text/plain", key(record), body, http.StatusUnsupportedMediaType},
		{"unknown field", "application/json", key(record), append(body[:len(body)-1], []byte(`,"unknown":true}`)...), http.StatusBadRequest},
		{"trailing json", "application/json", key(record), append(body, []byte(` {}`)...), http.StatusBadRequest},
		{"wrong key", "application/json", "audit-wrong", body, http.StatusBadRequest},
		{"oversized", "application/json", key(record), []byte(`{"padding":"` + strings.Repeat("x", maxRequestBytes) + `"}`), http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			appender := &fakeAppender{result: Created}
			handler, _ := NewHandler(appender, "praetor.local")
			request := authenticatedAuditRequest(t, test.body, "spiffe://praetor.local/workload/praetor-secrets")
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set("Idempotency-Key", test.key)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || appender.appendCalls != 0 {
				t.Fatalf("status=%d calls=%d", response.Code, appender.appendCalls)
			}
		})
	}
}

func TestHandlerMapsStoreFailuresWithoutValues(t *testing.T) {
	body, record := encodedAuditRecord(t)
	for _, test := range []struct {
		err    error
		status int
	}{{ErrInvalid, 400}, {ErrConflict, 409}, {ErrStore, 503}, {errors.New("unknown"), 503}} {
		appender := &fakeAppender{err: test.err}
		handler, _ := NewHandler(appender, "praetor.local")
		request := authenticatedAuditRequest(t, body, "spiffe://praetor.local/workload/praetor-secrets")
		request.Header.Set("Idempotency-Key", key(record))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status || strings.Contains(response.Body.String(), record.Event.Operation) {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}
}

func TestHandlerFailsClosedForUnknownStoreResult(t *testing.T) {
	body, record := encodedAuditRecord(t)
	appender := &fakeAppender{result: AppendResult(99)}
	handler, _ := NewHandler(appender, "praetor.local")
	request := authenticatedAuditRequest(t, body, "spiffe://praetor.local/workload/praetor-secrets")
	request.Header.Set("Idempotency-Key", key(record))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHandlerRejectsNonCanonicalEndpoint(t *testing.T) {
	body, record := encodedAuditRecord(t)
	appender := &fakeAppender{result: Created}
	handler, _ := NewHandler(appender, "praetor.local")
	request := authenticatedAuditRequest(t, body, "spiffe://praetor.local/workload/praetor-secrets")
	request.URL.RawQuery = "source=client"
	request.Header.Set("Idempotency-Key", key(record))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || appender.appendCalls != 0 {
		t.Fatalf("status=%d calls=%d", response.Code, appender.appendCalls)
	}
}

func TestNewHandlerValidatesConfiguration(t *testing.T) {
	if _, err := NewHandler(nil, "praetor.local"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil appender error=%v", err)
	}
	if _, err := NewHandler(&fakeAppender{}, "Bad/Domain"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad domain error=%v", err)
	}
}
