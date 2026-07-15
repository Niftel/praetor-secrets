package audit

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestHTTPSinkValidatesAndDelivers(t *testing.T) {
	if _, err := NewHTTPSink("http://sink.local/events", &tls.Config{MinVersion: tls.VersionTLS13}); !errors.Is(err, ErrSink) {
		t.Fatalf("plain HTTP accepted: %v", err)
	}
	if _, err := NewHTTPSink("https://user@sink.local/events", &tls.Config{MinVersion: tls.VersionTLS13}); !errors.Is(err, ErrSink) {
		t.Fatalf("URL credentials accepted: %v", err)
	}
	created, err := NewHTTPSink("https://sink.local/events", &tls.Config{MinVersion: tls.VersionTLS13})
	if err != nil || created.endpoint != "https://sink.local/events" {
		t.Fatalf("sink=%+v err=%v", created, err)
	}
	var received *http.Request
	sink := &HTTPSink{endpoint: "https://sink.local/events", client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		received = request
		return &http.Response{StatusCode: 202, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header)}, nil
	})}}
	record := Record{Sequence: 1, Event: validEvent(), MAC: make([]byte, 32)}
	if err := sink.Deliver(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if received.Header.Get("Idempotency-Key") == "" || received.Header.Get("Cache-Control") != "no-store" || received.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers=%v", received.Header)
	}
	sink.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("unavailable")), Header: make(http.Header)}, nil
	})}
	if err := sink.Deliver(context.Background(), record); !errors.Is(err, ErrSink) {
		t.Fatalf("failure accepted: %v", err)
	}
	if err := sink.Deliver(context.Background(), Record{}); !errors.Is(err, ErrSink) {
		t.Fatalf("invalid record accepted: %v", err)
	}
}

func TestDeliveryWorkerConfigurationAndStatus(t *testing.T) {
	if _, err := NewDeliveryWorker(nil, nil, nil, DeliveryConfig{}); !errors.Is(err, ErrAudit) {
		t.Fatalf("invalid worker: %v", err)
	}
	if err := (*DeliveryWorker)(nil).Run(nil); !errors.Is(err, ErrAudit) {
		t.Fatalf("nil run: %v", err)
	}
	status := (*DeliveryWorker)(nil).Status()
	if !status.Degraded {
		t.Fatal("nil worker not degraded")
	}
	worker := &DeliveryWorker{}
	if worker.Status().Degraded {
		t.Fatal("new worker degraded")
	}
	worker.lastDelivered.Store(time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC).UnixNano())
	if worker.Status().LastDelivered.IsZero() {
		t.Fatal("delivery time missing")
	}
}

func TestCompletionAndStableResults(t *testing.T) {
	started := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	ctx := WithRequest(context.Background(), Request{ID: "request-1", WorkloadIdentity: "praetor-scheduler", Operation: "run_binding_inspected", StartedAt: started})
	event := Completion(ctx, "success", "completed", started.Add(20*time.Millisecond))
	if event.RequestID != "request-1" || event.LatencyClass != "medium" || event.WorkloadIdentity != "praetor-scheduler" {
		t.Fatalf("event=%+v", event)
	}
	for _, test := range []struct {
		status int
		result string
	}{{200, "success"}, {403, "denied"}, {404, "rejected"}, {500, "error"}} {
		result, _ := StableResult(test.status)
		if result != test.result {
			t.Fatalf("status=%d result=%s", test.status, result)
		}
	}
	if _, err := NewRecorder(nil, nil, nil); !errors.Is(err, ErrAudit) {
		t.Fatalf("invalid recorder: %v", err)
	}
}
