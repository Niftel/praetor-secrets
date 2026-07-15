package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Niftel/praetor-secrets/credential"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testClient(t *testing.T, check func(*http.Request, string)) *Client {
	t.Helper()
	base, _ := url.Parse("https://secrets.internal")
	return &Client{base: base, http: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		check(request, string(body))
		response := `{"id":"4b152888-54a6-4f85-8ed1-8e66498db245","organization_id":"5","name":"machine","credential_type":"machine","schema_version":1,"version":1,"state":"active","secret_fields":["password"],"created_at":"2026-07-15T00:00:00Z","updated_at":"2026-07-15T00:00:00Z"}`
		status := http.StatusOK
		if request.URL.Path == "/internal/v1/credentials" || request.URL.Path == "/internal/v1/run-bindings" {
			status = http.StatusCreated
		}
		if strings.Contains(request.URL.Path, "run-bindings") {
			response = `{"run_id":"32b9fc25-fd71-47e6-b0e8-45db87df9f65","dispatch_id":"2f22ddc8-daba-4c64-a25a-bdbe7c521999","organization_id":"5","credential_id":"4b152888-54a6-4f85-8ed1-8e66498db245","credential_version":1,"executor_identity":"praetor-executor:worker-7","state":"active","not_before":"2026-07-15T00:00:00Z","expires_at":"2026-07-15T01:00:00Z","max_resolutions":3,"resolution_count":0,"created_at":"2026-07-15T00:00:00Z","updated_at":"2026-07-15T00:00:00Z"}`
		}
		if strings.Contains(request.URL.Path, "credential:resolve") {
			response = `{"run_id":"32b9fc25-fd71-47e6-b0e8-45db87df9f65","attempt_id":"53983bcc-db16-4921-a6c4-b589a8299c97","expires_at":"2026-07-15T01:00:00Z","environment":{"TOKEN":"value"}}`
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response))}, nil
	})}}
}

func TestCredentialOperationsUseNarrowRoutesAndHeaders(t *testing.T) {
	inputs := map[string]string{"username": "automation", "password": "secret"}
	client := testClient(t, func(request *http.Request, body string) {
		if request.Method != http.MethodPost || request.URL.Path != "/internal/v1/credentials" || request.Header.Get("Idempotency-Key") != "create-7" || !strings.Contains(body, `"organization_id":"5"`) {
			t.Fatalf("unexpected create request: %s %s %s", request.Method, request.URL.Path, body)
		}
	})
	metadata, err := client.CreateCredential(context.Background(), CreateCredentialRequest{
		OrganizationID: "5", Name: "machine", CredentialType: "machine", SchemaVersion: 1,
		Inputs: inputs, IdempotencyKey: "create-7", Actor: Actor{UserID: "42", Username: "operator"},
	})
	if err != nil || metadata.ID == "" {
		t.Fatalf("create: metadata=%+v err=%v", metadata, err)
	}
	if inputs["password"] != "secret" {
		t.Fatal("client mutated caller-owned inputs")
	}

	client = testClient(t, func(request *http.Request, _ string) {
		if request.Method != http.MethodGet || request.URL.Path != "/internal/v1/credentials/4b152888-54a6-4f85-8ed1-8e66498db245" || request.Header.Get("X-Praetor-Organization-ID") != "5" {
			t.Fatalf("unexpected get request: %s %s", request.Method, request.URL.Path)
		}
	})
	if _, err := client.GetCredential(context.Background(), "5", "4b152888-54a6-4f85-8ed1-8e66498db245"); err != nil {
		t.Fatal(err)
	}
}

func TestRunBindingAndResolutionContracts(t *testing.T) {
	now := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	client := testClient(t, func(request *http.Request, body string) {
		if request.URL.Path != "/internal/v1/run-bindings" || request.Header.Get("Idempotency-Key") != "dispatch-1" ||
			!strings.Contains(body, `"executor_identity":"praetor-executor:worker-7"`) || !strings.Contains(body, `"max_resolutions":3`) {
			t.Fatalf("unexpected binding request: %s", body)
		}
	})
	binding, err := client.RegisterBinding(context.Background(), credential.RegisterBindingRequest{
		RunID: "32b9fc25-fd71-47e6-b0e8-45db87df9f65", DispatchID: "2f22ddc8-daba-4c64-a25a-bdbe7c521999",
		OrganizationID: "5", CredentialID: "4b152888-54a6-4f85-8ed1-8e66498db245", ExecutorIdentity: "praetor-executor:worker-7",
		NotBefore: now, ExpiresAt: now.Add(time.Hour), MaxResolutions: 3, IdempotencyKey: "dispatch-1",
	})
	if err != nil || binding.CredentialVersion != 1 {
		t.Fatalf("binding: %+v %v", binding, err)
	}

	client = testClient(t, func(request *http.Request, body string) {
		if request.URL.Path != "/internal/v1/runs/32b9fc25-fd71-47e6-b0e8-45db87df9f65/credential:resolve" ||
			!strings.Contains(body, `"attempt_id":"53983bcc-db16-4921-a6c4-b589a8299c97"`) {
			t.Fatalf("unexpected resolution request: %s", body)
		}
	})
	resolved, err := client.Resolve(context.Background(), credential.ResolveRequest{RunID: "32b9fc25-fd71-47e6-b0e8-45db87df9f65", AttemptID: "53983bcc-db16-4921-a6c4-b589a8299c97", RequestedAt: now})
	if err != nil || resolved.Environment["TOKEN"] != "value" {
		t.Fatalf("resolve: %+v %v", resolved, err)
	}
}

func TestUpdateAndCancellationContracts(t *testing.T) {
	client := testClient(t, func(request *http.Request, body string) {
		if request.Method != http.MethodPut || !strings.HasSuffix(request.URL.Path, "/inputs") || request.Header.Get("X-Praetor-Organization-ID") != "5" ||
			!strings.Contains(body, `"expected_version":1`) || !strings.Contains(body, `"inputs":{"password":"replacement"}`) {
			t.Fatalf("unexpected replace request: %s %s %s", request.Method, request.URL.Path, body)
		}
	})
	inputs := map[string]string{"password": "replacement"}
	if _, err := client.ReplaceInputs(context.Background(), ReplaceInputsRequest{
		OrganizationID: "5", CredentialID: "4b152888-54a6-4f85-8ed1-8e66498db245", ExpectedVersion: 1,
		Inputs: inputs, Actor: Actor{UserID: "42"},
	}); err != nil || inputs["password"] != "replacement" {
		t.Fatalf("replace: err=%v inputs=%v", err, inputs)
	}

	client = testClient(t, func(request *http.Request, body string) {
		if request.Method != http.MethodPatch || strings.HasSuffix(request.URL.Path, "/inputs") || !strings.Contains(body, `"name":"renamed"`) {
			t.Fatalf("unexpected metadata request: %s %s", request.Method, body)
		}
	})
	if _, err := client.UpdateMetadata(context.Background(), UpdateMetadataRequest{
		OrganizationID: "5", CredentialID: "4b152888-54a6-4f85-8ed1-8e66498db245", ExpectedVersion: 1,
		Name: "renamed", Actor: Actor{UserID: "42"},
	}); err != nil {
		t.Fatal(err)
	}

	client = testClient(t, func(request *http.Request, body string) {
		if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/retire") || request.Header.Get("X-Praetor-Organization-ID") != "5" ||
			!strings.Contains(body, `"expected_version":2`) || !strings.Contains(body, `"user_id":"42"`) {
			t.Fatalf("unexpected retirement request: %s %s %s", request.Method, request.URL.Path, body)
		}
	})
	if _, err := client.RetireCredential(context.Background(), RetireCredentialRequest{
		OrganizationID: "5", CredentialID: "4b152888-54a6-4f85-8ed1-8e66498db245", ExpectedVersion: 2, Actor: Actor{UserID: "42"},
	}); err != nil {
		t.Fatal(err)
	}

	client = testClient(t, func(request *http.Request, body string) {
		if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/cancel") || !strings.Contains(body, `"reason":"job_canceled"`) {
			t.Fatalf("unexpected cancel request: %s %s", request.URL.Path, body)
		}
	})
	if _, err := client.CancelBinding(context.Background(), credential.CancelBindingRequest{
		RunID: "32b9fc25-fd71-47e6-b0e8-45db87df9f65", DispatchID: "2f22ddc8-daba-4c64-a25a-bdbe7c521999", Reason: "job_canceled",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestErrorsAreBoundedAndDoNotIncludeResponseBody(t *testing.T) {
	base, _ := url.Parse("https://secrets.internal")
	client := &Client{base: base, http: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":"operation_not_permitted","secret":"must-not-leak"}`))}, nil
	})}}
	_, err := client.GetCredential(context.Background(), "5", "4b152888-54a6-4f85-8ed1-8e66498db245")
	problem, ok := err.(*Problem)
	if !ok || problem.Status != http.StatusForbidden || problem.Code != "operation_not_permitted" || strings.Contains(err.Error(), "must-not-leak") {
		t.Fatalf("unsafe error: %#v", err)
	}
}

func TestMalformedAndOversizedResponsesFailClosed(t *testing.T) {
	for name, body := range map[string]string{
		"malformed": `{not-json}`,
		"oversized": strings.Repeat("x", maxResponseBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			base, _ := url.Parse("https://secrets.internal")
			client := &Client{base: base, http: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}}
			_, err := client.GetCredential(context.Background(), "5", "4b152888-54a6-4f85-8ed1-8e66498db245")
			problem, ok := err.(*Problem)
			if !ok || problem.Code != "invalid_response" {
				t.Fatalf("error=%#v", err)
			}
		})
	}
}

func TestTransportAndUntrustedProblemFailures(t *testing.T) {
	base, _ := url.Parse("https://secrets.internal")
	client := &Client{base: base, http: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})}}
	if _, err := client.GetCredential(context.Background(), "5", "4b152888-54a6-4f85-8ed1-8e66498db245"); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("transport error=%v", err)
	}

	client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`not-json-and-must-not-leak`))}, nil
	})
	_, err := client.GetCredential(context.Background(), "5", "4b152888-54a6-4f85-8ed1-8e66498db245")
	problem, ok := err.(*Problem)
	if !ok || problem.Code != "request_failed" || strings.Contains(err.Error(), "must-not-leak") {
		t.Fatalf("problem=%#v", err)
	}
}

func TestHeaderInjectionIsRejectedBeforeTransport(t *testing.T) {
	called := false
	base, _ := url.Parse("https://secrets.internal")
	client := &Client{base: base, http: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})}}
	_, err := client.GetCredential(context.Background(), "5\r\nInjected: yes", "4b152888-54a6-4f85-8ed1-8e66498db245")
	if !errors.Is(err, ErrConfiguration) || called {
		t.Fatalf("err=%v called=%v", err, called)
	}
}

func TestNewRejectsNonTLSAndIncompleteConfiguration(t *testing.T) {
	for _, config := range []Config{{}, {BaseURL: "http://secrets.internal", CAFile: "ca", CertificateFile: "cert", PrivateKeyFile: "key", Timeout: 5 * time.Second}} {
		if _, err := New(config); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("New(%+v) error=%v", config, err)
		}
	}
}
