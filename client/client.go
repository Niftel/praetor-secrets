// Package client provides the narrow mTLS client used by Praetor workloads.
// It deliberately mirrors only the service's reviewed operations; it does not
// expose a generic request method or an arbitrary plaintext credential lookup.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Niftel/praetor-secrets/credential"
)

const maxResponseBytes = 1 << 20

var ErrConfiguration = errors.New("invalid secrets client configuration")

// Config contains the workload identity and trust roots used for mTLS. The
// private key must be supplied as a file; accepting key bytes or environment
// variables would make accidental propagation much easier.
type Config struct {
	BaseURL         string
	CAFile          string
	CertificateFile string
	PrivateKeyFile  string
	Timeout         time.Duration
}

type Client struct {
	base *url.URL
	http *http.Client
}

// Problem is a stable, value-free service error. Response bodies are never
// copied into errors because they could contain unexpected sensitive content.
type Problem struct {
	Status int
	Code   string
}

func (problem *Problem) Error() string {
	return fmt.Sprintf("secrets service request failed: status=%d code=%s", problem.Status, problem.Code)
}

func New(config Config) (*Client, error) {
	base, err := url.Parse(config.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") ||
		config.CAFile == "" || config.CertificateFile == "" || config.PrivateKeyFile == "" || config.Timeout < time.Second || config.Timeout > time.Minute {
		return nil, ErrConfiguration
	}
	base.Path = ""
	caPEM, err := os.ReadFile(config.CAFile)
	if err != nil {
		return nil, ErrConfiguration
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, ErrConfiguration
	}
	certificate, err := tls.LoadX509KeyPair(config.CertificateFile, config.PrivateKeyFile)
	if err != nil {
		return nil, ErrConfiguration
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		Certificates: []tls.Certificate{certificate},
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       tlsConfig,
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	return &Client{base: base, http: &http.Client{
		Transport:     transport,
		Timeout:       config.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

type Actor struct {
	UserID                  string `json:"user_id"`
	Username                string `json:"username,omitempty"`
	AuthorizationDecisionID string `json:"authorization_decision_id,omitempty"`
}

type CreateCredentialRequest struct {
	OrganizationID string
	Name           string
	CredentialType string
	SchemaVersion  uint32
	Inputs         map[string]string
	IdempotencyKey string
	Actor          Actor
}

func (client *Client) CreateCredential(ctx context.Context, input CreateCredentialRequest) (credential.Metadata, error) {
	inputs := cloneStrings(input.Inputs)
	defer clear(inputs)
	body := struct {
		OrganizationID string            `json:"organization_id"`
		Name           string            `json:"name"`
		CredentialType string            `json:"credential_type"`
		SchemaVersion  uint32            `json:"schema_version"`
		Inputs         map[string]string `json:"inputs"`
		Actor          Actor             `json:"actor"`
	}{input.OrganizationID, input.Name, input.CredentialType, input.SchemaVersion, inputs, input.Actor}
	var result credential.Metadata
	err := client.do(ctx, http.MethodPost, "/internal/v1/credentials", body, map[string]string{"Idempotency-Key": input.IdempotencyKey}, &result, http.StatusCreated)
	return result, err
}

func (client *Client) GetCredential(ctx context.Context, organizationID, credentialID string) (credential.Metadata, error) {
	var result credential.Metadata
	err := client.do(ctx, http.MethodGet, "/internal/v1/credentials/"+url.PathEscape(credentialID), nil,
		map[string]string{"X-Praetor-Organization-ID": organizationID}, &result, http.StatusOK)
	return result, err
}

type ReplaceInputsRequest struct {
	OrganizationID  string
	CredentialID    string
	ExpectedVersion uint64
	Inputs          map[string]string
	Actor           Actor
}

func (client *Client) ReplaceInputs(ctx context.Context, input ReplaceInputsRequest) (credential.Metadata, error) {
	inputs := cloneStrings(input.Inputs)
	defer clear(inputs)
	body := struct {
		ExpectedVersion uint64            `json:"expected_version"`
		Inputs          map[string]string `json:"inputs"`
		Actor           Actor             `json:"actor"`
	}{input.ExpectedVersion, inputs, input.Actor}
	var result credential.Metadata
	err := client.do(ctx, http.MethodPut, "/internal/v1/credentials/"+url.PathEscape(input.CredentialID)+"/inputs", body,
		map[string]string{"X-Praetor-Organization-ID": input.OrganizationID}, &result, http.StatusOK)
	return result, err
}

func cloneStrings(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

type UpdateMetadataRequest struct {
	OrganizationID  string
	CredentialID    string
	ExpectedVersion uint64
	Name            string
	Actor           Actor
}

func (client *Client) UpdateMetadata(ctx context.Context, input UpdateMetadataRequest) (credential.Metadata, error) {
	body := struct {
		ExpectedVersion uint64 `json:"expected_version"`
		Name            string `json:"name"`
		Actor           Actor  `json:"actor"`
	}{input.ExpectedVersion, input.Name, input.Actor}
	var result credential.Metadata
	err := client.do(ctx, http.MethodPatch, "/internal/v1/credentials/"+url.PathEscape(input.CredentialID), body,
		map[string]string{"X-Praetor-Organization-ID": input.OrganizationID}, &result, http.StatusOK)
	return result, err
}

type RetireCredentialRequest struct {
	OrganizationID  string
	CredentialID    string
	ExpectedVersion uint64
	Actor           Actor
}

func (client *Client) RetireCredential(ctx context.Context, input RetireCredentialRequest) (credential.Metadata, error) {
	body := struct {
		ExpectedVersion uint64 `json:"expected_version"`
		Actor           Actor  `json:"actor"`
	}{input.ExpectedVersion, input.Actor}
	var result credential.Metadata
	err := client.do(ctx, http.MethodPost, "/internal/v1/credentials/"+url.PathEscape(input.CredentialID)+"/retire", body,
		map[string]string{"X-Praetor-Organization-ID": input.OrganizationID}, &result, http.StatusOK)
	return result, err
}

func (client *Client) RegisterBinding(ctx context.Context, input credential.RegisterBindingRequest) (credential.Binding, error) {
	body := struct {
		RunID            string    `json:"run_id"`
		DispatchID       string    `json:"dispatch_id"`
		OrganizationID   string    `json:"organization_id"`
		CredentialID     string    `json:"credential_id"`
		ExecutorIdentity string    `json:"executor_identity"`
		NotBefore        time.Time `json:"not_before"`
		ExpiresAt        time.Time `json:"expires_at"`
		MaxResolutions   uint32    `json:"max_resolutions"`
	}{input.RunID, input.DispatchID, input.OrganizationID, input.CredentialID, input.ExecutorIdentity, input.NotBefore, input.ExpiresAt, input.MaxResolutions}
	var result credential.Binding
	err := client.do(ctx, http.MethodPost, "/internal/v1/run-bindings", body,
		map[string]string{"Idempotency-Key": input.IdempotencyKey}, &result, http.StatusCreated)
	return result, err
}

func (client *Client) CancelBinding(ctx context.Context, input credential.CancelBindingRequest) (credential.Binding, error) {
	body := struct {
		DispatchID string `json:"dispatch_id"`
		Reason     string `json:"reason"`
	}{input.DispatchID, input.Reason}
	var result credential.Binding
	err := client.do(ctx, http.MethodPost, "/internal/v1/run-bindings/"+url.PathEscape(input.RunID)+"/cancel", body, nil, &result, http.StatusOK)
	return result, err
}

func (client *Client) Resolve(ctx context.Context, input credential.ResolveRequest) (credential.ResolvedCredential, error) {
	body := struct {
		AttemptID   string    `json:"attempt_id"`
		RequestedAt time.Time `json:"requested_at"`
	}{input.AttemptID, input.RequestedAt}
	var result credential.ResolvedCredential
	err := client.do(ctx, http.MethodPost, "/internal/v1/runs/"+url.PathEscape(input.RunID)+"/credential:resolve", body, nil, &result, http.StatusOK)
	return result, err
}

func (client *Client) do(ctx context.Context, method, path string, body any, headers map[string]string, output any, expectedStatus int) error {
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return ErrConfiguration
		}
	}
	defer clear(encoded)
	request, err := http.NewRequestWithContext(ctx, method, client.base.String()+path, bytes.NewReader(encoded))
	if err != nil {
		return ErrConfiguration
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		if strings.ContainsAny(value, "\r\n") {
			return ErrConfiguration
		}
		request.Header.Set(name, value)
	}
	response, err := client.http.Do(request)
	if err != nil {
		return fmt.Errorf("secrets service unavailable: %w", err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil || len(responseBody) > maxResponseBytes {
		return &Problem{Status: response.StatusCode, Code: "invalid_response"}
	}
	defer clear(responseBody)
	if response.StatusCode != expectedStatus {
		var problem struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(responseBody, &problem) != nil || problem.Code == "" || len(problem.Code) > 128 {
			problem.Code = "request_failed"
		}
		return &Problem{Status: response.StatusCode, Code: problem.Code}
	}
	if output == nil || json.Unmarshal(responseBody, output) != nil {
		return &Problem{Status: response.StatusCode, Code: "invalid_response"}
	}
	return nil
}
