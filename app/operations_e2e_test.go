package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Niftel/praetor-secrets/audit"
	"github.com/Niftel/praetor-secrets/builtin"
	"github.com/Niftel/praetor-secrets/credential"
	"github.com/Niftel/praetor-secrets/masterkey"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOperationsSurviveRestartAndValidateIsolatedRestore(t *testing.T) {
	databaseURL := os.Getenv("PRAETOR_SECRETS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PRAETOR_SECRETS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()

	sourceSchema := fmt.Sprintf("praetor_operations_%d", time.Now().UnixNano())
	restoreSchema := sourceSchema + "_restore"
	for _, schema := range []string{sourceSchema, restoreSchema} {
		if _, err := admin.Exec(ctx, `CREATE SCHEMA "`+schema+`"`); err != nil {
			t.Fatal(err)
		}
		defer func(schema string) {
			_, _ = admin.Exec(context.Background(), `DROP SCHEMA "`+schema+`" CASCADE`)
		}(schema)
	}
	sourceURL := databaseURLWithSchema(t, databaseURL, sourceSchema)
	restoreURL := databaseURLWithSchema(t, databaseURL, restoreSchema)
	sourcePool := openOperationsPool(t, sourceURL)
	defer sourcePool.Close()
	restorePool := openOperationsPool(t, restoreURL)
	defer restorePool.Close()
	for _, pool := range []*pgxpool.Pool{sourcePool, restorePool} {
		if err := credential.ApplyPostgresMigrations(ctx, pool); err != nil {
			t.Fatal(err)
		}
		if err := audit.ApplyMigration(ctx, pool); err != nil {
			t.Fatal(err)
		}
	}

	directory := t.TempDir()
	oldKey := writeFile(t, directory+"/old-master-key", bytes.Repeat([]byte{0x31}, 32), 0o400)
	newKey := writeFile(t, directory+"/new-master-key", bytes.Repeat([]byte{0x32}, 32), 0o400)
	wrongKey := writeFile(t, directory+"/wrong-master-key", bytes.Repeat([]byte{0x33}, 32), 0o400)
	seedEncryptedCredentials(t, sourcePool, oldKey)

	// This copies only encrypted service-owned rows into a separately migrated
	// schema. It is the integration-test equivalent of restoring an encrypted
	// database dump and deliberately excludes keys from the backup boundary.
	for _, table := range []string{"credentials", "credential_versions", "credential_idempotency"} {
		query := fmt.Sprintf(`INSERT INTO "%s".%s SELECT * FROM "%s".%s`, restoreSchema, table, sourceSchema, table)
		if _, err := admin.Exec(ctx, query); err != nil {
			t.Fatalf("restore encrypted table %s: %v", table, err)
		}
	}

	fixture := newOperationsTLSFixture(t, directory)
	sourceConfig := operationsConfig(t, directory+"/source", sourceURL, newKey, oldKey, fixture)
	client := fixture.client("operator")

	runtime, cancel, done := startOperationsRuntime(t, sourceConfig)
	baseURL := "https://" + runtimeAddress(t, runtime)
	proveSnapshottedCredentialLifecycle(t, fixture, baseURL)
	rotation := operationsJSON(t, client, http.MethodPost, baseURL+"/internal/v1/operations/rotations", "", http.StatusCreated)
	rotationID := stringField(t, rotation, "id")
	firstBatch := operationsJSON(t, client, http.MethodPost, baseURL+"/internal/v1/operations/rotations/"+rotationID+"/resume", `{"batch_size":1}`, http.StatusOK)
	if numberField(t, firstBatch, "processed_records") != 1 {
		t.Fatalf("first rotation batch=%v", firstBatch)
	}
	stopOperationsRuntime(t, cancel, done)

	// Rebuilding the complete runtime proves rotation progress is durable in
	// PostgreSQL rather than retained by the original service process.
	runtime, cancel, done = startOperationsRuntime(t, sourceConfig)
	baseURL = "https://" + runtimeAddress(t, runtime)
	finalBatch := operationsJSON(t, client, http.MethodPost, baseURL+"/internal/v1/operations/rotations/"+rotationID+"/resume", `{"batch_size":10}`, http.StatusOK)
	if stringField(t, finalBatch, "state") != "ready" || numberField(t, finalBatch, "processed_records") != 2 {
		t.Fatalf("resumed rotation=%v", finalBatch)
	}
	finalized := operationsJSON(t, client, http.MethodPost, baseURL+"/internal/v1/operations/rotations/"+rotationID+"/finalize", "", http.StatusOK)
	if stringField(t, finalized, "state") != "finalized" {
		t.Fatalf("finalized rotation=%v", finalized)
	}
	status := operationsJSON(t, client, http.MethodGet, baseURL+"/internal/v1/operations/key-status", "", http.StatusOK)
	if cleared, _ := status["database_references_cleared"].(bool); !cleared {
		t.Fatalf("key status did not clear old database references: %v", status)
	}
	stopOperationsRuntime(t, cancel, done)

	// The restored encrypted rows must reject an unrelated key without returning
	// plaintext, then validate successfully when the separately held backup key
	// is supplied.
	wrongConfig := operationsConfig(t, directory+"/restore-wrong", restoreURL, wrongKey, "", fixture)
	runtime, cancel, done = startOperationsRuntime(t, wrongConfig)
	wrongBody := operationsRaw(t, client, http.MethodPost, "https://"+runtimeAddress(t, runtime)+"/internal/v1/operations/recovery-validations", `{"sample_size":10}`, http.StatusConflict)
	if strings.Contains(wrongBody, "rotation-secret") || strings.Contains(wrongBody, "automation") {
		t.Fatalf("wrong-key recovery response leaked plaintext: %s", wrongBody)
	}
	stopOperationsRuntime(t, cancel, done)

	restoreConfig := operationsConfig(t, directory+"/restore-correct", restoreURL, oldKey, "", fixture)
	runtime, cancel, done = startOperationsRuntime(t, restoreConfig)
	defer stopOperationsRuntime(t, cancel, done)
	recovery := operationsJSON(t, client, http.MethodPost, "https://"+runtimeAddress(t, runtime)+"/internal/v1/operations/recovery-validations", `{"sample_size":10}`, http.StatusOK)
	if numberField(t, recovery, "total_records") != 2 || numberField(t, recovery, "validated_records") != 2 {
		t.Fatalf("recovery validation=%v", recovery)
	}
	digest := stringField(t, recovery, "metadata_sha256")
	if len(digest) != 64 || strings.Contains(digest, "rotation-secret") {
		t.Fatalf("unsafe recovery digest %q", digest)
	}
}

func databaseURLWithSchema(t *testing.T, rawURL, schema string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func openOperationsPool(t *testing.T, databaseURL string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func seedEncryptedCredentials(t *testing.T, pool *pgxpool.Pool, keyPath string) {
	t.Helper()
	keys, err := masterkey.Load(masterkey.Config{CurrentPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	registry := builtin.Registry{}
	manager, err := credential.NewPostgresManager(keys, registry, pool, registry)
	if err != nil {
		t.Fatal(err)
	}
	spool, err := audit.New(bytes.Repeat([]byte{0x44}, 32), 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RequireAuditSpool(spool); err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 2; index++ {
		ctx := audit.WithRequest(context.Background(), audit.Request{
			ID: fmt.Sprintf("seed-%d", index), WorkloadIdentity: "praetor-api",
			Operation: audit.OperationCredentialCreated, StartedAt: time.Now().UTC(),
		})
		_, err := manager.CreateContext(ctx, credential.CreateRequest{
			OrganizationID: "5", Name: fmt.Sprintf("rotation-%d", index),
			CredentialType: "machine", SchemaVersion: 1,
			Inputs:         map[string]string{"username": "automation", "password": fmt.Sprintf("rotation-secret-%d", index)},
			IdempotencyKey: fmt.Sprintf("rotation-seed-%d", index),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func proveSnapshottedCredentialLifecycle(t *testing.T, fixture operationsTLSFixture, baseURL string) {
	t.Helper()
	api := fixture.client("api")
	scheduler := fixture.client("scheduler")
	executor := fixture.client("executor")
	actor := `{"user_id":"104","username":"acceptance","authorization_decision_id":"operations-e2e"}`
	created := operationsJSONWithHeaders(t, api, http.MethodPost, baseURL+"/internal/v1/credentials",
		`{"organization_id":"5","name":"lifecycle","credential_type":"machine","schema_version":1,"inputs":{"username":"automation","password":"snapshot-old-secret"},"actor":`+actor+`}`,
		map[string]string{"Idempotency-Key": "operations-lifecycle-create"}, http.StatusCreated)
	credentialID := stringField(t, created, "id")
	persisted := operationsJSONWithHeaders(t, api, http.MethodGet, baseURL+"/internal/v1/credentials/"+credentialID,
		"", map[string]string{"X-Praetor-Organization-ID": "5"}, http.StatusOK)
	if stringField(t, persisted, "id") != credentialID {
		t.Fatalf("created credential was not durably readable: %v", persisted)
	}

	now := time.Now().UTC()
	oldRun, oldDispatch := testUUID(t), testUUID(t)
	registerBinding := func(runID, dispatchID, idempotencyKey string, status int) map[string]any {
		body, err := json.Marshal(map[string]any{
			"run_id": runID, "dispatch_id": dispatchID, "organization_id": "5",
			"credential_id": credentialID, "executor_identity": "praetor-executor:operations-1",
			"not_before": now.Add(-30 * time.Second), "expires_at": now.Add(10 * time.Minute), "max_resolutions": 2,
		})
		if err != nil {
			t.Fatal(err)
		}
		return operationsJSONWithHeaders(t, scheduler, http.MethodPost, baseURL+"/internal/v1/run-bindings",
			string(body), map[string]string{"Idempotency-Key": idempotencyKey}, status)
	}
	oldBinding := registerBinding(oldRun, oldDispatch, "operations-old-binding", http.StatusCreated)
	if numberField(t, oldBinding, "credential_version") != 1 {
		t.Fatalf("old binding did not snapshot version 1: %v", oldBinding)
	}

	replaced := operationsJSONWithHeaders(t, api, http.MethodPut, baseURL+"/internal/v1/credentials/"+credentialID+"/inputs",
		`{"expected_version":1,"inputs":{"username":"automation","password":"snapshot-new-secret"},"actor":`+actor+`}`,
		map[string]string{"X-Praetor-Organization-ID": "5"}, http.StatusOK)
	if numberField(t, replaced, "version") != 2 {
		t.Fatalf("credential replacement=%v", replaced)
	}
	oldResolution := resolveLifecycleRun(t, executor, baseURL, oldRun)
	if !strings.Contains(oldResolution, "snapshot-old-secret") || strings.Contains(oldResolution, "snapshot-new-secret") {
		t.Fatal("in-flight binding did not preserve its snapshotted credential version")
	}

	newRun, newDispatch := testUUID(t), testUUID(t)
	newBinding := registerBinding(newRun, newDispatch, "operations-new-binding", http.StatusCreated)
	if numberField(t, newBinding, "credential_version") != 2 {
		t.Fatalf("new binding did not snapshot version 2: %v", newBinding)
	}
	newResolution := resolveLifecycleRun(t, executor, baseURL, newRun)
	if !strings.Contains(newResolution, "snapshot-new-secret") || strings.Contains(newResolution, "snapshot-old-secret") {
		t.Fatal("new binding did not use the replacement credential version")
	}

	retired := operationsJSONWithHeaders(t, api, http.MethodPost, baseURL+"/internal/v1/credentials/"+credentialID+"/retire",
		`{"expected_version":2,"actor":`+actor+`}`,
		map[string]string{"X-Praetor-Organization-ID": "5"}, http.StatusOK)
	if stringField(t, retired, "state") != "retired" || numberField(t, retired, "version") != 3 {
		t.Fatalf("credential retirement=%v", retired)
	}
	rejectedRun, rejectedDispatch := testUUID(t), testUUID(t)
	registerBinding(rejectedRun, rejectedDispatch, "operations-retired-binding", http.StatusNotFound)
}

func resolveLifecycleRun(t *testing.T, client *http.Client, baseURL, runID string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"attempt_id": testUUID(t), "requested_at": time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	return operationsRaw(t, client, http.MethodPost, baseURL+"/internal/v1/runs/"+runID+"/credential:resolve", string(body), http.StatusOK)
}

func testUUID(t *testing.T) string {
	t.Helper()
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

type operationsTLSFixture struct {
	caFile, serverCertFile, serverKeyFile string
	clients                               map[string]tls.Certificate
	roots                                 *x509.CertPool
}

func newOperationsTLSFixture(t *testing.T, directory string) operationsTLSFixture {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "operations-ca"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, identity string) ([]byte, []byte) {
		key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature,
		}
		if identity != "" {
			identityURL, _ := url.Parse(identity)
			template.URIs = []*url.URL{identityURL}
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		} else {
			template.DNSNames = []string{"localhost"}
			template.IPAddresses = nil
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		der, createErr := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if createErr != nil {
			t.Fatal(createErr)
		}
		keyDER, marshalErr := x509.MarshalPKCS8PrivateKey(key)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}
	serverCert, serverKey := issue(101, "")
	identities := map[string]string{
		"operator":  "spiffe://praetor.local/workload/praetor-secrets-operator",
		"api":       "spiffe://praetor.local/workload/praetor-api",
		"scheduler": "spiffe://praetor.local/workload/praetor-scheduler",
		"executor":  "spiffe://praetor.local/workload/praetor-executor/operations-1",
	}
	clients := make(map[string]tls.Certificate, len(identities))
	serial := int64(102)
	for name, identity := range identities {
		certificate, key := issue(serial, identity)
		parsed, parseErr := tls.X509KeyPair(certificate, key)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		clients[name] = parsed
		serial++
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	return operationsTLSFixture{
		caFile:         writeFile(t, directory+"/operations-ca.crt", caPEM, 0o444),
		serverCertFile: writeFile(t, directory+"/operations-server.crt", serverCert, 0o444),
		serverKeyFile:  writeFile(t, directory+"/operations-server.key", serverKey, 0o400),
		clients:        clients, roots: roots,
	}
}

func (fixture operationsTLSFixture) client(identity string) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: fixture.roots,
		Certificates: []tls.Certificate{fixture.clients[identity]}, ServerName: "localhost",
	}}}
}

func operationsConfig(t *testing.T, directory, databaseURL, currentKey, previousKey string, fixture operationsTLSFixture) Config {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return Config{
		ListenAddress: "127.0.0.1:0", HealthListenAddress: "127.0.0.1:0", TrustDomain: "praetor.local",
		DatabaseURLFile: writeFile(t, directory+"/database-url", []byte(databaseURL), 0o400),
		MasterKeyFile:   currentKey, PreviousKeyFile: previousKey,
		AuditKeyFile:       writeFile(t, directory+"/audit-key", bytes.Repeat([]byte{0x44}, 32), 0o400),
		TLSCertificateFile: fixture.serverCertFile, TLSPrivateKeyFile: fixture.serverKeyFile, ClientCAFile: fixture.caFile,
		AuditSinkURL: "https://audit.invalid/events", AuditSinkCAFile: fixture.caFile,
		AuditSinkCertificateFile: fixture.serverCertFile, AuditSinkPrivateKeyFile: fixture.serverKeyFile,
		ShutdownTimeout: 2 * time.Second, MaxDatabaseConns: 3, MaxNetworkConns: 5, MaxPendingAuditEvents: 1000,
		AuditDeliveryBatchSize: 10, AuditDeliveryPollInterval: time.Second, AuditDeliveryRequestTimeout: time.Second,
	}
}

func startOperationsRuntime(t *testing.T, config Config) (*Runtime, context.CancelFunc, <-chan error) {
	t.Helper()
	runtime, err := Build(context.Background(), config)
	if err != nil {
		t.Fatalf("build operations runtime: %v", err)
	}
	runContext, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(runContext) }()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		_, healthAddress := runtime.Addresses()
		if healthAddress != "" {
			response, requestErr := http.Get("http://" + healthAddress + "/readyz")
			if requestErr == nil {
				response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return runtime, cancel, done
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	t.Fatal("operations runtime did not become ready")
	return runtime, cancel, done
}

func runtimeAddress(t *testing.T, runtime *Runtime) string {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		address, _ := runtime.Addresses()
		if address != "" {
			return address
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("operations runtime listener did not start")
	return ""
}

func stopOperationsRuntime(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stop operations runtime: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("operations runtime did not stop")
	}
}

func operationsJSON(t *testing.T, client *http.Client, method, endpoint, body string, status int) map[string]any {
	t.Helper()
	return operationsJSONWithHeaders(t, client, method, endpoint, body, nil, status)
}

func operationsJSONWithHeaders(t *testing.T, client *http.Client, method, endpoint, body string, headers map[string]string, status int) map[string]any {
	t.Helper()
	raw := operationsRawWithHeaders(t, client, method, endpoint, body, headers, status)
	var result map[string]any
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("decode operations response %q: %v", raw, err)
	}
	return result
}

func operationsRaw(t *testing.T, client *http.Client, method, endpoint, body string, status int) string {
	t.Helper()
	return operationsRawWithHeaders(t, client, method, endpoint, body, nil, status)
}

func operationsRawWithHeaders(t *testing.T, client *http.Client, method, endpoint, body string, headers map[string]string, status int) string {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var value bytes.Buffer
	_, _ = value.ReadFrom(response.Body)
	if response.StatusCode != status {
		t.Fatalf("%s %s status=%d body=%s", method, endpoint, response.StatusCode, value.String())
	}
	return value.String()
}

func stringField(t *testing.T, value map[string]any, name string) string {
	t.Helper()
	field, ok := value[name].(string)
	if !ok || field == "" {
		t.Fatalf("missing string field %q in %v", name, value)
	}
	return field
}

func numberField(t *testing.T, value map[string]any, name string) int {
	t.Helper()
	field, ok := value[name].(float64)
	if !ok {
		t.Fatalf("missing number field %q in %v", name, value)
	}
	return int(field)
}
