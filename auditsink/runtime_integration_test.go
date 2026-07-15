package auditsink

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
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAuditSinkRuntimeBootsAndAppendsOverMTLS(t *testing.T) {
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
	schema := fmt.Sprintf("audit_sink_runtime_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, `CREATE SCHEMA "`+schema+`"`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.Exec(context.Background(), `DROP SCHEMA "`+schema+`" CASCADE`) }()
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	databaseURL = poolConfig.ConnString()
	directory := t.TempDir()
	caFile, certificateFile, keyFile, clientCertificate, roots := sinkTestCertificates(t, directory)
	config := Config{
		ListenAddress: "127.0.0.1:0", HealthListenAddress: "127.0.0.1:0", TrustDomain: "praetor.local",
		DatabaseURLFile:    writeSinkFile(t, directory+"/database-url", []byte(databaseURL), 0o400),
		TLSCertificateFile: certificateFile, TLSPrivateKeyFile: keyFile, ClientCAFile: caFile,
		ShutdownTimeout: 2 * time.Second, MaxDatabaseConns: 2, MaxNetworkConns: 4,
	}
	runtime, err := Build(ctx, config)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	runContext, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- runtime.Run(runContext) }()
	var mainAddress, healthAddress string
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		mainAddress, healthAddress = runtime.Addresses()
		if mainAddress != "" && healthAddress != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if mainAddress == "" {
		cancel()
		t.Fatal("listeners did not start")
	}
	response, err := http.Get("http://" + healthAddress + "/readyz")
	if err != nil || response.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("readiness response=%v err=%v", response, err)
	}
	_ = response.Body.Close()
	record := validRecord(1)
	body, _ := json.Marshal(record)
	request, _ := http.NewRequest(http.MethodPost, "https://"+mainAddress+IngestionPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", key(record))
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientCertificate}, ServerName: "localhost",
	}}}
	response, err = client.Do(request)
	if err != nil || response.StatusCode != http.StatusCreated {
		cancel()
		t.Fatalf("append response=%v err=%v", response, err)
	}
	_ = response.Body.Close()
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM "`+schema+`".remote_audit_records`).Scan(&count); err != nil || count != 1 {
		cancel()
		t.Fatalf("stored count=%d err=%v", count, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func sinkTestCertificates(t *testing.T, directory string) (string, string, string, tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "audit-test-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	issue := func(serial int64, identity string, server bool) ([]byte, []byte) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if server {
			template.DNSNames = []string{"localhost"}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			parsed, parseErr := url.Parse(identity)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			template.URIs = []*url.URL{parsed}
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, createErr := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if createErr != nil {
			t.Fatal(createErr)
		}
		keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	serverCertificate, serverKey := issue(2, "", true)
	clientPEM, clientKey := issue(3, "spiffe://praetor.local/workload/praetor-secrets", false)
	clientCertificate, err := tls.X509KeyPair(clientPEM, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	return writeSinkFile(t, directory+"/ca.crt", caPEM, 0o444), writeSinkFile(t, directory+"/tls.crt", serverCertificate, 0o444), writeSinkFile(t, directory+"/tls.key", serverKey, 0o400), clientCertificate, roots
}
