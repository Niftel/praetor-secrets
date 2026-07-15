package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

func TestRuntimeBootsWithDatabaseAndMTLS(t *testing.T) {
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
	schema := fmt.Sprintf("praetor_app_%d", time.Now().UnixNano())
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
	databaseFile := writeFile(t, directory+"/database-url", []byte(databaseURL), 0o400)
	masterFile := writeFile(t, directory+"/master-key", make([]byte, 32), 0o400)
	auditFile := writeFile(t, directory+"/audit-key", make([]byte, 32), 0o400)
	caFile, serverCertFile, serverKeyFile, clientCertificate, roots := testCertificates(t, directory)
	config := Config{
		ListenAddress: "127.0.0.1:0", HealthListenAddress: "127.0.0.1:0", TrustDomain: "praetor.local",
		DatabaseURLFile: databaseFile, MasterKeyFile: masterFile, AuditKeyFile: auditFile, TLSCertificateFile: serverCertFile,
		TLSPrivateKeyFile: serverKeyFile, ClientCAFile: caFile, ShutdownTimeout: 2 * time.Second,
		AuditSinkURL: "https://audit.invalid/events", AuditSinkCAFile: caFile,
		AuditSinkCertificateFile: serverCertFile, AuditSinkPrivateKeyFile: serverKeyFile,
		MaxDatabaseConns: 2, MaxNetworkConns: 4, MaxPendingAuditEvents: 100,
		AuditDeliveryBatchSize: 10, AuditDeliveryPollInterval: time.Second, AuditDeliveryRequestTimeout: time.Second,
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
		t.Fatalf("readiness status=%v err=%v", responseStatus(response), err)
	}
	response.Body.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientCertificate}, ServerName: "localhost",
	}}}
	response, err = client.Get("https://" + mainAddress + "/internal/v1/run-bindings/32b9fc25-fd71-47e6-b0e8-45db87df9f65")
	if err != nil || response.StatusCode != http.StatusNotFound {
		cancel()
		t.Fatalf("mTLS status=%v err=%v", responseStatus(response), err)
	}
	response.Body.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func responseStatus(response *http.Response) any {
	if response == nil {
		return nil
	}
	return response.StatusCode
}

func writeFile(t *testing.T, path string, value []byte, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, value, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func testCertificates(t *testing.T, directory string) (string, string, string, tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	issue := func(serial int64, uri string, server bool) ([]byte, []byte) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if server {
			template.DNSNames = []string{"localhost"}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			parsed, parseErr := url.Parse(uri)
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
		keyDER, marshalErr := x509.MarshalPKCS8PrivateKey(key)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	serverCert, serverKey := issue(2, "", true)
	clientCert, clientKey := issue(3, "spiffe://praetor.local/workload/praetor-scheduler", false)
	clientCertificate, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	return writeFile(t, directory+"/ca.crt", caPEM, 0o444), writeFile(t, directory+"/tls.crt", serverCert, 0o444), writeFile(t, directory+"/tls.key", serverKey, 0o400), clientCertificate, roots
}
