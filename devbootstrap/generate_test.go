package devbootstrap

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestGenerateCreatesRestrictedInteroperableBootstrap(t *testing.T) {
	root := t.TempDir()
	secretsURL := restrictedInput(t, root+"/secrets-url", "postgres://secrets:password@postgres:5432/secrets?sslmode=disable")
	auditURL := restrictedInput(t, root+"/audit-url", "postgres://audit:password@postgres:5432/audit?sslmode=disable")
	output := root + "/generated"
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	err := Generate(Config{OutputDirectory: output, Namespace: "security", TrustDomain: "praetor.local", SecretsDatabaseURLFile: secretsURL, AuditDatabaseURLFile: auditURL, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{
		"praetor-secrets-runtime/database-url", "praetor-secrets-runtime/master-key", "praetor-secrets-runtime/audit-key",
		"praetor-secrets-server/tls.crt", "praetor-secrets-server/tls.key", "praetor-secrets-server/ca.crt",
		"praetor-secrets-audit-client/tls.crt", "praetor-secrets-audit-client/tls.key", "praetor-secrets-audit-client/ca.crt",
		"praetor-audit-runtime/database-url", "praetor-audit-server/tls.crt", "praetor-audit-server/tls.key", "praetor-audit-server/ca.crt",
		"clients/praetor-api/tls.crt", "clients/praetor-api/tls.key", "clients/praetor-api/ca.crt",
		"clients/praetor-scheduler/tls.crt", "clients/praetor-scheduler/claim.crt", "clients/praetor-scheduler/claim.key", "clients/praetor-scheduler/executor-ca.crt",
		"clients/praetor-executor/tls.crt", "clients/praetor-executor/secrets-ca.crt",
		"clients/praetor-secrets-operator/tls.crt", "clients/praetor-secrets-auditor/tls.crt",
		"kubectl-secrets.sh", ".gitignore",
	}
	for _, relative := range paths {
		info, statErr := os.Stat(filepath.Join(output, relative))
		if statErr != nil || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("path=%s mode=%v err=%v", relative, infoMode(info), statErr)
		}
	}
	if value, _ := os.ReadFile(filepath.Join(output, "praetor-secrets-runtime/master-key")); len(value) != 32 {
		t.Fatalf("master key length=%d", len(value))
	}
	if value, _ := os.ReadFile(filepath.Join(output, "praetor-secrets-runtime/audit-key")); len(value) != 32 {
		t.Fatalf("audit key length=%d", len(value))
	}
	client := readCertificate(t, filepath.Join(output, "praetor-secrets-audit-client/tls.crt"))
	if len(client.URIs) != 1 || client.URIs[0].String() != "spiffe://praetor.local/workload/praetor-secrets" || !slices.Contains(client.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		t.Fatalf("client identity=%v usages=%v", client.URIs, client.ExtKeyUsage)
	}
	apiClient := readCertificate(t, filepath.Join(output, "clients/praetor-api/tls.crt"))
	if len(apiClient.URIs) != 1 || apiClient.URIs[0].String() != "spiffe://praetor.local/workload/praetor-api" {
		t.Fatalf("API client identity=%v", apiClient.URIs)
	}
	executorClient := readCertificate(t, filepath.Join(output, "clients/praetor-executor/tls.crt"))
	if len(executorClient.URIs) != 1 || executorClient.URIs[0].String() != "spiffe://praetor.local/workload/praetor-executor/development-1" {
		t.Fatalf("executor identity=%v", executorClient.URIs)
	}
	claimServer := readCertificate(t, filepath.Join(output, "clients/praetor-scheduler/claim.crt"))
	if !slices.Contains(claimServer.DNSNames, "praetor-scheduler.security.svc") || !slices.Contains(claimServer.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatalf("claim server DNS names=%v usages=%v", claimServer.DNSNames, claimServer.ExtKeyUsage)
	}
	workloadRoots := x509.NewCertPool()
	workloadCA, _ := os.ReadFile(filepath.Join(output, "clients/praetor-scheduler/executor-ca.crt"))
	workloadRoots.AppendCertsFromPEM(workloadCA)
	if _, err := executorClient.Verify(x509.VerifyOptions{Roots: workloadRoots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
		t.Fatalf("executor chain: %v", err)
	}
	if _, err := claimServer.Verify(x509.VerifyOptions{Roots: workloadRoots, DNSName: "praetor-scheduler.security.svc", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: now}); err != nil {
		t.Fatalf("claim server chain: %v", err)
	}
	sink := readCertificate(t, filepath.Join(output, "praetor-audit-server/tls.crt"))
	for _, expected := range []string{"praetor-audit-sink", "praetor-audit-sink.security.svc", "praetor-audit-sink.security.svc.cluster.local"} {
		if !slices.Contains(sink.DNSNames, expected) {
			t.Fatalf("missing sink DNS name %q from %v", expected, sink.DNSNames)
		}
	}
	clientRoots := x509.NewCertPool()
	clientCA, _ := os.ReadFile(filepath.Join(output, "praetor-audit-server/ca.crt"))
	clientRoots.AppendCertsFromPEM(clientCA)
	if _, err := client.Verify(x509.VerifyOptions{Roots: clientRoots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
		t.Fatalf("client chain: %v", err)
	}
	serverRoots := x509.NewCertPool()
	serverCA, _ := os.ReadFile(filepath.Join(output, "praetor-secrets-audit-client/ca.crt"))
	serverRoots.AppendCertsFromPEM(serverCA)
	if _, err := sink.Verify(x509.VerifyOptions{Roots: serverRoots, DNSName: "praetor-audit-sink.security.svc", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: now}); err != nil {
		t.Fatalf("server chain: %v", err)
	}
	script, _ := os.ReadFile(filepath.Join(output, "kubectl-secrets.sh"))
	if strings.Contains(string(script), "password") || !strings.Contains(string(script), `namespace="security"`) {
		t.Fatalf("unsafe or invalid kubectl script: %s", script)
	}
}

func TestGenerateRejectsUnsafeInputsAndOverwrite(t *testing.T) {
	root := t.TempDir()
	validURL := restrictedInput(t, root+"/url", "postgres://user:password@localhost/database")
	base := Config{OutputDirectory: root + "/output", Namespace: "security", TrustDomain: "praetor.local", SecretsDatabaseURLFile: validURL, AuditDatabaseURLFile: validURL}
	if err := Generate(base); err != nil {
		t.Fatal(err)
	}
	if err := Generate(base); !errors.Is(err, ErrInvalid) {
		t.Fatalf("overwrite error=%v", err)
	}
	for _, test := range []Config{
		{OutputDirectory: root + "/bad-namespace", Namespace: "Bad/Namespace", TrustDomain: "praetor.local", SecretsDatabaseURLFile: validURL, AuditDatabaseURLFile: validURL},
		{OutputDirectory: root + "/bad-domain", Namespace: "security", TrustDomain: "Bad Domain", SecretsDatabaseURLFile: validURL, AuditDatabaseURLFile: validURL},
		{OutputDirectory: root + "/missing-url", Namespace: "security", TrustDomain: "praetor.local", SecretsDatabaseURLFile: root + "/missing", AuditDatabaseURLFile: validURL},
	} {
		if err := Generate(test); !errors.Is(err, ErrInvalid) {
			t.Fatalf("config=%+v error=%v", test, err)
		}
	}
	publicURL := restrictedInput(t, root+"/public-url", "postgres://user:password@localhost/database")
	if err := os.Chmod(publicURL, 0o644); err != nil {
		t.Fatal(err)
	}
	base.OutputDirectory = root + "/public-output"
	base.SecretsDatabaseURLFile = publicURL
	if err := Generate(base); !errors.Is(err, ErrInvalid) {
		t.Fatalf("public URL file error=%v", err)
	}
}

func TestValidationAndFileFailureEdges(t *testing.T) {
	for _, value := range []string{"", "UPPER", "-start.local", "end-.local", "two..labels", strings.Repeat("a", 64) + ".local", "bad_name"} {
		if validDNSName(value) {
			t.Fatalf("invalid DNS name accepted: %q", value)
		}
	}
	root := t.TempDir()
	for name, value := range map[string]string{"scheme": "https://localhost/database", "empty": "  ", "nul": "postgres://localhost/data\x00base"} {
		path := restrictedInput(t, root+"/"+name, value)
		if _, err := readDatabaseURL(path); !errors.Is(err, ErrInvalid) {
			t.Fatalf("value=%q error=%v", value, err)
		}
	}
	oversized := restrictedInput(t, root+"/oversized", "postgres://localhost/"+strings.Repeat("x", 4096))
	if _, err := readDatabaseURL(oversized); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized URL error=%v", err)
	}
	blockingFile := restrictedInput(t, root+"/blocking", "value")
	if err := writeRestricted(blockingFile+"/child", []byte("value")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("blocked directory error=%v", err)
	}
	if _, _, err := issue(certificateAuthority{}, time.Now(), nil, "%"); err == nil {
		t.Fatal("invalid client URI accepted")
	}
}

func restrictedInput(t *testing.T, path, value string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(value)
	if block == nil {
		t.Fatal("certificate PEM missing")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func infoMode(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode()
}
