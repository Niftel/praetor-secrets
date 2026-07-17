package devbootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrInvalid = errors.New("invalid development bootstrap configuration")

type Config struct {
	OutputDirectory        string
	Namespace              string
	TrustDomain            string
	SchedulerServiceName   string
	SecretsDatabaseURLFile string
	AuditDatabaseURLFile   string
	Now                    func() time.Time
}

func Generate(config Config) error {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.SchedulerServiceName == "" {
		config.SchedulerServiceName = "praetor-scheduler"
	}
	if !validDNSName(config.Namespace) || !validDNSName(config.TrustDomain) || config.OutputDirectory == "" ||
		!validDNSName(config.SchedulerServiceName) || config.SecretsDatabaseURLFile == "" || config.AuditDatabaseURLFile == "" {
		return ErrInvalid
	}
	if _, err := os.Stat(config.OutputDirectory); !errors.Is(err, os.ErrNotExist) {
		return ErrInvalid
	}
	secretsDatabaseURL, err := readDatabaseURL(config.SecretsDatabaseURLFile)
	if err != nil {
		return err
	}
	auditDatabaseURL, err := readDatabaseURL(config.AuditDatabaseURLFile)
	if err != nil {
		return err
	}
	defer clear(secretsDatabaseURL)
	defer clear(auditDatabaseURL)
	if err := os.MkdirAll(config.OutputDirectory, 0o700); err != nil {
		return ErrInvalid
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = os.RemoveAll(config.OutputDirectory)
		}
	}()
	now := config.Now().UTC()
	workloadCA, err := newCA("praetor-development-workload-ca", now)
	if err != nil {
		return ErrInvalid
	}
	auditServerCA, err := newCA("praetor-development-audit-server-ca", now)
	if err != nil {
		return ErrInvalid
	}
	auditClientCA, err := newCA("praetor-development-audit-client-ca", now)
	if err != nil {
		return ErrInvalid
	}
	secretsServer, secretsServerKey, err := issueServer(workloadCA, "praetor-secrets", config.Namespace, now)
	if err != nil {
		return ErrInvalid
	}
	claimServer, claimServerKey, err := issueServer(workloadCA, config.SchedulerServiceName, config.Namespace, now)
	if err != nil {
		return ErrInvalid
	}
	auditServer, auditServerKey, err := issueServer(auditServerCA, "praetor-audit-sink", config.Namespace, now)
	if err != nil {
		return ErrInvalid
	}
	auditClient, auditClientKey, err := issueClient(auditClientCA, "spiffe://"+config.TrustDomain+"/workload/praetor-secrets", now)
	if err != nil {
		return ErrInvalid
	}
	workloadClients := map[string]string{
		"praetor-api":              "spiffe://" + config.TrustDomain + "/workload/praetor-api",
		"praetor-scheduler":        "spiffe://" + config.TrustDomain + "/workload/praetor-scheduler",
		"praetor-executor":         "spiffe://" + config.TrustDomain + "/workload/praetor-executor/development-1",
		"praetor-secrets-operator": "spiffe://" + config.TrustDomain + "/workload/praetor-secrets-operator",
		"praetor-secrets-auditor":  "spiffe://" + config.TrustDomain + "/workload/praetor-secrets-auditor",
	}
	masterKey := make([]byte, 32)
	auditKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return ErrInvalid
	}
	if _, err := rand.Read(auditKey); err != nil {
		clear(masterKey)
		return ErrInvalid
	}
	defer clear(masterKey)
	defer clear(auditKey)
	files := map[string][]byte{
		"praetor-secrets-runtime/database-url":      secretsDatabaseURL,
		"praetor-secrets-runtime/master-key":        masterKey,
		"praetor-secrets-runtime/audit-key":         auditKey,
		"praetor-secrets-server/tls.crt":            secretsServer,
		"praetor-secrets-server/tls.key":            secretsServerKey,
		"praetor-secrets-server/ca.crt":             workloadCA.certificatePEM,
		"clients/praetor-scheduler/claim.crt":       claimServer,
		"clients/praetor-scheduler/claim.key":       claimServerKey,
		"clients/praetor-scheduler/executor-ca.crt": workloadCA.certificatePEM,
		"clients/praetor-executor/secrets-ca.crt":   workloadCA.certificatePEM,
		"praetor-secrets-audit-client/tls.crt":      auditClient,
		"praetor-secrets-audit-client/tls.key":      auditClientKey,
		"praetor-secrets-audit-client/ca.crt":       auditServerCA.certificatePEM,
		"praetor-audit-runtime/database-url":        auditDatabaseURL,
		"praetor-audit-server/tls.crt":              auditServer,
		"praetor-audit-server/tls.key":              auditServerKey,
		"praetor-audit-server/ca.crt":               auditClientCA.certificatePEM,
	}
	for name, identity := range workloadClients {
		certificate, key, err := issueClient(workloadCA, identity, now)
		if err != nil {
			return ErrInvalid
		}
		files["clients/"+name+"/tls.crt"] = certificate
		files["clients/"+name+"/tls.key"] = key
		files["clients/"+name+"/ca.crt"] = workloadCA.certificatePEM
	}
	for relative, value := range files {
		if err := writeRestricted(filepath.Join(config.OutputDirectory, relative), value); err != nil {
			return err
		}
	}
	if err := writeRestricted(filepath.Join(config.OutputDirectory, "kubectl-secrets.sh"), []byte(kubectlScript(config.Namespace))); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(config.OutputDirectory, "kubectl-secrets.sh"), 0o700); err != nil {
		return ErrInvalid
	}
	if err := writeRestricted(filepath.Join(config.OutputDirectory, ".gitignore"), []byte("*\n!.gitignore\n")); err != nil {
		return err
	}
	succeeded = true
	return nil
}

type certificateAuthority struct {
	certificate    *x509.Certificate
	privateKey     *ecdsa.PrivateKey
	certificatePEM []byte
}

func newCA(name string, now time.Time) (certificateAuthority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return certificateAuthority{}, err
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(30 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return certificateAuthority{}, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return certificateAuthority{}, err
	}
	return certificateAuthority{certificate: certificate, privateKey: key, certificatePEM: certificatePEM(der)}, nil
}

func issueServer(ca certificateAuthority, service, namespace string, now time.Time) ([]byte, []byte, error) {
	return issue(ca, now, []string{service, service + "." + namespace, service + "." + namespace + ".svc", service + "." + namespace + ".svc.cluster.local"}, "")
}

func issueClient(ca certificateAuthority, identity string, now time.Time) ([]byte, []byte, error) {
	return issue(ca, now, nil, identity)
}

func issue(ca certificateAuthority, now time.Time, dnsNames []string, identity string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: randomSerial(), NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(7 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: dnsNames}
	if identity == "" {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		parsed, err := url.Parse(identity)
		if err != nil {
			return nil, nil, err
		}
		template.URIs = []*url.URL{parsed}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.privateKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return certificatePEM(der), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil || serial.Sign() == 0 {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}

func certificatePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func readDatabaseURL(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 4096 {
		return nil, ErrInvalid
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrInvalid
	}
	trimmed := strings.TrimSpace(string(value))
	clear(value)
	parsed, err := url.Parse(trimmed)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" || strings.ContainsRune(trimmed, '\x00') {
		return nil, ErrInvalid
	}
	return []byte(trimmed), nil
}

func writeRestricted(path string, value []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return ErrInvalid
	}
	if err := os.WriteFile(path, value, 0o600); err != nil {
		return ErrInvalid
	}
	return nil
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
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

func kubectlScript(namespace string) string {
	return fmt.Sprintf(`#!/bin/sh
set -eu
root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
namespace=%q
kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$namespace" create secret generic praetor-secrets-runtime --from-file="$root/praetor-secrets-runtime" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$namespace" create secret generic praetor-secrets-server --from-file="$root/praetor-secrets-server" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$namespace" create secret generic praetor-secrets-audit-client --from-file="$root/praetor-secrets-audit-client" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$namespace" create secret generic praetor-audit-runtime --from-file="$root/praetor-audit-runtime" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$namespace" create secret generic praetor-audit-server --from-file="$root/praetor-audit-server" --dry-run=client -o yaml | kubectl apply -f -
`, namespace)
}
