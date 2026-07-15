package transport

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/Niftel/praetor-secrets/credential"
)

func certificateWithURI(t *testing.T, value string) *x509.Certificate {
	t.Helper()
	identity, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{URIs: []*url.URL{identity}}
}

func TestSPIFFEMapper(t *testing.T) {
	mapper := SPIFFEMapper{TrustDomain: "praetor.local"}
	tests := []struct {
		name    string
		uri     string
		role    credential.WorkloadRole
		subject string
		valid   bool
	}{
		{"scheduler", "spiffe://praetor.local/workload/praetor-scheduler", credential.RoleScheduler, "praetor-scheduler", true},
		{"executor", "spiffe://praetor.local/workload/praetor-executor/worker-7", credential.RoleExecutor, "praetor-executor:worker-7", true},
		{"wrong trust domain", "spiffe://other.local/workload/praetor-scheduler", "", "", false},
		{"unknown workload", "spiffe://praetor.local/workload/praetor-api", "", "", false},
		{"executor path escape", "spiffe://praetor.local/workload/praetor-executor/..", "", "", false},
		{"executor slash", "spiffe://praetor.local/workload/praetor-executor/a/b", "", "", false},
		{"query", "spiffe://praetor.local/workload/praetor-scheduler?role=executor", "", "", false},
		{"invalid instance", "spiffe://praetor.local/workload/praetor-executor/bad%20instance", "", "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity, err := mapper.Identity(certificateWithURI(t, test.uri))
			if test.valid && (err != nil || identity.Role != test.role || identity.Subject != test.subject) {
				t.Fatalf("identity=%+v err=%v", identity, err)
			}
			if !test.valid && err == nil {
				t.Fatalf("accepted identity %+v", identity)
			}
		})
	}
	certificate := certificateWithURI(t, "spiffe://praetor.local/workload/praetor-scheduler")
	certificate.URIs = append(certificate.URIs, certificate.URIs[0])
	if _, err := mapper.Identity(certificate); err == nil {
		t.Fatal("accepted multiple URI identities")
	}
}

func TestTLSConfigRequiresVerifiedTLS13Clients(t *testing.T) {
	pool := x509.NewCertPool()
	serverCertificate := tls.Certificate{Certificate: [][]byte{{1}}}
	config, err := TLSConfig(serverCertificate, pool)
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 || config.ClientAuth != tls.RequireAndVerifyClientCert || config.ClientCAs != pool {
		t.Fatalf("unsafe TLS config: %+v", config)
	}
	if len(config.NextProtos) != 1 || config.NextProtos[0] != "http/1.1" {
		t.Fatalf("secret response isolation requires HTTP/1.1: %v", config.NextProtos)
	}
	if _, err := TLSConfig(tls.Certificate{}, pool); err == nil {
		t.Fatal("accepted missing server certificate")
	}
	if _, err := TLSConfig(serverCertificate, nil); err == nil {
		t.Fatal("accepted missing client CA")
	}
}
