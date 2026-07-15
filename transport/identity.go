// Package transport exposes the authenticated internal HTTP boundary for the
// Praetor Secrets Service.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"strings"

	"github.com/Niftel/praetor-secrets/credential"
)

var ErrWorkloadIdentity = errors.New("unrecognized workload certificate identity")

type SPIFFEMapper struct {
	TrustDomain string
}

// Identity accepts exactly one SPIFFE URI SAN. Certificate subjects, DNS SANs,
// source addresses, and HTTP headers never contribute to authorization.
func (mapper SPIFFEMapper) Identity(certificate *x509.Certificate) (credential.WorkloadIdentity, error) {
	if certificate == nil || mapper.TrustDomain == "" || len(certificate.URIs) != 1 {
		return credential.WorkloadIdentity{}, ErrWorkloadIdentity
	}
	identity := certificate.URIs[0]
	if identity.Scheme != "spiffe" || identity.Host != mapper.TrustDomain || identity.RawQuery != "" || identity.Fragment != "" {
		return credential.WorkloadIdentity{}, ErrWorkloadIdentity
	}
	parts := strings.Split(strings.TrimPrefix(identity.EscapedPath(), "/"), "/")
	if len(parts) == 2 && parts[0] == "workload" && parts[1] == "praetor-scheduler" {
		return credential.WorkloadIdentity{Role: credential.RoleScheduler, Subject: string(credential.RoleScheduler)}, nil
	}
	if len(parts) == 3 && parts[0] == "workload" && parts[1] == "praetor-executor" {
		instance, err := url.PathUnescape(parts[2])
		if err != nil || !validInstance(instance) {
			return credential.WorkloadIdentity{}, ErrWorkloadIdentity
		}
		return credential.WorkloadIdentity{Role: credential.RoleExecutor, Subject: string(credential.RoleExecutor) + ":" + instance}, nil
	}
	return credential.WorkloadIdentity{}, ErrWorkloadIdentity
}

func validInstance(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return value != "." && value != ".."
}

func TLSConfig(serverCertificate tls.Certificate, clientCAs *x509.CertPool) (*tls.Config, error) {
	if len(serverCertificate.Certificate) == 0 || clientCAs == nil {
		return nil, ErrWorkloadIdentity
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		Certificates: []tls.Certificate{serverCertificate},
		NextProtos:   []string{"http/1.1"},
	}, nil
}
