package app

import (
	"errors"
	"testing"
	"time"
)

func validEnvironment() map[string]string {
	return map[string]string{
		"PRAETOR_SECRETS_LISTEN_ADDRESS":        "127.0.0.1:8443",
		"PRAETOR_SECRETS_HEALTH_LISTEN_ADDRESS": "127.0.0.1:8081",
		"PRAETOR_SECRETS_TRUST_DOMAIN":          "praetor.local",
		"PRAETOR_SECRETS_DATABASE_URL_FILE":     "/run/secrets/database-url",
		"PRAETOR_SECRETS_MASTER_KEY_FILE":       "/run/secrets/master-key",
		"PRAETOR_SECRETS_AUDIT_KEY_FILE":        "/run/secrets/audit-key",
		"PRAETOR_SECRETS_TLS_CERTIFICATE_FILE":  "/run/tls/tls.crt",
		"PRAETOR_SECRETS_TLS_PRIVATE_KEY_FILE":  "/run/tls/tls.key",
		"PRAETOR_SECRETS_CLIENT_CA_FILE":        "/run/tls/ca.crt",
	}
}

func loadMap(values map[string]string) (Config, error) {
	return LoadConfig(func(name string) (string, bool) { value, ok := values[name]; return value, ok })
}

func TestLoadConfigDefaultsAndOverrides(t *testing.T) {
	values := validEnvironment()
	config, err := loadMap(values)
	if err != nil || config.ShutdownTimeout != 20*time.Second || config.MaxDatabaseConns != 10 || config.MaxNetworkConns != 100 {
		t.Fatalf("config=%+v err=%v", config, err)
	}
	values["PRAETOR_SECRETS_SHUTDOWN_TIMEOUT"] = "45s"
	values["PRAETOR_SECRETS_MAX_DATABASE_CONNECTIONS"] = "20"
	values["PRAETOR_SECRETS_MAX_NETWORK_CONNECTIONS"] = "250"
	values["PRAETOR_SECRETS_MAX_PENDING_AUDIT_EVENTS"] = "2500"
	config, err = loadMap(values)
	if err != nil || config.ShutdownTimeout != 45*time.Second || config.MaxDatabaseConns != 20 || config.MaxNetworkConns != 250 || config.MaxPendingAuditEvents != 2500 {
		t.Fatalf("overridden config=%+v err=%v", config, err)
	}
}

func TestLoadConfigRejectsMissingAndUnsafeValues(t *testing.T) {
	for _, name := range []string{
		"PRAETOR_SECRETS_LISTEN_ADDRESS", "PRAETOR_SECRETS_HEALTH_LISTEN_ADDRESS",
		"PRAETOR_SECRETS_TRUST_DOMAIN", "PRAETOR_SECRETS_DATABASE_URL_FILE",
		"PRAETOR_SECRETS_MASTER_KEY_FILE", "PRAETOR_SECRETS_TLS_CERTIFICATE_FILE",
		"PRAETOR_SECRETS_AUDIT_KEY_FILE",
		"PRAETOR_SECRETS_TLS_PRIVATE_KEY_FILE", "PRAETOR_SECRETS_CLIENT_CA_FILE",
	} {
		t.Run(name, func(t *testing.T) {
			values := validEnvironment()
			delete(values, name)
			if _, err := loadMap(values); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	invalid := []struct{ name, value string }{
		{"PRAETOR_SECRETS_LISTEN_ADDRESS", "not-an-address"},
		{"PRAETOR_SECRETS_TRUST_DOMAIN", "Bad.Domain"},
		{"PRAETOR_SECRETS_TRUST_DOMAIN", "bad/domain"},
		{"PRAETOR_SECRETS_SHUTDOWN_TIMEOUT", "999ms"},
		{"PRAETOR_SECRETS_MAX_DATABASE_CONNECTIONS", "0"},
		{"PRAETOR_SECRETS_MAX_NETWORK_CONNECTIONS", "10001"},
		{"PRAETOR_SECRETS_MAX_PENDING_AUDIT_EVENTS", "0"},
	}
	for _, test := range invalid {
		t.Run(test.name+test.value, func(t *testing.T) {
			values := validEnvironment()
			values[test.name] = test.value
			if _, err := loadMap(values); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	values := validEnvironment()
	values["PRAETOR_SECRETS_HEALTH_LISTEN_ADDRESS"] = values["PRAETOR_SECRETS_LISTEN_ADDRESS"]
	if _, err := loadMap(values); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("duplicate listeners: %v", err)
	}
	if _, err := LoadConfig(nil); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("nil lookup: %v", err)
	}
}

func TestValidTrustDomain(t *testing.T) {
	for _, value := range []string{"praetor.local", "test-1.internal", "a"} {
		if !validTrustDomain(value) {
			t.Fatalf("valid domain rejected: %q", value)
		}
	}
	for _, value := range []string{"", "-bad.local", "bad-.local", "bad..local", "bad_local"} {
		if validTrustDomain(value) {
			t.Fatalf("invalid domain accepted: %q", value)
		}
	}
}
