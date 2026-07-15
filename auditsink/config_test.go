package auditsink

import (
	"errors"
	"testing"
	"time"
)

func validConfigValues() map[string]string {
	return map[string]string{
		"PRAETOR_AUDIT_SINK_LISTEN_ADDRESS":           "127.0.0.1:8444",
		"PRAETOR_AUDIT_SINK_HEALTH_LISTEN_ADDRESS":    "127.0.0.1:8082",
		"PRAETOR_AUDIT_SINK_TRUST_DOMAIN":             "praetor.local",
		"PRAETOR_AUDIT_SINK_DATABASE_URL_FILE":        "/restricted/database-url",
		"PRAETOR_AUDIT_SINK_TLS_CERTIFICATE_FILE":     "/restricted/tls.crt",
		"PRAETOR_AUDIT_SINK_TLS_PRIVATE_KEY_FILE":     "/restricted/tls.key",
		"PRAETOR_AUDIT_SINK_CLIENT_CA_FILE":           "/restricted/ca.crt",
		"PRAETOR_AUDIT_SINK_SHUTDOWN_TIMEOUT":         "5s",
		"PRAETOR_AUDIT_SINK_MAX_DATABASE_CONNECTIONS": "4",
		"PRAETOR_AUDIT_SINK_MAX_NETWORK_CONNECTIONS":  "20",
	}
}

func TestLoadConfig(t *testing.T) {
	values := validConfigValues()
	config, err := LoadConfig(func(name string) (string, bool) { value, ok := values[name]; return value, ok })
	if err != nil || config.ShutdownTimeout != 5*time.Second || config.MaxDatabaseConns != 4 || config.MaxNetworkConns != 20 {
		t.Fatalf("config=%+v err=%v", config, err)
	}
	delete(values, "PRAETOR_AUDIT_SINK_CLIENT_CA_FILE")
	if _, err := LoadConfig(func(name string) (string, bool) { value, ok := values[name]; return value, ok }); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("missing value error=%v", err)
	}
}

func TestLoadConfigRejectsInvalidLimitsAndTrustBoundaries(t *testing.T) {
	for name, value := range map[string]string{
		"PRAETOR_AUDIT_SINK_SHUTDOWN_TIMEOUT":         "0s",
		"PRAETOR_AUDIT_SINK_MAX_DATABASE_CONNECTIONS": "101",
		"PRAETOR_AUDIT_SINK_MAX_NETWORK_CONNECTIONS":  "0",
		"PRAETOR_AUDIT_SINK_TRUST_DOMAIN":             "Bad/Domain",
		"PRAETOR_AUDIT_SINK_LISTEN_ADDRESS":           "not-an-address",
	} {
		t.Run(name, func(t *testing.T) {
			values := validConfigValues()
			values[name] = value
			if _, err := LoadConfig(func(name string) (string, bool) { item, ok := values[name]; return item, ok }); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("value=%q error=%v", value, err)
			}
		})
	}
	values := validConfigValues()
	values["PRAETOR_AUDIT_SINK_HEALTH_LISTEN_ADDRESS"] = values["PRAETOR_AUDIT_SINK_LISTEN_ADDRESS"]
	if _, err := LoadConfig(func(name string) (string, bool) { value, ok := values[name]; return value, ok }); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("shared listener error=%v", err)
	}
	if _, err := LoadConfig(nil); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("nil lookup error=%v", err)
	}
}
