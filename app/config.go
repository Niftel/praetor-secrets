package app

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	ErrConfiguration = errors.New("invalid service configuration")
	ErrStartup       = errors.New("service startup failed")
	ErrServe         = errors.New("service runtime failed")
)

type Config struct {
	ListenAddress         string
	HealthListenAddress   string
	TrustDomain           string
	DatabaseURLFile       string
	MasterKeyFile         string
	AuditKeyFile          string
	PreviousKeyFile       string
	TLSCertificateFile    string
	TLSPrivateKeyFile     string
	ClientCAFile          string
	ShutdownTimeout       time.Duration
	MaxDatabaseConns      int32
	MaxNetworkConns       int
	MaxPendingAuditEvents int64
}

func LoadConfig(lookup func(string) (string, bool)) (Config, error) {
	if lookup == nil {
		return Config{}, ErrConfiguration
	}
	required := func(name string) (string, bool) {
		value, ok := lookup(name)
		return strings.TrimSpace(value), ok && strings.TrimSpace(value) != ""
	}
	var config Config
	var ok bool
	if config.ListenAddress, ok = required("PRAETOR_SECRETS_LISTEN_ADDRESS"); !ok {
		return Config{}, ErrConfiguration
	}
	if config.HealthListenAddress, ok = required("PRAETOR_SECRETS_HEALTH_LISTEN_ADDRESS"); !ok {
		return Config{}, ErrConfiguration
	}
	if config.TrustDomain, ok = required("PRAETOR_SECRETS_TRUST_DOMAIN"); !ok {
		return Config{}, ErrConfiguration
	}
	if config.DatabaseURLFile, ok = required("PRAETOR_SECRETS_DATABASE_URL_FILE"); !ok {
		return Config{}, ErrConfiguration
	}
	if config.MasterKeyFile, ok = required("PRAETOR_SECRETS_MASTER_KEY_FILE"); !ok {
		return Config{}, ErrConfiguration
	}
	if config.AuditKeyFile, ok = required("PRAETOR_SECRETS_AUDIT_KEY_FILE"); !ok {
		return Config{}, ErrConfiguration
	}
	config.PreviousKeyFile, _ = lookup("PRAETOR_SECRETS_PREVIOUS_KEY_FILE")
	if config.TLSCertificateFile, ok = required("PRAETOR_SECRETS_TLS_CERTIFICATE_FILE"); !ok {
		return Config{}, ErrConfiguration
	}
	if config.TLSPrivateKeyFile, ok = required("PRAETOR_SECRETS_TLS_PRIVATE_KEY_FILE"); !ok {
		return Config{}, ErrConfiguration
	}
	if config.ClientCAFile, ok = required("PRAETOR_SECRETS_CLIENT_CA_FILE"); !ok {
		return Config{}, ErrConfiguration
	}
	config.ShutdownTimeout = 20 * time.Second
	config.MaxDatabaseConns = 10
	config.MaxNetworkConns = 100
	config.MaxPendingAuditEvents = 100000
	if value, exists := lookup("PRAETOR_SECRETS_SHUTDOWN_TIMEOUT"); exists && value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil || duration < time.Second || duration > 5*time.Minute {
			return Config{}, ErrConfiguration
		}
		config.ShutdownTimeout = duration
	}
	if value, exists := lookup("PRAETOR_SECRETS_MAX_DATABASE_CONNECTIONS"); exists && value != "" {
		parsed, err := strconv.ParseInt(value, 10, 32)
		if err != nil || parsed < 1 || parsed > 100 {
			return Config{}, ErrConfiguration
		}
		config.MaxDatabaseConns = int32(parsed)
	}
	if value, exists := lookup("PRAETOR_SECRETS_MAX_NETWORK_CONNECTIONS"); exists && value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 10000 {
			return Config{}, ErrConfiguration
		}
		config.MaxNetworkConns = parsed
	}
	if value, exists := lookup("PRAETOR_SECRETS_MAX_PENDING_AUDIT_EVENTS"); exists && value != "" {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsed < 1 || parsed > 10000000 {
			return Config{}, ErrConfiguration
		}
		config.MaxPendingAuditEvents = parsed
	}
	if err := validateConfig(config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func validateConfig(config Config) error {
	if config.DatabaseURLFile == "" || config.MasterKeyFile == "" || config.AuditKeyFile == "" || config.TLSCertificateFile == "" ||
		config.TLSPrivateKeyFile == "" || config.ClientCAFile == "" || config.ShutdownTimeout <= 0 ||
		config.MaxDatabaseConns <= 0 || config.MaxNetworkConns <= 0 || config.MaxPendingAuditEvents <= 0 {
		return ErrConfiguration
	}
	for _, address := range []string{config.ListenAddress, config.HealthListenAddress} {
		if _, _, err := net.SplitHostPort(address); err != nil {
			return ErrConfiguration
		}
	}
	// Port zero asks the kernel for two distinct ephemeral ports and is useful for
	// isolated tests. Fixed addresses must never collapse the health and secret API
	// trust boundaries onto one listener.
	_, mainPort, _ := net.SplitHostPort(config.ListenAddress)
	if config.ListenAddress == config.HealthListenAddress && mainPort != "0" || !validTrustDomain(config.TrustDomain) {
		return ErrConfiguration
	}
	return nil
}

func validTrustDomain(value string) bool {
	if value == "" || len(value) > 253 || strings.ToLower(value) != value || strings.ContainsAny(value, "/:@ \t\r\n") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
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
