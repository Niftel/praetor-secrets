package auditsink

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	ErrConfiguration = errors.New("invalid audit sink configuration")
	ErrStartup       = errors.New("audit sink startup failed")
	ErrServe         = errors.New("audit sink runtime failed")
)

type Config struct {
	ListenAddress       string
	HealthListenAddress string
	TrustDomain         string
	DatabaseURLFile     string
	TLSCertificateFile  string
	TLSPrivateKeyFile   string
	ClientCAFile        string
	ShutdownTimeout     time.Duration
	MaxDatabaseConns    int32
	MaxNetworkConns     int
}

func LoadConfig(lookup func(string) (string, bool)) (Config, error) {
	if lookup == nil {
		return Config{}, ErrConfiguration
	}
	required := func(name string) (string, bool) {
		value, ok := lookup(name)
		value = strings.TrimSpace(value)
		return value, ok && value != ""
	}
	var config Config
	var ok bool
	for name, target := range map[string]*string{
		"PRAETOR_AUDIT_SINK_LISTEN_ADDRESS":        &config.ListenAddress,
		"PRAETOR_AUDIT_SINK_HEALTH_LISTEN_ADDRESS": &config.HealthListenAddress,
		"PRAETOR_AUDIT_SINK_TRUST_DOMAIN":          &config.TrustDomain,
		"PRAETOR_AUDIT_SINK_DATABASE_URL_FILE":     &config.DatabaseURLFile,
		"PRAETOR_AUDIT_SINK_TLS_CERTIFICATE_FILE":  &config.TLSCertificateFile,
		"PRAETOR_AUDIT_SINK_TLS_PRIVATE_KEY_FILE":  &config.TLSPrivateKeyFile,
		"PRAETOR_AUDIT_SINK_CLIENT_CA_FILE":        &config.ClientCAFile,
	} {
		if *target, ok = required(name); !ok {
			return Config{}, ErrConfiguration
		}
	}
	config.ShutdownTimeout = 20 * time.Second
	config.MaxDatabaseConns = 10
	config.MaxNetworkConns = 100
	if value, exists := lookup("PRAETOR_AUDIT_SINK_SHUTDOWN_TIMEOUT"); exists && value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed < time.Second || parsed > 5*time.Minute {
			return Config{}, ErrConfiguration
		}
		config.ShutdownTimeout = parsed
	}
	if value, exists := lookup("PRAETOR_AUDIT_SINK_MAX_DATABASE_CONNECTIONS"); exists && value != "" {
		parsed, err := strconv.ParseInt(value, 10, 32)
		if err != nil || parsed < 1 || parsed > 100 {
			return Config{}, ErrConfiguration
		}
		config.MaxDatabaseConns = int32(parsed)
	}
	if value, exists := lookup("PRAETOR_AUDIT_SINK_MAX_NETWORK_CONNECTIONS"); exists && value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 10000 {
			return Config{}, ErrConfiguration
		}
		config.MaxNetworkConns = parsed
	}
	if err := validateConfig(config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func validateConfig(config Config) error {
	if config.DatabaseURLFile == "" || config.TLSCertificateFile == "" || config.TLSPrivateKeyFile == "" ||
		config.ClientCAFile == "" || config.ShutdownTimeout <= 0 || config.MaxDatabaseConns <= 0 ||
		config.MaxNetworkConns <= 0 || !validSinkTrustDomain(config.TrustDomain) {
		return ErrConfiguration
	}
	for _, address := range []string{config.ListenAddress, config.HealthListenAddress} {
		if _, _, err := net.SplitHostPort(address); err != nil {
			return ErrConfiguration
		}
	}
	_, port, _ := net.SplitHostPort(config.ListenAddress)
	if config.ListenAddress == config.HealthListenAddress && port != "0" {
		return ErrConfiguration
	}
	return nil
}
