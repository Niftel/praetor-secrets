package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Niftel/praetor-secrets/audit"
	"github.com/Niftel/praetor-secrets/builtin"
	"github.com/Niftel/praetor-secrets/credential"
	"github.com/Niftel/praetor-secrets/masterkey"
	"github.com/Niftel/praetor-secrets/transport"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maxDatabaseURLBytes = 4096
	maxCertificateBytes = 1 << 20
)

type Runtime struct {
	config        Config
	pool          *pgxpool.Pool
	mainServer    *http.Server
	healthServer  *http.Server
	ready         atomic.Bool
	addressMu     sync.RWMutex
	mainAddress   string
	healthAddress string
	auditWorker   *audit.DeliveryWorker
}

func Build(ctx context.Context, config Config) (*Runtime, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	keys, err := masterkey.Load(masterkey.Config{CurrentPath: config.MasterKeyFile, PreviousPath: strings.TrimSpace(config.PreviousKeyFile)})
	if err != nil {
		return nil, ErrStartup
	}
	auditKey, err := audit.LoadKey(config.AuditKeyFile)
	if err != nil {
		return nil, ErrStartup
	}
	auditSpool, err := audit.New(auditKey, config.MaxPendingAuditEvents)
	clear(auditKey)
	if err != nil {
		return nil, ErrStartup
	}
	databaseURL, err := readRestrictedText(config.DatabaseURLFile, maxDatabaseURLBytes)
	if err != nil {
		return nil, ErrStartup
	}
	if err := requireRestrictedFile(config.TLSPrivateKeyFile); err != nil {
		return nil, ErrStartup
	}
	serverCertificate, err := tls.LoadX509KeyPair(config.TLSCertificateFile, config.TLSPrivateKeyFile)
	if err != nil || len(serverCertificate.Certificate) == 0 {
		return nil, ErrStartup
	}
	leaf, err := x509.ParseCertificate(serverCertificate.Certificate[0])
	if err != nil || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return nil, ErrStartup
	}
	clientCAPEM, err := readBounded(config.ClientCAFile, maxCertificateBytes)
	if err != nil {
		return nil, ErrStartup
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAPEM) {
		return nil, ErrStartup
	}
	tlsConfig, err := transport.TLSConfig(serverCertificate, clientCAs)
	if err != nil {
		return nil, ErrStartup
	}
	if err := requireRestrictedFile(config.AuditSinkPrivateKeyFile); err != nil {
		return nil, ErrStartup
	}
	sinkCertificate, err := tls.LoadX509KeyPair(config.AuditSinkCertificateFile, config.AuditSinkPrivateKeyFile)
	if err != nil || len(sinkCertificate.Certificate) == 0 {
		return nil, ErrStartup
	}
	sinkLeaf, err := x509.ParseCertificate(sinkCertificate.Certificate[0])
	if err != nil || time.Now().Before(sinkLeaf.NotBefore) || !time.Now().Before(sinkLeaf.NotAfter) {
		return nil, ErrStartup
	}
	sinkCAPEM, err := readBounded(config.AuditSinkCAFile, maxCertificateBytes)
	if err != nil {
		return nil, ErrStartup
	}
	sinkRoots := x509.NewCertPool()
	if !sinkRoots.AppendCertsFromPEM(sinkCAPEM) {
		return nil, ErrStartup
	}
	sink, err := audit.NewHTTPSink(config.AuditSinkURL, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: sinkRoots, Certificates: []tls.Certificate{sinkCertificate}})
	if err != nil {
		return nil, ErrStartup
	}

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, ErrStartup
	}
	poolConfig.MaxConns = config.MaxDatabaseConns
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, ErrStartup
	}
	startupSucceeded := false
	defer func() {
		if !startupSucceeded {
			pool.Close()
		}
	}()
	if err := pool.Ping(ctx); err != nil {
		return nil, ErrStartup
	}
	if err := credential.ApplyPostgresMigrations(ctx, pool); err != nil {
		return nil, ErrStartup
	}
	if err := audit.ApplyMigration(ctx, pool); err != nil {
		return nil, ErrStartup
	}
	registry := builtin.Registry{}
	manager, err := credential.NewPostgresManager(keys, registry, pool, registry)
	if err != nil {
		return nil, ErrStartup
	}
	if err := manager.RequireAuditSpool(auditSpool); err != nil {
		return nil, ErrStartup
	}
	auditWorker, err := audit.NewDeliveryWorker(auditSpool, pool, sink, audit.DeliveryConfig{BatchSize: config.AuditDeliveryBatchSize, PollInterval: config.AuditDeliveryPollInterval, RequestTimeout: config.AuditDeliveryRequestTimeout})
	if err != nil {
		return nil, ErrStartup
	}
	auditRecorder, err := audit.NewRecorder(auditSpool, pool, auditWorker)
	if err != nil {
		return nil, ErrStartup
	}
	handler, err := transport.NewServer(manager, transport.SPIFFEMapper{TrustDomain: config.TrustDomain}, auditRecorder)
	if err != nil {
		return nil, ErrStartup
	}
	mainServer, err := transport.NewHTTPServer(config.ListenAddress, handler, tlsConfig)
	if err != nil {
		return nil, ErrStartup
	}
	runtime := &Runtime{config: config, pool: pool, mainServer: mainServer, auditWorker: auditWorker}
	runtime.healthServer = &http.Server{
		Addr: config.HealthListenAddress, Handler: runtime.healthHandler(),
		ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second,
		WriteTimeout: 3 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4 << 10,
	}
	startupSucceeded = true
	return runtime, nil
}

func (runtime *Runtime) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrServe
	}
	mainListener, err := net.Listen("tcp", runtime.config.ListenAddress)
	if err != nil {
		runtime.pool.Close()
		return ErrServe
	}
	healthListener, err := net.Listen("tcp", runtime.config.HealthListenAddress)
	if err != nil {
		mainListener.Close()
		runtime.pool.Close()
		return ErrServe
	}
	runtime.setAddresses(mainListener.Addr().String(), healthListener.Addr().String())
	limited := newLimitListener(mainListener, runtime.config.MaxNetworkConns)
	tlsListener := tls.NewListener(limited, runtime.mainServer.TLSConfig)
	runContext, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	errorsChannel := make(chan error, 3)
	var workers sync.WaitGroup
	workers.Add(3)
	go func() { defer workers.Done(); errorsChannel <- runtime.mainServer.Serve(tlsListener) }()
	go func() { defer workers.Done(); errorsChannel <- runtime.healthServer.Serve(healthListener) }()
	go func() { defer workers.Done(); errorsChannel <- runtime.auditWorker.Run(runContext) }()
	runtime.ready.Store(true)

	var serveError error
	select {
	case <-ctx.Done():
	case serveError = <-errorsChannel:
		if errors.Is(serveError, http.ErrServerClosed) {
			serveError = nil
		}
	}
	runtime.ready.Store(false)
	cancelRun()
	shutdownContext, cancel := context.WithTimeout(context.Background(), runtime.config.ShutdownTimeout)
	defer cancel()
	mainError := runtime.mainServer.Shutdown(shutdownContext)
	healthError := runtime.healthServer.Shutdown(shutdownContext)
	workers.Wait()
	runtime.pool.Close()
	if serveError != nil || mainError != nil || healthError != nil {
		return ErrServe
	}
	return nil
}

func (runtime *Runtime) Addresses() (string, string) {
	runtime.addressMu.RLock()
	defer runtime.addressMu.RUnlock()
	return runtime.mainAddress, runtime.healthAddress
}

func (runtime *Runtime) setAddresses(mainAddress, healthAddress string) {
	runtime.addressMu.Lock()
	defer runtime.addressMu.Unlock()
	runtime.mainAddress, runtime.healthAddress = mainAddress, healthAddress
}

func (runtime *Runtime) healthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		if !runtime.ready.Load() {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte("not ready\n"))
			return
		}
		pingContext, cancel := context.WithTimeout(request.Context(), 250*time.Millisecond)
		defer cancel()
		if err := runtime.pool.Ping(pingContext); err != nil {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte("not ready\n"))
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ready\n"))
	})
	return mux
}

func readRestrictedText(path string, maximum int64) (string, error) {
	if err := requireRestrictedFile(path); err != nil {
		return "", err
	}
	value, err := readBounded(path, maximum)
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(string(value))
	for index := range value {
		value[index] = 0
	}
	if text == "" || strings.ContainsRune(text, '\x00') {
		return "", ErrStartup
	}
	return text, nil
}

func requireRestrictedFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return ErrStartup
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return ErrStartup
	}
	return nil
}

func readBounded(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrStartup
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(value)) > maximum {
		return nil, ErrStartup
	}
	return value, nil
}

type limitListener struct {
	net.Listener
	tokens chan struct{}
}

func newLimitListener(listener net.Listener, maximum int) net.Listener {
	return &limitListener{Listener: listener, tokens: make(chan struct{}, maximum)}
}

func (listener *limitListener) Accept() (net.Conn, error) {
	listener.tokens <- struct{}{}
	connection, err := listener.Listener.Accept()
	if err != nil {
		<-listener.tokens
		return nil, err
	}
	return &limitedConn{Conn: connection, release: func() { <-listener.tokens }}, nil
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (connection *limitedConn) Close() error {
	error := connection.Conn.Close()
	connection.once.Do(connection.release)
	return error
}
