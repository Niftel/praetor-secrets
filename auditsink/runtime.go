package auditsink

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
}

func Build(ctx context.Context, config Config) (*Runtime, error) {
	if ctx == nil || validateConfig(config) != nil {
		return nil, ErrConfiguration
	}
	databaseURL, err := readRestrictedText(config.DatabaseURLFile, maxDatabaseURLBytes)
	if err != nil || requireRestrictedFile(config.TLSPrivateKeyFile) != nil {
		return nil, ErrStartup
	}
	certificate, err := tls.LoadX509KeyPair(config.TLSCertificateFile, config.TLSPrivateKeyFile)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, ErrStartup
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
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
	tlsConfig, err := transport.TLSConfig(certificate, clientCAs)
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
	succeeded := false
	defer func() {
		if !succeeded {
			pool.Close()
		}
	}()
	if pool.Ping(ctx) != nil || ApplyMigration(ctx, pool) != nil {
		return nil, ErrStartup
	}
	store, err := NewStore(pool)
	if err != nil {
		return nil, ErrStartup
	}
	handler, err := NewHandler(store, config.TrustDomain)
	if err != nil {
		return nil, ErrStartup
	}
	runtime := &Runtime{config: config, pool: pool}
	runtime.mainServer = &http.Server{
		Addr: config.ListenAddress, Handler: handler, TLSConfig: tlsConfig,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	runtime.healthServer = &http.Server{
		Addr: config.HealthListenAddress, Handler: runtime.healthHandler(),
		ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second,
		WriteTimeout: 3 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4 << 10,
	}
	succeeded = true
	return runtime, nil
}

func (runtime *Runtime) Run(ctx context.Context) error {
	if ctx == nil || runtime == nil || runtime.pool == nil {
		return ErrServe
	}
	mainListener, err := net.Listen("tcp", runtime.config.ListenAddress)
	if err != nil {
		runtime.pool.Close()
		return ErrServe
	}
	healthListener, err := net.Listen("tcp", runtime.config.HealthListenAddress)
	if err != nil {
		_ = mainListener.Close()
		runtime.pool.Close()
		return ErrServe
	}
	runtime.setAddresses(mainListener.Addr().String(), healthListener.Addr().String())
	tlsListener := tls.NewListener(newLimitListener(mainListener, runtime.config.MaxNetworkConns), runtime.mainServer.TLSConfig)
	errorsChannel := make(chan error, 2)
	var servers sync.WaitGroup
	servers.Add(2)
	go func() { defer servers.Done(); errorsChannel <- runtime.mainServer.Serve(tlsListener) }()
	go func() { defer servers.Done(); errorsChannel <- runtime.healthServer.Serve(healthListener) }()
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
	shutdownContext, cancel := context.WithTimeout(context.Background(), runtime.config.ShutdownTimeout)
	defer cancel()
	mainError := runtime.mainServer.Shutdown(shutdownContext)
	healthError := runtime.healthServer.Shutdown(shutdownContext)
	servers.Wait()
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
		_, _ = writer.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		if !runtime.ready.Load() || runtime.pool == nil {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte("not ready\n"))
			return
		}
		pingContext, cancel := context.WithTimeout(request.Context(), 250*time.Millisecond)
		defer cancel()
		if runtime.pool.Ping(pingContext) != nil {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte("not ready\n"))
			return
		}
		_, _ = writer.Write([]byte("ready\n"))
	})
	return mux
}

type limitListener struct {
	net.Listener
	tokens chan struct{}
	done   chan struct{}
	once   sync.Once
}

func newLimitListener(listener net.Listener, maximum int) net.Listener {
	return &limitListener{Listener: listener, tokens: make(chan struct{}, maximum), done: make(chan struct{})}
}

func (listener *limitListener) Accept() (net.Conn, error) {
	select {
	case listener.tokens <- struct{}{}:
	case <-listener.done:
		return nil, net.ErrClosed
	}
	connection, err := listener.Listener.Accept()
	if err != nil {
		<-listener.tokens
		return nil, err
	}
	return &limitedConn{Conn: connection, release: func() { <-listener.tokens }}, nil
}

func (listener *limitListener) Close() error {
	listener.once.Do(func() { close(listener.done) })
	return listener.Listener.Close()
}

type limitedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (connection *limitedConn) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(connection.release)
	return err
}

func readRestrictedText(path string, maximum int64) (string, error) {
	if requireRestrictedFile(path) != nil {
		return "", ErrStartup
	}
	value, err := readBounded(path, maximum)
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(string(value))
	clear(value)
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
