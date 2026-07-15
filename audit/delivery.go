package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrSink = errors.New("audit sink unavailable")

type Sink interface {
	Deliver(context.Context, Record) error
}

type HTTPSink struct {
	endpoint string
	client   *http.Client
}

func NewHTTPSink(endpoint string, tlsConfig *tls.Config) (*HTTPSink, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || tlsConfig == nil || tlsConfig.MinVersion < tls.VersionTLS13 {
		return nil, ErrSink
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig.Clone(), DisableCompression: true, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return ErrSink }}
	return &HTTPSink{endpoint: parsed.String(), client: client}, nil
}

func (sink *HTTPSink) Deliver(ctx context.Context, record Record) error {
	if sink == nil || sink.client == nil || record.Sequence < 1 || len(record.MAC) != 32 || validate(record.Event) != nil {
		return ErrSink
	}
	body, err := json.Marshal(record)
	if err != nil {
		return ErrSink
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, sink.endpoint, bytes.NewReader(body))
	if err != nil {
		return ErrSink
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Idempotency-Key", "audit-"+hex.EncodeToString(record.MAC))
	response, err := sink.client.Do(request)
	if err != nil {
		return ErrSink
	}
	defer response.Body.Close()
	_, drainErr := io.Copy(io.Discard, io.LimitReader(response.Body, 4097))
	if drainErr != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		return ErrSink
	}
	return nil
}

type DeliveryConfig struct {
	BatchSize      int
	PollInterval   time.Duration
	RequestTimeout time.Duration
}

type DeliveryWorker struct {
	spool         *Spool
	pool          *pgxpool.Pool
	sink          Sink
	config        DeliveryConfig
	degraded      atomic.Bool
	lastDelivered atomic.Int64
}

func NewDeliveryWorker(spool *Spool, pool *pgxpool.Pool, sink Sink, config DeliveryConfig) (*DeliveryWorker, error) {
	if spool == nil || pool == nil || sink == nil || config.BatchSize < 1 || config.BatchSize > 1000 || config.PollInterval < 100*time.Millisecond || config.PollInterval > time.Minute || config.RequestTimeout < time.Second || config.RequestTimeout > time.Minute {
		return nil, ErrAudit
	}
	return &DeliveryWorker{spool: spool, pool: pool, sink: sink, config: config}, nil
}

type DeliveryStatus struct {
	Degraded      bool
	LastDelivered time.Time
}

func (worker *DeliveryWorker) Status() DeliveryStatus {
	if worker == nil {
		return DeliveryStatus{Degraded: true}
	}
	value := worker.lastDelivered.Load()
	var delivered time.Time
	if value != 0 {
		delivered = time.Unix(0, value).UTC()
	}
	return DeliveryStatus{Degraded: worker.degraded.Load(), LastDelivered: delivered}
}

func (worker *DeliveryWorker) Run(ctx context.Context) error {
	if worker == nil || ctx == nil {
		return ErrAudit
	}
	if err := worker.spool.Verify(ctx, worker.pool); err != nil {
		worker.degraded.Store(true)
		return ErrAudit
	}
	ticker := time.NewTicker(worker.config.PollInterval)
	defer ticker.Stop()
	for {
		err := worker.deliverBatch(ctx)
		if err != nil && !errors.Is(err, ErrSink) {
			worker.degraded.Store(true)
			return err
		}
		worker.degraded.Store(err != nil)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (worker *DeliveryWorker) deliverBatch(ctx context.Context) error {
	records, err := worker.spool.Pending(ctx, worker.pool, worker.config.BatchSize)
	if err != nil {
		return ErrAudit
	}
	for _, record := range records {
		requestContext, cancel := context.WithTimeout(ctx, worker.config.RequestTimeout)
		err := worker.sink.Deliver(requestContext, record)
		cancel()
		if err != nil {
			return ErrSink
		}
		deliveredAt := time.Now().UTC()
		if err := worker.spool.MarkDelivered(ctx, worker.pool, record.Sequence, record.MAC, deliveredAt); err != nil {
			return ErrAudit
		}
		worker.lastDelivered.Store(deliveredAt.UnixNano())
	}
	return nil
}
