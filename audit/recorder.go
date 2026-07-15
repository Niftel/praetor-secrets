package audit

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Request struct {
	ID, WorkloadIdentity, Operation string
	StartedAt                       time.Time
}
type requestKey struct{}

func WithRequest(ctx context.Context, request Request) context.Context {
	return context.WithValue(ctx, requestKey{}, request)
}
func RequestFromContext(ctx context.Context) (Request, bool) {
	request, ok := ctx.Value(requestKey{}).(Request)
	return request, ok
}

func Completion(ctx context.Context, result, reason string, finished time.Time) Event {
	request, _ := RequestFromContext(ctx)
	latency := "fast"
	duration := finished.Sub(request.StartedAt)
	if duration >= 100*time.Millisecond {
		latency = "slow"
	} else if duration >= 10*time.Millisecond {
		latency = "medium"
	}
	return Event{SchemaVersion: SchemaVersion, Timestamp: finished.UTC(), EventType: "request_completed", Operation: request.Operation, Result: result, ReasonCode: reason, WorkloadIdentity: request.WorkloadIdentity, RequestID: request.ID, LatencyClass: latency}
}

type Recorder struct {
	spool    *Spool
	pool     *pgxpool.Pool
	worker   *DeliveryWorker
	degraded atomic.Bool
}

func NewRecorder(spool *Spool, pool *pgxpool.Pool, worker *DeliveryWorker) (*Recorder, error) {
	if spool == nil || pool == nil || worker == nil {
		return nil, ErrAudit
	}
	return &Recorder{spool: spool, pool: pool, worker: worker}, nil
}
func (recorder *Recorder) Record(ctx context.Context, event Event) error {
	if recorder == nil {
		return ErrAudit
	}
	tx, err := recorder.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		recorder.degraded.Store(true)
		return ErrAudit
	}
	defer tx.Rollback(ctx)
	if err := recorder.spool.AppendTx(ctx, tx, event); err != nil {
		recorder.degraded.Store(true)
		return ErrAudit
	}
	if err := tx.Commit(ctx); err != nil {
		recorder.degraded.Store(true)
		return ErrAudit
	}
	return nil
}

type SecurityStatus struct {
	AuditIntegrityHealthy     bool      `json:"audit_integrity_healthy"`
	AuditDeliveryDegraded     bool      `json:"audit_delivery_degraded"`
	PendingAuditEvents        int64     `json:"pending_audit_events"`
	MaximumPendingAuditEvents int64     `json:"maximum_pending_audit_events"`
	LastAuditDelivery         time.Time `json:"last_audit_delivery,omitempty"`
}

func (recorder *Recorder) Status(ctx context.Context) (SecurityStatus, error) {
	if recorder == nil {
		return SecurityStatus{}, ErrAudit
	}
	pending, maximum, err := recorder.spool.PendingCount(ctx, recorder.pool)
	if err != nil {
		recorder.degraded.Store(true)
		return SecurityStatus{}, ErrAudit
	}
	delivery := recorder.worker.Status()
	return SecurityStatus{AuditIntegrityHealthy: !recorder.degraded.Load(), AuditDeliveryDegraded: delivery.Degraded, PendingAuditEvents: pending, MaximumPendingAuditEvents: maximum, LastAuditDelivery: delivery.LastDelivered}, nil
}

func StableResult(status int) (string, string) {
	switch {
	case status >= 200 && status < 300:
		return "success", "completed"
	case status == 401 || status == 403:
		return "denied", "operation_not_permitted"
	case status >= 400 && status < 500:
		return "rejected", "invalid_request"
	default:
		return "error", "secure_operation_failed"
	}
}
