// Package sink delivers immutable JSON lines best effort, independently of capture.
package sink

import (
	"context"
	"errors"
)

var ErrNotImplemented = errors.New("sink implementation unavailable")
var ErrQueueFull = errors.New("sink queue is full")
var ErrClosed = errors.New("sink queue is closed")

// Sink serializes each Write with Reopen. A successful Reopen means no write
// remains on its old destination. Write reports bytes accepted even on error;
// failure never establishes that the destination holds no part of the line.
// Close and Reopen honor cancellation while waiting for a blocked Write.
type Sink interface {
	Write(context.Context, []byte) (int, error)
	Reopen(context.Context) error
	Close(context.Context) error
}

// Factory supplies a sink even when its initial destination is unavailable.
// A later Reopen can recover it. Names are stable absolute or relative paths.
type Factory func(path string) Sink

// Stats counts attempts and outcomes, never an inventory of destination data.
// Authorized = Written + Failed + Dropped + Pending. Discarded is the subset
// of Dropped discarded at shutdown. PendingBytes includes queued AND in-flight
// encoded bytes, including LF; HighWaterBytes is its maximum.
type Stats struct {
	Authorized     uint64 `json:"authorized"`
	Written        uint64 `json:"written"`
	Failed         uint64 `json:"failed"`
	Dropped        uint64 `json:"dropped"`
	Pending        uint64 `json:"pending"`
	Discarded      uint64 `json:"discarded"`
	Bytes          int64  `json:"bytes"`
	PendingBytes   int64  `json:"pending_bytes"`
	HighWaterBytes int64  `json:"high_water_bytes"`
	LimitBytes     int64  `json:"limit_bytes"`
}

// Queue retains only complete processed lines. Register precedes Enqueue.
// All destinations share the byte bound. Enqueue transfers ownership of line;
// its caller must not mutate or retain it. A nil error transfers its byte charge
// to the queue before the caller refunds input reservations. A full queue drops
// immediately. No method doing I/O holds the enqueue lock.
type Queue struct{}

func NewQueue(limitBytes int64) (*Queue, error)               { return nil, ErrNotImplemented }
func (q *Queue) Register(name string, destination Sink) error { return ErrNotImplemented }
func (q *Queue) Enqueue(name string, line []byte) error       { return ErrNotImplemented }
func (q *Queue) Stats() Stats                                 { return Stats{} }
func (q *Queue) DestinationStats(name string) Stats           { return Stats{} }

// Drain waits for current pending work, bounded by ctx; it leaves admission open.
func (q *Queue) Drain(ctx context.Context) error { return ErrNotImplemented }

// Shutdown closes admission, drains up to ctx's bound, then counts all remaining
// pending lines as discarded. A late write completion cannot change that count.
func (q *Queue) Shutdown(ctx context.Context) error { return ErrNotImplemented }
func (q *Queue) Reopen(ctx context.Context) error   { return ErrNotImplemented }
func NewFile(path string) Sink                      { return nil }
