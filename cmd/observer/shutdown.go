package main

import (
	"context"
	"time"
)

// Both allowances start at the first shutdown trigger. The last five seconds
// are reserved for publishing the frozen account; they are not another work
// allowance. A normal stop uses neither allowance up.
const (
	shutdownWorkWithin = 20 * time.Second
	shutdownExitWithin = 25 * time.Second
	stopWithin         = 30 * time.Second
)

type shutdownStage string

const (
	shutdownController shutdownStage = "controller"
	shutdownWithdrawal shutdownStage = "withdrawal"
	shutdownDrain      shutdownStage = "producer drain"
	shutdownCounters   shutdownStage = "producer counters"
	shutdownCapture    shutdownStage = "capture finalization"
	shutdownWorkers    shutdownStage = "processing workers"
	shutdownExtensions shutdownStage = "extension shutdown"
	shutdownWriter     shutdownStage = "writer shutdown"
	shutdownSnapshot   shutdownStage = "final snapshot"
	shutdownAttachment shutdownStage = "attachment close"
	shutdownLog        shutdownStage = "log shutdown"
	shutdownAccount    shutdownStage = "account publication"
	shutdownProjection shutdownStage = "projection publication"
	shutdownPointer    shutdownStage = "last-seal publication"
	shutdownResult     shutdownStage = "stop result publication"
)

// shutdownHooks holds fault-injection boundaries for in-package subprocess
// tests. A hook runs before the named operation, outside every owner lock.
// Production leaves it nil. A held hook does not suspend either deadline.
type shutdownHooks struct {
	Before func(context.Context, shutdownStage) error
}

// A validated session account is the seal. These outcomes describe the command,
// not another kind of account: a later publication failure keeps that seal.
type shutdownOutcome string

const (
	shutdownComplete          shutdownOutcome = "complete"
	shutdownIncomplete        shutdownOutcome = "incomplete"
	shutdownUnsealed          shutdownOutcome = "unsealed"
	shutdownPublicationFailed shutdownOutcome = "publication failed"
)

func (d *daemon) beforeShutdown(ctx context.Context, stage shutdownStage) error {
	if d.shutdownHooks == nil || d.shutdownHooks.Before == nil {
		return nil
	}
	return d.shutdownHooks.Before(ctx, stage)
}
