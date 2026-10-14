package attachment

import (
	"context"
	"time"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/probe"
)

// Lifecycle is the aggregate attachment's deadline-aware finalisation boundary.
// The caller owns the deadline and calls withdrawal, drain, account, then close
// in that order. Each operation starts every owner independently: a held owner
// cannot prevent another owner from withdrawing or closing. No owner call runs
// while the aggregate's membership lock is held.
//
// Context expiry stops waiting, not a kernel call already in flight. A pending
// owner contributes unknown facts and a named error, never a successful zero.
// Returned facts are detached values: a late completion cannot change them or
// publish an account. The daemon's exit backstop remains the caller's concern.
// Ordinary Close and Producer methods wait without a caller deadline; bounded
// shutdown must use these context methods instead.
type Lifecycle interface {
	probe.Attachment
	connection.Producer
	StopProducingContext(context.Context) (connection.Withdrawal, error)
	DrainContext(context.Context, time.Duration) (connection.Drained, error)
	AccountContext(context.Context) (connection.Counters, error)
	CloseContext(context.Context) error
}

// PartialAttachmentPolicy describes startup failure across selected adapters.
// Unsupported processes retain their catalogue refusal and do not prevent other
// supported processes from attaching. A selected adapter's attachment failure
// aborts startup: every attachment already returned (including one returned with
// an error) is closed, and no successful aggregate is handed to the caller.
// Cleanup errors name their owner beside the original selected-adapter failure.
// An adapter returning no attachment on failure owns its own partial cleanup.
const PartialAttachmentPolicy = "abort on selected-adapter failure and close every returned attachment"
