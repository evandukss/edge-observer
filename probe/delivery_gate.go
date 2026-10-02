package probe

import (
	"errors"
	"sync"
)

// DeliveryWithoutGate is the diagnostic counter in an attachment's Refusals
// report for decoded events that bypassed the gate. Like the socket success
// counter in that report, it is evidence of a path taken, not a capture loss.
const DeliveryWithoutGate = "decoded events delivered without an admission gate"

// GateRefusal is the counter in an attachment's Refusals report for decoded
// events the gate refused under reason. A refusal is accounted as refused and
// never as capture loss: the event still takes its place in the production
// order, so no stream is retired for it.
func GateRefusal(reason GateReason) string {
	return "an event the delivery gate refused under " + string(reason)
}

// RefusalUnplaced is the counter for refused events whose place in the
// production order the capture could not take. Each is then read as an
// observation missing from the order, a loss, which is the defect GateRefusal
// exists to prevent; nonzero means the hand-off to capture is not wired.
const RefusalUnplaced = "a refused event the capture could not place in the production order"

// DeliveryKind classifies a decoded event before any identity lookup. Its
// values match the producer's transfer and close kinds; every other value is
// unknown and fails closed after charging a slot.
type DeliveryKind uint8

const (
	DeliveryTransfer DeliveryKind = 1
	DeliveryClose    DeliveryKind = 2
)

// DeliveryGateOptions are fixed for one capture, shared by every placement.
type DeliveryGateOptions struct {
	// MaxEvents must be positive. It counts decoded events, not bytes or heap
	// usage. Events 1 through N can reserve a slot; N+1 is refused and makes
	// every pending release ineligible. Reservations are never refunded.
	MaxEvents uint64

	// StorageExhausted is ignored. Sink failures do not invalidate capture.
	// Deprecated: retained for source compatibility.
	StorageExhausted <-chan struct{}

	// IntakeExhausted is observed under the ordering lock at Admit, Authorize
	// and Snapshot. A refused input leaves capture incomplete and invalidates
	// pending release. Nil means no intake signal is connected.
	IntakeExhausted <-chan struct{}

	// BeforeAuthorize is an optional test seam called just before authorization
	// acquires its ordering lock. It runs with no gate lock held. Holding this
	// hook cannot prevent admission, invalidation, or the withdrawal signal.
	// Production callers leave it nil. Concurrent callers must synchronize any
	// mutable state in the hook themselves.
	BeforeAuthorize func()
}

// GateSnapshot is diagnostic state, never permission to release payload.
// Authorize alone grants permission; a snapshot followed by a write races with
// invalidation. Charged stops at MaxEvents, including the event that invalidates
// on unknown length or kind. Later refused events reserve nothing.
type GateSnapshot struct {
	MaxEvents uint64
	Charged   uint64
	Reason    GateReason
}

// AdmissionDecision is the decision for exactly one decoded event. Charged
// says it reserved a slot even if uncertainty then refused delivery. Admitted
// alone permits identity lookup and dispatch to either capture sink.
type AdmissionDecision struct {
	Admitted bool
	Charged  bool
	State    GateSnapshot
}

// ReleaseEvidence is the worker's assertion about this particular result.
// Both fields must be true. InputsSettled means all inputs for the result have
// arrived and processing finished. LifecycleSettled means its batch closed
// completely, or withdrawal and finalisation established its capture-end
// boundary. A live batch, unfinished parse or queued candidate is not settled.
// The gate does not parse or independently establish either fact.
type ReleaseEvidence struct {
	InputsSettled    bool
	LifecycleSettled bool
}

// ReleaseDecision records the atomic authorization of one settled result.
// Authorized is a completed decision, not a readable eligibility flag. A later
// invalidation cannot recall it. It must not be reused for another result or
// for inputs or lifecycle evidence changed after authorization.
type ReleaseDecision struct {
	Authorized bool
	Reason     GateReason
}

// DeliveryGate orders capture-wide invalidation and release authorization.
// Share one pointer between the delivery loops and the processing workers. It
// must not be copied. A nil pointer or zero value refuses all work with
// GateUninitialized; construct a usable gate with NewDeliveryGate.
//
// No gate operation performs sink I/O. AuthorizeEnqueue permits one short
// nonblocking enqueue under the ordering lock; BeforeAuthorize runs outside it. Invalidation is permanent and
// uses constant work: it revokes all pending candidates without walking them.
type DeliveryGate struct {
	mutex      sync.Mutex
	options    DeliveryGateOptions
	charged    uint64
	reason     GateReason
	withdrawal chan struct{}
}

// NewDeliveryGate validates options. Zero MaxEvents is the only invalid option;
// there are no hidden identity, payload, length, timestamp or batch-ID rules.
func NewDeliveryGate(options DeliveryGateOptions) (*DeliveryGate, error) {
	if options.MaxEvents == 0 {
		return nil, errors.New("delivery gate requires a positive event allowance")
	}
	return &DeliveryGate{options: options, withdrawal: make(chan struct{})}, nil
}

// Admit reserves a slot before classifying the event. A transfer with
// measured=false invalidates capture-wide, including early or zero-length
// transfers. A close ignores measured: false is the ordinary close shape.
// Unknown kinds are charged then invalidate. Observable intake
// exhaustion is consumed before reserving a slot. Otherwise, at N+1 the input
// limit takes precedence over the event's kind and measurement, and nothing is
// dispatched. Once invalidated, no event is charged or admitted, and the first
// reason survives later faults.
func (g *DeliveryGate) Admit(kind DeliveryKind, measured bool) AdmissionDecision {
	if g == nil || g.withdrawal == nil {
		return AdmissionDecision{State: GateSnapshot{Reason: GateUninitialized}}
	}
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.consumeIntakeExhaustionLocked()
	if g.reason != "" {
		return AdmissionDecision{State: g.snapshotLocked()}
	}
	if g.charged == g.options.MaxEvents {
		g.invalidateLocked(GateInputLimit)
		return AdmissionDecision{State: g.snapshotLocked()}
	}
	g.charged++
	switch kind {
	case DeliveryTransfer:
		if !measured {
			g.invalidateLocked(GateUnknownLength)
		}
	case DeliveryClose:
		// A close crossed no socket, so its ordinary measured value is false.
	default:
		g.invalidateLocked(GateUnknownKind)
	}
	return AdmissionDecision{Admitted: g.reason == "", Charged: true, State: g.snapshotLocked()}
}

// Authorize checks the supplied evidence and capture eligibility in ONE
// ordering with invalidation. If invalidation precedes this decision it must
// refuse, even if a prior snapshot was clear or BeforeAuthorize was entered
// before the fault. A refusal for unsettled evidence does not invalidate the
// capture. Invalidation takes precedence over GateUnsettled in the decision.
// Writing happens only after this call returns, holding no gate lock.
func (g *DeliveryGate) Authorize(evidence ReleaseEvidence) ReleaseDecision {
	return g.AuthorizeEnqueue(evidence, nil)
}

// AuthorizeEnqueue orders a short, nonblocking enqueue with invalidation.
// enqueue must only transfer processed bytes to a bounded queue, never perform
// I/O or call the gate. Authorization survives a later invalidation.
func (g *DeliveryGate) AuthorizeEnqueue(evidence ReleaseEvidence, enqueue func()) ReleaseDecision {
	if g == nil || g.withdrawal == nil {
		return ReleaseDecision{Reason: GateUninitialized}
	}
	if g.options.BeforeAuthorize != nil {
		g.options.BeforeAuthorize()
	}
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.consumeIntakeExhaustionLocked()
	if g.reason != "" {
		return ReleaseDecision{Reason: g.reason}
	}
	if !evidence.InputsSettled || !evidence.LifecycleSettled {
		return ReleaseDecision{Reason: GateUnsettled}
	}
	if enqueue != nil {
		enqueue()
	}
	return ReleaseDecision{Authorized: true}
}

// Snapshot consumes observable intake exhaustion and returns diagnostic state
// under the same ordering as Admit. It never authorizes a release.
func (g *DeliveryGate) Snapshot() GateSnapshot {
	if g == nil || g.withdrawal == nil {
		return GateSnapshot{Reason: GateUninitialized}
	}
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.consumeIntakeExhaustionLocked()
	return g.snapshotLocked()
}

// ConsumeStorageExhaustion is a historical alias for Snapshot. Only intake
// exhaustion invalidates capture; sink outcomes are independent.
func (g *DeliveryGate) ConsumeStorageExhaustion() GateSnapshot {
	return g.Snapshot()
}

// Withdrawal is closed exactly once on capture-wide invalidation, in the same
// critical section as the reason and release revocation. It requests withdrawal;
// it is not evidence that kernel authority has already been withdrawn. The
// session controller performs and records that operation independently of the
// delivery loop, worker, writer and finalisation. No receiver is needed for
// Admit to return. An uninitialized gate returns an already-closed channel.
func (g *DeliveryGate) Withdrawal() <-chan struct{} {
	if g == nil || g.withdrawal == nil {
		return uninitializedWithdrawal
	}
	return g.withdrawal
}

var uninitializedWithdrawal = func() <-chan struct{} {
	closed := make(chan struct{})
	close(closed)
	return closed
}()

func (g *DeliveryGate) snapshotLocked() GateSnapshot {
	return GateSnapshot{MaxEvents: g.options.MaxEvents, Charged: g.charged, Reason: g.reason}
}

func (g *DeliveryGate) consumeIntakeExhaustionLocked() {
	if g.reason != "" {
		return
	}
	select {
	case <-g.options.IntakeExhausted:
		g.invalidateLocked(GateIntakeExhausted)
	default:
	}
}

func (g *DeliveryGate) invalidateLocked(reason GateReason) {
	g.reason = reason
	close(g.withdrawal)
}
