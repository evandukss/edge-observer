package probe

// CaptureFailureExitStatus is the command's nonzero status after a terminal
// capture fault. Graceful operator stops use zero.
const CaptureFailureExitStatus = 1

// GateReason identifies a refusal. Unknown length and kind invalidate the
// capture until session end. Input and intake limits cut only affected input.
// Unsettled refuses one candidate; uninitialized refuses an unusable gate.
//
// GateReasons enumerates the declared reasons. InvalidatesCapture classifies
// them so callers can derive populations without maintaining another list.
// The empty string means no refusal; other undeclared strings have no defined
// gate meaning. Neither is classified as capture-wide invalidation.
type GateReason string

const (
	GateInputLimit      GateReason = "input_limit"
	GateIntakeExhausted GateReason = "intake_exhausted"
	GateUnknownLength   GateReason = "unknown_length"
	GateUnknownKind     GateReason = "unknown_kind"
	GateUnsettled       GateReason = "unsettled"
	GateUninitialized   GateReason = "uninitialized"
)

// Keep reason declarations and their classification together. The declaration
// coverage test rejects a new constant missing from this table, so a caller's
// derived population cannot silently omit it.
var gateReasonClasses = [...]struct {
	reason             GateReason
	invalidatesCapture bool
}{
	{GateInputLimit, false},
	{GateIntakeExhausted, false},
	{GateUnknownLength, true},
	{GateUnknownKind, true},
	{GateUnsettled, false},
	{GateUninitialized, false},
}

// GateReasons returns every declared GateReason exactly once. The caller owns
// the returned slice; changing it cannot change later enumeration or decisions.
// Order is unspecified. Filter with GateReason.InvalidatesCapture to enumerate
// capture-wide invalidation reasons.
func GateReasons() []GateReason {
	reasons := make([]GateReason, len(gateReasonClasses))
	for i, class := range gateReasonClasses {
		reasons[i] = class.reason
	}
	return reasons
}

// InvalidatesCapture reports whether r denotes capture-wide invalidation.
// It is false for GateUnsettled, GateUninitialized, the empty string and
// undeclared values. It classifies reasons, not a live gate's eligibility;
// DeliveryGate.Authorize alone grants permission to release a result.
func (r GateReason) InvalidatesCapture() bool {
	for _, class := range gateReasonClasses {
		if class.reason == r {
			return class.invalidatesCapture
		}
	}
	return false
}
