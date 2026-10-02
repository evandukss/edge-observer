// Package activation verifies the payload holder before protected capture begins.
package activation

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path"
	"strings"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// Check identifies the condition that refused setup before attach.
type Check string

const (
	DeliveryGate               Check = "delivery_gate"
	ProcessingPlan             Check = "processing_plan"
	ExecutionMemory            Check = "execution_memory"
	AnonymousSwap              Check = "anonymous_swap"
	CoreDumps                  Check = "core_dumps"
	PayloadMembership          Check = "payload_membership"
	ParticipantOutsideEnvelope Check = "participant_outside_envelope"
	// NoParticipantRunning refuses a start at which every selected process had
	// exited by the time its posture was read.
	NoParticipantRunning Check = "no_participant_running"
	// PostureUnreadable labels unavailable evidence in Refusal.Error; the
	// refusal's Check retains the particular condition that could not be read.
	PostureUnreadable Check = "posture_unreadable"
)

// Refusal names the deciding check and the payload-holding process.
// PID is zero only when the current process could not be identified.
type Refusal struct {
	Check  Check
	PID    int
	Detail string
	// Unreadable distinguishes unavailable or uninterpretable posture evidence
	// from an observed condition that fails Check. Check still names the field.
	Unreadable bool
}

func (r *Refusal) Error() string {
	if r.Unreadable {
		return fmt.Sprintf("activation refused: %s: %s (payload pid %d): %s", PostureUnreadable, r.Check, r.PID, r.Detail)
	}
	return fmt.Sprintf("activation refused: %s (payload pid %d): %s", r.Check, r.PID, r.Detail)
}

type ParticipantState struct {
	PID       int32  `json:"pid"`
	StartTime uint64 `json:"start_time"`
	Cgroup    string `json:"cgroup"`
}

// Posture records the kernel readings made in the payload holder,
// not in its launcher. The supported envelope is that process's own cgroup v2
// domain: a positive finite memory.max and zero memory.swap.max/current.
// Cgroup paths use the observer's namespace and must be absolute and clean.
// Participants must be identified by pid AND start time and lie outside the
// envelope and all its descendants. An unreadable member is not an absence. An
// exited one, whose entry is gone or whose pid carries another start, is
// counted in ParticipantsExited rather than read. Dumpable must be zero. Core
// limits and core_pattern are not alternatives to non-dumpability and impose
// no additional acceptance condition.
//
// The memory assurance requires entry into the isolated bounded no-swap cgroup
// BEFORE exec, with membership and limits fixed throughout capture. These
// readings cannot establish that no allocation predates entry: migrating an
// existing process does not move the charges for pages it already holds.
// They establish current posture, not historical page ownership or immunity
// to subsequent changes by the administrator of the execution environment.
type Posture struct {
	PID         int    `json:"pid"`
	StartTime   uint64 `json:"start_time"`
	Cgroup      string `json:"cgroup"`
	Domain      string `json:"domain"`
	Member      bool   `json:"member"`
	MemoryMax   uint64 `json:"memory_max"`
	SwapMax     uint64 `json:"swap_max"`
	SwapCurrent uint64 `json:"swap_current"`
	Dumpable    int    `json:"dumpable"`
	// CoreSoft, CoreHard and CorePattern are optional diagnostics, never
	// acceptance evidence. Their zero values do not prove a successful reading.
	CoreSoft     uint64             `json:"core_soft,omitempty"`
	CoreHard     uint64             `json:"core_hard,omitempty"`
	CorePattern  string             `json:"core_pattern,omitempty"`
	Participants []ParticipantState `json:"participants"`
	// ParticipantsExited counts supplied participants that had exited when read:
	// the entry was gone, or the pid carried a different start. They are left
	// out of Participants.
	ParticipantsExited int `json:"participants_exited"`
}

// Capture shares volatile intake and the delivery gate with processing.
// Intake exhaustion invalidates incomplete input; sink outcomes are separate.
type Capture struct {
	Recording *capture.Session
	Intake    *intake.Store
	Gate      *probe.DeliveryGate
	Posture   Posture
}

// Prepare requires a policy from policy.CompileProcessing and a positive
// admitted-event allowance whose product with ebpf.MaxEventPayloadBytes fits
// int64. The product bounds accepted raw payload, not process memory. It builds
// both volatile sinks and the shared gate, then verifies posture before returning
// anything an attachment can use. It opens no durable file and attaches nothing.
// The last parameter is retained for source compatibility and ignored. Output
// failures cannot refuse activation. Intake exhaustion remains a gate source.
func Prepare(read policy.Policy, participants []process.Process, maxEvents uint64, _ <-chan struct{}) (*Capture, error) {
	if read.Processing == nil || read.ProcessingRevision == "" {
		return nil, &Refusal{Check: ProcessingPlan, PID: os.Getpid(), Detail: "a compiler-produced processing plan and revision are required"}
	}
	recording, store, err := RecordingIntake(maxEvents)
	if err != nil {
		return nil, &Refusal{Check: DeliveryGate, PID: os.Getpid(), Detail: err.Error()}
	}
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: maxEvents,
		IntakeExhausted: store.Exhausted()})
	if err != nil {
		_ = store.Close()
		return nil, &Refusal{Check: DeliveryGate, PID: os.Getpid(), Detail: err.Error()}
	}
	posture, err := Verify(gate, participants)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	return &Capture{Recording: recording, Intake: store, Gate: gate, Posture: posture}, nil
}

// Verify reads the current process and the exact participant set,
// then checks the readings. It consumes no event slot. Nil, zero-value,
// invalidated, and already-used gates are refused as delivery_gate; a fresh
// gate is required. The caller must pass this same gate to every placement.
func Verify(gate *probe.DeliveryGate, participants []process.Process) (Posture, error) {
	return verify(gate, participants, true)
}

// VerifyActive verifies a gate already in force during additive reload.
// It performs the same current-process posture and participant isolation checks
// as Verify. Charged slots are allowed; invalidated and unconstructed gates are
// refused as delivery_gate. It consumes no event slot and replaces no gate.
// Verify is for initial activation before any event has been admitted;
// VerifyActive is for the running session's existing gate and is not an
// initial-activation entry point.
func VerifyActive(gate *probe.DeliveryGate, participants []process.Process) (Posture, error) {
	return verify(gate, participants, false)
}

// CheckPosture judges complete readings, in gate, membership, memory, swap,
// core, participant order. MemoryMax zero or MaxUint64 denotes no finite cap.
// SwapMax MaxUint64 denotes max. Empty participant evidence refuses activation,
// as no_participant_running where every participant had exited.
// This is an initial-activation check and requires a fresh gate.
// Reading failures are returned before this function with Unreadable set and
// Check naming the attempted condition. Refusals from these complete readings
// leave Unreadable false: the condition was evaluated and failed.
func CheckPosture(gate *probe.DeliveryGate, posture Posture) error {
	return checkPosture(gate, posture, true)
}

// Judgment is one envelope condition start's posture check decides. Met false
// with Unreadable true is a condition that could not be read; nothing after it
// was judged. PID names the participant a participant judgment is about, and is
// zero for every other condition.
type Judgment struct {
	Check      Check  `json:"check"`
	Met        bool   `json:"met"`
	Unreadable bool   `json:"unreadable,omitempty"`
	PID        int32  `json:"pid,omitempty"`
	Detail     string `json:"detail"`
}

// Judge judges complete readings against every envelope condition start
// refuses on, in the order start checks them: membership, memory, swap, core
// dumps, then the participants: one judgment when every participant is outside
// the envelope, or one per participant that is not, or no_participant_running
// where none was read because every one had exited. start refuses on the first
// judgment that is not met
// (checkPosture); preflight names every one (Envelope). The delivery gate is not
// an envelope condition and is not judged here.
func Judge(posture Posture) []Judgment {
	judged := make([]Judgment, 0, 5)
	judge := func(check Check, met bool, holds, fails string) {
		detail := fails
		if met {
			detail = holds
		}
		judged = append(judged, Judgment{Check: check, Met: met, Detail: detail})
	}
	judge(PayloadMembership,
		posture.PID > 0 && posture.StartTime != 0 && posture.Member && cleanCgroup(posture.Cgroup),
		fmt.Sprintf("payload pid %d is a member of cgroup %q", posture.PID, posture.Cgroup),
		"payload process identity and membership in a clean absolute cgroup must be established")
	judge(ExecutionMemory,
		(posture.Domain == "domain" || posture.Domain == "domain threaded") && posture.MemoryMax != 0 && posture.MemoryMax != math.MaxUint64,
		fmt.Sprintf("cgroup %q is a memory domain with memory.max %d", posture.Cgroup, posture.MemoryMax),
		"the payload holder's cgroup must be a memory domain with a positive finite memory.max")
	judge(AnonymousSwap, posture.SwapMax == 0 && posture.SwapCurrent == 0,
		"memory.swap.max and memory.swap.current are both zero",
		fmt.Sprintf("memory.swap.max and memory.swap.current must both be zero: max=%d current=%d", posture.SwapMax, posture.SwapCurrent))
	judge(CoreDumps, posture.Dumpable == 0, "payload process dumpability is zero",
		fmt.Sprintf("payload process dumpability must be zero, read %d", posture.Dumpable))

	if len(posture.Participants) == 0 {
		if posture.ParticipantsExited > 0 {
			judge(NoParticipantRunning, false, "", fmt.Sprintf("no selected process was running at activation: all %d had exited when their posture was read", posture.ParticipantsExited))
			return judged
		}
		judge(ParticipantOutsideEnvelope, false, "", "no participant identities were verified outside the envelope")
		return judged
	}
	inside := false
	for _, participant := range posture.Participants {
		if participant.PID <= 0 || participant.StartTime == 0 || int(participant.PID) == posture.PID || !cleanCgroup(participant.Cgroup) || withinCgroup(participant.Cgroup, posture.Cgroup) {
			inside = true
			judged = append(judged, Judgment{Check: ParticipantOutsideEnvelope, PID: participant.PID,
				Detail: fmt.Sprintf("participant pid %d start %d cgroup %q is not an identified process outside payload envelope %q", participant.PID, participant.StartTime, participant.Cgroup, posture.Cgroup)})
		}
	}
	if !inside {
		judge(ParticipantOutsideEnvelope, true,
			fmt.Sprintf("%d participants are outside payload envelope %q", len(posture.Participants), posture.Cgroup), "")
	}
	return judged
}

// Envelope reads this process and the participants exactly as start does
// (readPosture) and judges the readings with Judge. A reading that fails is one
// judgment, not met, naming the condition it was reading.
func Envelope(participants []process.Process) []Judgment {
	return judged(readPosture(participants))
}

// judged is Judge over a complete reading, or the one condition a reading
// stopped at.
func judged(posture Posture, err error) []Judgment {
	if err == nil {
		return Judge(posture)
	}
	var refusal *Refusal
	if errors.As(err, &refusal) {
		return []Judgment{{Check: refusal.Check, Unreadable: refusal.Unreadable, Detail: refusal.Detail}}
	}
	return []Judgment{{Check: PostureUnreadable, Unreadable: true, Detail: err.Error()}}
}

func verify(gate *probe.DeliveryGate, participants []process.Process, fresh bool) (Posture, error) {
	return verifyReading(gate, participants, fresh, KernelReadings().reads())
}

func verifyReading(gate *probe.DeliveryGate, participants []process.Process, fresh bool, reads postureReads) (Posture, error) {
	posture := Posture{PID: os.Getpid()}
	if err := checkGate(gate, posture.PID, fresh); err != nil {
		return posture, err
	}
	posture, err := readPostureUsing(participants, reads)
	if err != nil {
		return posture, err
	}
	return posture, checkPosture(gate, posture, fresh)
}

func checkGate(gate *probe.DeliveryGate, pid int, fresh bool) error {
	state := gate.Snapshot()
	if state.MaxEvents == 0 || state.Reason != "" || (fresh && state.Charged != 0) {
		return &Refusal{Check: DeliveryGate, PID: pid, Detail: fmt.Sprintf("gate must be constructed and valid (fresh=%t): allowance=%d charged=%d reason=%q", fresh, state.MaxEvents, state.Charged, state.Reason)}
	}
	return nil
}

func cleanCgroup(group string) bool {
	return strings.HasPrefix(group, "/") && path.Clean(group) == group
}

func withinCgroup(group, envelope string) bool {
	return envelope == "/" || group == envelope || strings.HasPrefix(group, envelope+"/")
}

func checkPosture(gate *probe.DeliveryGate, posture Posture, fresh bool) error {
	refuse := func(check Check, detail string) error {
		return &Refusal{Check: check, PID: posture.PID, Detail: detail}
	}
	if err := checkGate(gate, posture.PID, fresh); err != nil {
		return err
	}
	// The same judgment preflight reports (Envelope): start refuses on the first
	// condition it finds not met, in Judge's order.
	for _, judgment := range Judge(posture) {
		if !judgment.Met {
			return refuse(judgment.Check, judgment.Detail)
		}
	}
	return nil
}
