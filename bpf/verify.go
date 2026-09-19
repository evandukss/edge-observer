package bpf

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Program names one of the two embedded programs by the difference that
// matters: whether it may read the observed process's memory.
type Program struct {
	// Name is what the program is called in reports and errors.
	Name string

	// Object is the compiled ELF, as it is embedded and as it ships.
	Object []byte

	// ReadsPayload is whether this program may read the caller's buffer. Verify
	// proves it by the helpers the object calls, not by this flag.
	ReadsPayload bool
}

// Meta is the metadata-only program: it reads no process memory.
func Meta() Program { return Program{Name: "meta", Object: metaObject(), ReadsPayload: false} }

// The one allowlist, shared by the unit check over the committed objects and
// the check over freshly compiled ones (cmd/verify), so the two cannot diverge.
// A helper a program calls that is not named here fails the check, so gaining
// a helper-mediated capability is a deliberate edit. Names are the kernel
// helpers' own, as the instruction decoder reports them.
//
// # What this bounds
//
// Only capabilities reached through a helper call: Helpers keeps the call
// instructions and discards the rest. A field read through a BTF-typed context
// pointer (fentry, tp_btf) compiles to plain loads with no call, and Verify
// accepts it; the same read through bpf_probe_read_kernel is refused. A socket
// metadata read is not access to plaintext, but this allowlist does not
// account for it. Such a CO-RE read needs the running kernel's BTF at load
// time, not a toolchain on the host.
//
// The programs here are nine uprobes, eight uretprobes and three raw
// tracepoints (sched_process_fork, sched_process_exec, sched_process_exit),
// none BTF-typed: the fork event reads kernel memory through a helper, so the
// decoder sees it. That is an inventory, not a proof that the memory-access
// boundary is closed. What the check establishes is that the metadata-only
// object calls no user-memory helper.

// baseHelpers is what either program may call: the ones that move no process
// memory. The allowlist is a subset check, so a helper absent from here is
// refused wherever it appears.
var baseHelpers = map[string]bool{
	"FnGetCurrentPidTgid":   true, // which process and thread fired, in the observer's own numbering
	"FnGetNsCurrentPidTgid": true, // the same task's number INSIDE a named pid namespace, which is
	//                               what the allowlist is keyed by; a kernel fact
	//                               about the current task, no process memory
	"FnMapLookupElem":  true, // the allowlist and the in-flight table
	"FnMapUpdateElem":  true,
	"FnMapDeleteElem":  true,
	"FnRingbufReserve": true, // an event, and the count of a refusal
	"FnRingbufSubmit":  true,

	// The two that reach kernel memory, for identities found nowhere else: a
	// thread group's birth (separating successive occupants of a pid) and a new
	// task's pid namespace and number. Both programs admit and authenticate, so
	// both need them. Neither reaches the observed process's memory:
	// FnProbeReadKernel copies through copy_from_kernel_nofault, which refuses a
	// user address on both architectures built for. FnProbeReadUser is the one
	// that reads process memory, and stays out of here. Their cost is BTF: a
	// kernel without it fails to load the program.
	"FnGetCurrentTask":  true,
	"FnProbeReadKernel": true,

	// The monotonic clock, which gives a counted loss its occasion. It reads no
	// memory, only elapsed nanoseconds since boot, so both programs may call it.
	"FnKtimeGetNs": true,
}

// payloadHelpers is what the full program may additionally call. It is exactly
// the read of the observed process's memory, and it is the whole of the
// difference the allowlist permits between the two programs.
var payloadHelpers = map[string]bool{
	"FnProbeReadUser": true,
}

// forbidden names helpers no program may ever call. It is redundant with the
// subset check, deliberately, so the refusal of a write helper says why.
var forbidden = map[string]string{
	"FnProbeWriteUser": "writes the observed process's memory",
}

// allowed returns the helper set this program is permitted to call.
func (p Program) allowed() map[string]bool {
	set := make(map[string]bool, len(baseHelpers)+len(payloadHelpers))
	for name := range baseHelpers {
		set[name] = true
	}
	if p.ReadsPayload {
		for name := range payloadHelpers {
			set[name] = true
		}
	}
	return set
}

// Helpers is every kernel helper the object's programs call, decoded from the
// instruction stream. Both checks are built on it, over the committed or a
// freshly built object.
func Helpers(object []byte) (map[string]bool, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("read the object: %w", err)
	}

	called := make(map[string]bool)
	for _, program := range spec.Programs {
		for _, instruction := range program.Instructions {
			if instruction.OpCode.JumpOp() != asm.Call || instruction.Src == asm.PseudoCall {
				// A pseudo-call targets another BPF function, not a kernel helper, and is
				// skipped. Everything else is skipped too, which is the bound: memory accesses
				// compiled to ordinary loads are not collected.
				continue
			}
			called[asm.BuiltinFunc(instruction.Constant).String()] = true
		}
	}
	return called, nil
}

// Verify reports whether an object calls only helpers its program is allowed,
// and none forbidden outright. Run over a freshly compiled object, a
// user-memory read added to the metadata-only source fails it. A nil return is
// a guarantee about helper calls only (see the allowlist above).
func (p Program) Verify() error {
	called, err := Helpers(p.Object)
	if err != nil {
		return fmt.Errorf("%s: %w", p.Name, err)
	}
	return p.verifyHelpers(called)
}

// VerifyObject checks an arbitrary object against this program's allowlist,
// such as a just-built one.
func (p Program) VerifyObject(object []byte) error {
	called, err := Helpers(object)
	if err != nil {
		return fmt.Errorf("%s: %w", p.Name, err)
	}
	return p.verifyHelpers(called)
}

func (p Program) verifyHelpers(called map[string]bool) error {
	allowed := p.allowed()
	var offenders []string
	for name := range called {
		if reason, isForbidden := forbidden[name]; isForbidden {
			offenders = append(offenders, fmt.Sprintf("%s (%s)", name, reason))
			continue
		}
		if !allowed[name] {
			offenders = append(offenders, fmt.Sprintf("%s (not in the %s allowlist)", name, p.Name))
		}
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		return fmt.Errorf("%s program calls %s", p.Name, strings.Join(offenders, ", "))
	}
	return nil
}
