package bpf

// The counter registry, by each index's name in the program (OBS_STAT_* in
// ssl.bpf.h). It lives beside the program because there are several readers
// and one program. A moved index is still read, and its number filed under
// the wrong meaning; StatsAreTheProgramsOwn pins these against the defines.
const (
	StatReserveFailed        uint32 = 0
	StatUnmatched            uint32 = 1
	StatDescendants          uint32 = 2
	StatRefused              uint32 = 3
	StatCallUnrecorded       uint32 = 4
	StatReadUnrecorded       uint32 = 5
	StatDescendantUnrecorded uint32 = 6
	StatDenialUnrecorded     uint32 = 7
	StatDeferredDiscarded    uint32 = 8
	StatSocketUnrecorded     uint32 = 9
	StatBindingUnrecorded    uint32 = 10
	StatUnmeasurableCall     uint32 = 11
	StatUnauthenticated      uint32 = 12
	StatChildUnnameable      uint32 = 13
	StatStaleBindingDropped  uint32 = 14
	StatChildNSUnenumerated  uint32 = 15
	StatSocketFDInvalid      uint32 = 16
	StatSocketOutsideCall    uint32 = 17
	StatSocketUnlocatable    uint32 = 18
	StatSocketNoLifetime     uint32 = 19
	StatSocketRecorded       uint32 = 20

	// The kernel evidence group's, counting what happened to a call's operation
	// frames.
	StatOperationUnrecorded  uint32 = 21
	StatOperationOverwritten uint32 = 22
	StatOperationUnmatched   uint32 = 23
	StatEvidenceUnreadable   uint32 = 24
	StatSocketUndiscovered   uint32 = 25
	StatDiscoveryContended   uint32 = 26
)

// Stats is every counter this package names, against the define it mirrors.
var Stats = map[string]uint32{
	"OBS_STAT_RESERVE_FAILED":        StatReserveFailed,
	"OBS_STAT_UNMATCHED":             StatUnmatched,
	"OBS_STAT_DESCENDANTS":           StatDescendants,
	"OBS_STAT_REFUSED":               StatRefused,
	"OBS_STAT_CALL_UNRECORDED":       StatCallUnrecorded,
	"OBS_STAT_READ_UNRECORDED":       StatReadUnrecorded,
	"OBS_STAT_DESCENDANT_UNRECORDED": StatDescendantUnrecorded,
	"OBS_STAT_DENIAL_UNRECORDED":     StatDenialUnrecorded,
	"OBS_STAT_DEFERRED_DISCARDED":    StatDeferredDiscarded,
	"OBS_STAT_SOCKET_UNRECORDED":     StatSocketUnrecorded,
	"OBS_STAT_BINDING_UNRECORDED":    StatBindingUnrecorded,
	"OBS_STAT_UNMEASURABLE_CALL":     StatUnmeasurableCall,
	"OBS_STAT_UNAUTHENTICATED":       StatUnauthenticated,
	"OBS_STAT_CHILD_UNNAMEABLE":      StatChildUnnameable,
	"OBS_STAT_STALE_BINDING_DROPPED": StatStaleBindingDropped,
	"OBS_STAT_CHILD_NS_UNENUMERATED": StatChildNSUnenumerated,
	"OBS_STAT_SOCKET_FD_INVALID":     StatSocketFDInvalid,
	"OBS_STAT_SOCKET_OUTSIDE_CALL":   StatSocketOutsideCall,
	"OBS_STAT_SOCKET_UNLOCATABLE":    StatSocketUnlocatable,
	"OBS_STAT_SOCKET_NO_LIFETIME":    StatSocketNoLifetime,
	"OBS_STAT_SOCKET_RECORDED":       StatSocketRecorded,

	"OBS_STAT_OPERATION_UNRECORDED":  StatOperationUnrecorded,
	"OBS_STAT_OPERATION_OVERWRITTEN": StatOperationOverwritten,
	"OBS_STAT_OPERATION_UNMATCHED":   StatOperationUnmatched,
	"OBS_STAT_EVIDENCE_UNREADABLE":   StatEvidenceUnreadable,
	"OBS_STAT_SOCKET_UNDISCOVERED":   StatSocketUndiscovered,
	"OBS_STAT_DISCOVERY_CONTENDED":   StatDiscoveryContended,
}

// The function registry, by each code's name in the program (OBS_FUNC_* in
// ssl.bpf.h). The codes index a per-function array, so a code that moves
// without its constant files numbers under the wrong function.
const (
	FuncRead       uint32 = 1
	FuncWrite      uint32 = 2
	FuncReadEx     uint32 = 3
	FuncWriteEx    uint32 = 4
	FuncReadEarly  uint32 = 5
	FuncWriteEarly uint32 = 6
	FuncWriteEx2   uint32 = 7
	FuncCodeBound  uint32 = 8
)

// Functions is every function code this package names, against the define it
// mirrors.
var Functions = map[string]uint32{
	"OBS_FUNC_READ":        FuncRead,
	"OBS_FUNC_WRITE":       FuncWrite,
	"OBS_FUNC_READ_EX":     FuncReadEx,
	"OBS_FUNC_WRITE_EX":    FuncWriteEx,
	"OBS_FUNC_READ_EARLY":  FuncReadEarly,
	"OBS_FUNC_WRITE_EARLY": FuncWriteEarly,
	"OBS_FUNC_WRITE_EX2":   FuncWriteEx2,
}

// BindingPrograms is every program that records a descriptor against the call
// in flight on its thread. A descriptor is what the process passed, not the
// socket the bytes crossed, which comes from the object the kernel acquired
// (package ebpf, KernelPoints). It is not every socket program: of fourteen
// socket entry points only these record a descriptor inside a call, and
// counting the rest would claim a binding capability a session lacks. It is
// checked against the program's call sites.
var BindingPrograms = map[string]bool{
	"obs_sendto":   true,
	"obs_recvfrom": true,
	"obs_sendmsg":  true,
	"obs_recvmsg":  true,
	"obs_read":     true,
	"obs_write":    true,
	"obs_readv":    true,
	"obs_writev":   true,
}

// EntryPrograms is the code each entry program files its in-flight call under:
// a third spelling of the fact (the call site is the second), so the source
// check compares all three.
var EntryPrograms = map[string]uint32{
	"obs_read_entry":        FuncRead,
	"obs_write_entry":       FuncWrite,
	"obs_read_ex_entry":     FuncReadEx,
	"obs_write_ex_entry":    FuncWriteEx,
	"obs_read_early_entry":  FuncReadEarly,
	"obs_write_early_entry": FuncWriteEarly,
	"obs_write_ex2_entry":   FuncWriteEx2,
}

// SocketOnlySyscalls is every followed syscall that can only operate on a
// socket, by the program's own defines, checked against its source. One
// missing reports an unresolved operation instead of a stated limit. The
// scalar and vector family is absent: it can operate on an ordinary file, and
// the classifier settles it by the acquired file's inode mode.
var SocketOnlySyscalls = map[string]bool{
	"OBS_SYS_SENDTO":   true,
	"OBS_SYS_RECVFROM": true,
	"OBS_SYS_SENDMSG":  true,
	"OBS_SYS_RECVMSG":  true,
	"OBS_SYS_RECVMMSG": true,
	"OBS_SYS_SENDMMSG": true,
}
