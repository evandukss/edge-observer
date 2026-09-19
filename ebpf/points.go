package ebpf

import (
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"slices"
)

// The BPF programs, by their names in the object: six transfer pairs and one
// entry-only close. A function's program is decided by its direction, whether
// its count is a register or an out-parameter, and whether the bytes are early
// data (package bpf; the catalogue in package probe).
const (
	progReadEntry        = "obs_read_entry"
	progReadReturn       = "obs_read_return"
	progWriteEntry       = "obs_write_entry"
	progWriteReturn      = "obs_write_return"
	progReadExEntry      = "obs_read_ex_entry"
	progReadExReturn     = "obs_read_ex_return"
	progWriteExEntry     = "obs_write_ex_entry"
	progWriteExReturn    = "obs_write_ex_return"
	progReadEarlyEntry   = "obs_read_early_entry"
	progReadEarlyReturn  = "obs_read_early_return"
	progWriteEarlyEntry  = "obs_write_early_entry"
	progWriteEarlyReturn = "obs_write_early_return"
	progWriteEx2Entry    = "obs_write_ex2_entry"
	progWriteEx2Return   = "obs_write_ex2_return"
	progFreeEntry        = "obs_free_entry"
)

// Discard is one resolved probe no point was made for, and why. The resolver
// found the symbol, so dropping it leaves an entry point nobody attaches to,
// whose bytes are absent while the rest looks right (probe, Support.Unknown).
type Discard struct {
	Symbol string
	Reason string
}

// PointsFrom turns the probes an adapter resolved into the points a session
// attaches, choosing each program pair from the catalogue. A probe it can make
// no point for is returned as a Discard: the catalogue and the programs
// disagree, a defect to report rather than attach short over.
func PointsFrom(probes []probe.Probe, runtime probe.Runtime) ([]Point, []Discard) {
	points := make([]Point, 0, len(probes))
	var discarded []Discard

	for _, resolved := range probes {
		function, known := runtime.Lookup(resolved.Symbol)
		if !known {
			discarded = append(discarded, Discard{
				Symbol: resolved.Symbol,
				Reason: "the catalogue names no such function, so no program was chosen for it",
			})
			continue
		}
		entry, back := programsFor(function)
		if entry == "" {
			discarded = append(discarded, Discard{
				Symbol: resolved.Symbol,
				Reason: "the catalogue names it, and no program observes a function that counts this way",
			})
			continue
		}
		points = append(points, Point{
			Symbol: resolved.Symbol,
			Path:   resolved.Path,
			Offset: resolved.Offset,
			Entry:  entry,
			Return: back,
		})
	}
	return points, discarded
}

// SocketPrograms is every socket entry point the association comes from, with
// its program and whether the call can operate on anything but a socket.
// sendto and its relatives cannot, so their descriptor is a socket; read and
// its relatives can, so theirs counts as network I/O only if this run saw the
// socket created (else a log write inside an SSL call would be taken for it).
// socket, accept and connect open an occupancy, close ends one, and dup2
// replaces one without any TLS call.
var SocketPrograms = map[string]string{
	"sendto":   "obs_sendto",
	"recvfrom": "obs_recvfrom",
	"sendmsg":  "obs_sendmsg",
	"recvmsg":  "obs_recvmsg",
	"read":     "obs_read",
	"write":    "obs_write",
	"readv":    "obs_readv",
	"writev":   "obs_writev",
	"connect":  "obs_connect",
	"close":    "obs_close",
	"dup2":     "obs_dup2",
}

// SocketReturnPrograms is the socket entry points whose answer, the descriptor
// they hand back, is in the return register.
var SocketReturnPrograms = map[string]string{
	"socket":  "obs_socket_return",
	"accept":  "obs_accept_return",
	"accept4": "obs_accept_return",
}

// SocketPoint is one socket entry point of the observed process's own C
// library. An Entry program reads the descriptor argument, a Return program the
// descriptor produced; a symbol is one or the other.
func SocketPoint(symbol, path string, offset uint64) Point {
	if program, returns := SocketReturnPrograms[symbol]; returns {
		return Point{Symbol: symbol, Path: path, Offset: offset, Return: program}
	}
	return Point{Symbol: symbol, Path: path, Offset: offset, Entry: SocketPrograms[symbol]}
}

// SocketSymbols is every symbol SocketPoint knows a program for, in a fixed
// order.
func SocketSymbols() []string {
	symbols := make([]string, 0, len(SocketPrograms)+len(SocketReturnPrograms))
	for symbol := range SocketPrograms {
		symbols = append(symbols, symbol)
	}
	for symbol := range SocketReturnPrograms {
		symbols = append(symbols, symbol)
	}
	slices.Sort(symbols)
	return symbols
}

// ForkPoint is the entry and return pair on fork in the C library an approved
// process runs. The caller builds it, knowing the file (a process in another
// mount namespace runs a C library reached through /proc/<pid>/root). Neither
// end admits anything (forkTracepoint does): the pair marks the window in which
// an unadmitted task's call is held rather than refused (the forking map).
func ForkPoint(symbol, path string, offset uint64) Point {
	return Point{
		Symbol: symbol, Path: path, Offset: offset,
		Entry:  ForkEntryProgram,
		Return: ForkReturnProgram,
	}
}

// programsFor is the mapping from a catalogued function to the BPF programs
// that observe it. Entry is empty for a function this does not attach to.
func programsFor(function probe.Function) (entry, back string) {
	switch function.Count {
	case probe.CountNone:
		// A connection ending. No count and no return.
		return progFreeEntry, ""
	case probe.CountReturned:
		if function.Direction == fragment.Sent {
			return progWriteEntry, progWriteReturn
		}
		return progReadEntry, progReadReturn
	case probe.CountOutParameter:
		// The program reading the count depends on which argument holds the
		// out-parameter, the catalogue's CountArg: SSL_write_ex2 keeps it at argument
		// five.
		switch {
		case function.CountArg == 5:
			return progWriteEx2Entry, progWriteEx2Return
		case function.Early && function.Direction == fragment.Sent:
			return progWriteEarlyEntry, progWriteEarlyReturn
		case function.Early:
			return progReadEarlyEntry, progReadEarlyReturn
		case function.Direction == fragment.Sent:
			return progWriteExEntry, progWriteExReturn
		default:
			return progReadExEntry, progReadExReturn
		}
	}
	return "", ""
}
