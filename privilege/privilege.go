// Package privilege drops the capabilities attachment needed once the probes
// are placed, and reports whether the process listens on anything. Both are
// readable from /proc, so an operator can check them independently.
package privilege

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// capabilityVersion is capability interface version 3 (kernel 2.6.26+), whose
// payload is two words wide.
const capabilityVersion = 0x20080522

// noNewPrivileges is PR_SET_NO_NEW_PRIVS: no exec can regain what Drop gave up.
const noNewPrivileges = 38

type capabilityHeader struct {
	version uint32
	pid     int32
}

type capabilitySet struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

// Drop gives up every capability this process holds, irreversibly. It is
// called once the probes are placed.
//
// Capabilities are per thread, so this uses the runtime's all-threads call,
// which refuses in a cgo program; that refusal is returned, never swallowed.
func Drop() error {
	// All three sets, inheritable included, so an exec carries nothing forward.
	header := capabilityHeader{version: capabilityVersion}
	var sets [2]capabilitySet

	if _, _, err := syscall.AllThreadsSyscall(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&header)),
		uintptr(unsafe.Pointer(&sets[0])), 0); err != 0 {
		return fmt.Errorf("drop the capabilities: %w (a program linked against C cannot do this to every thread)", err)
	}

	if _, _, err := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, noNewPrivileges, 1, 0); err != 0 {
		return fmt.Errorf("refuse new privileges: %w", err)
	}
	return nil
}

// Effective is the capabilities the process whose /proc directory is proc
// holds now. Zero is what Drop leaves.
func Effective(proc string) (uint64, error) {
	content, err := os.ReadFile(filepath.Join(proc, "status"))
	if err != nil {
		return 0, fmt.Errorf("read what this process holds: %w", err)
	}

	for line := range strings.Lines(string(content)) {
		name, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found || name != "CapEff" {
			continue
		}
		held, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		if err != nil {
			return 0, fmt.Errorf("read what this process holds: %w", err)
		}
		return held, nil
	}
	return 0, errors.New("read what this process holds: the kernel reported no effective set")
}

// Socket is one socket this process is listening on.
type Socket struct {
	// Kind is the /proc/net table the socket was read from.
	Kind string

	// Address is where it is listening, as the kernel writes it.
	Address string
}

func (s Socket) String() string { return s.Kind + " " + s.Address }

// listening is the listening state in the network tables' hexadecimal.
const listening = "0A"

// unixListening is the same state in /proc/net/unix's decimal.
const unixListening = "01"

// Listening is every socket the process is accepting connections on. The
// kernel's tables list the whole namespace; the process's own socket inodes
// narrow them. The observer should listen on nothing, and this checks that
// against the kernel rather than the code.
func Listening(proc string) ([]Socket, error) {
	held, err := socketInodes(proc)
	if err != nil {
		return nil, err
	}
	if len(held) == 0 {
		return nil, nil
	}

	// Zero-based columns: state, inode and address. The unix table differs from
	// the network tables, and omits the path for an abstract socket.
	tables := []struct {
		path                  string
		state, inode, address int
	}{
		{"net/tcp", 3, 9, 1},
		{"net/tcp6", 3, 9, 1},
		{"net/unix", 5, 6, 7},
	}

	var found []Socket
	for _, table := range tables {
		sockets, err := listeningIn(filepath.Join(proc, table.path), table.path, held, table.state, table.inode, table.address)
		if err != nil {
			return nil, err
		}
		found = append(found, sockets...)
	}
	return found, nil
}

// socketInodes is the inode of every socket this process holds open.
func socketInodes(proc string) (map[string]bool, error) {
	directory := filepath.Join(proc, "fd")

	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read this process's open files: %w", err)
	}

	held := make(map[string]bool, len(entries))
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(directory, entry.Name()))
		if err != nil {
			// A descriptor that closed during the read.
			continue
		}
		inode, found := strings.CutPrefix(target, "socket:[")
		if !found {
			continue
		}
		held[strings.TrimSuffix(inode, "]")] = true
	}
	return held, nil
}

// listeningIn is the listening sockets in one kernel table that the process
// holds. state, inode and address are the columns.
func listeningIn(path, kind string, held map[string]bool, state, inode, address int) ([]Socket, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// A kernel built without the family.
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var found []Socket
	for line := range strings.Lines(string(content)) {
		fields := strings.Fields(line)
		if len(fields) <= inode || len(fields) <= state {
			continue
		}
		if !held[fields[inode]] {
			continue
		}
		if fields[state] != listening && fields[state] != unixListening {
			continue
		}
		where := ""
		if address < len(fields) {
			where = fields[address]
		}
		found = append(found, Socket{Kind: kind, Address: where})
	}
	return found, nil
}
