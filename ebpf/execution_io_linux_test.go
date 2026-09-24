//go:build attach

package ebpf_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/process"
	"golang.org/x/sys/unix"
)

type executionIO struct {
	path    string
	syscall int32
	count   uint64
}

// Only the inspection goroutine's locked OS thread is filtered. The other
// thread supervises actual kernel operations, not an implementation callback.
// Exiting the locked goroutine retires the filtered thread; it is never reused.
func executionSupervised(t *testing.T, f executionFixture, intervene func(executionIO) unix.Errno) (process.Execution, []executionIO) {
	t.Helper()
	f.syncThreads() // Fixture preparation is outside measured reader IO.
	listener := make(chan int)
	result := make(chan process.Execution, 1)
	failed := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		filter := []unix.SockFilter{{Code: classicLoadWordAbsolute, K: 0}}
		for _, number := range []uint32{uint32(unix.SYS_OPENAT), uint32(unix.SYS_OPENAT2), uint32(unix.SYS_GETDENTS64)} {
			filter = append(filter, unix.SockFilter{Code: classicJumpEqual, Jf: 1, K: number}, unix.SockFilter{Code: classicReturn, K: unix.SECCOMP_RET_USER_NOTIF})
		}
		filter = append(filter, unix.SockFilter{Code: classicReturn, K: seccompReturnAllow})
		program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			failed <- err
			return
		}
		fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, seccompSetModeFilter, unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, uintptr(unsafe.Pointer(&program)))
		if errno != 0 {
			failed <- errno
			return
		}
		listener <- int(fd)
		result <- process.Inspect(f.root, f.pid, f.group)
	}()
	var fd int
	select {
	case fd = <-listener:
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("fixture: syscall listener was not installed")
	}
	defer func() { _ = unix.Close(fd) }()
	memory, err := os.Open("/proc/self/mem")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = memory.Close() }()
	var seen []executionIO
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case read := <-result:
			return read, seen
		default:
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if _, err := unix.Poll(poll, 20); err != nil && err != unix.EINTR {
			t.Fatal(err)
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			continue
		}
		var request seccompNotification
		if err := notification(fd, &request); err != nil {
			t.Fatal(err)
		}
		op := executionIO{syscall: request.Data.Number}
		if request.Data.Number == int32(unix.SYS_GETDENTS64) {
			op.path, err = os.Readlink(fmt.Sprintf("/proc/self/fd/%d", request.Data.Arguments[0]))
			op.count = request.Data.Arguments[2]
		} else {
			buf := make([]byte, 4096)
			n, readErr := memory.ReadAt(buf, int64(request.Data.Arguments[1]))
			if n == 0 {
				t.Fatal(readErr)
			}
			end := bytes.IndexByte(buf[:n], 0)
			if end < 0 {
				t.Fatal("fixture: unterminated syscall path")
			}
			op.path = string(buf[:end])
			if !filepath.IsAbs(op.path) {
				base, readErr := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", int32(request.Data.Arguments[0])))
				if readErr != nil {
					t.Fatal(readErr)
				}
				op.path = filepath.Join(base, op.path)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		var refusal unix.Errno
		if strings.HasPrefix(op.path, f.root+"/") || op.path == f.root {
			seen = append(seen, op)
			if intervene != nil {
				refusal = intervene(op)
			}
		}
		response := seccompResponse{ID: request.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
		if refusal != 0 {
			response.Flags = 0
			response.Error = -int32(refusal)
		}
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SECCOMP_IOCTL_NOTIF_SEND, uintptr(unsafe.Pointer(&response)))
		if errno != 0 {
			t.Fatal(errno)
		}
	}
	t.Fatal("fixture: inspection did not finish within its bounded read window")
	return process.Execution{}, nil
}

func TestExecutionKernelRefusalNamesItsOperation(t *testing.T) {
	for _, refusal := range []unix.Errno{unix.EACCES, unix.EPERM} {
		t.Run(refusal.Error(), func(t *testing.T) {
			f := newExecutionFixture(t, "S")
			injected := 0
			read, _ := executionSupervised(t, f, func(op executionIO) unix.Errno {
				if op.path == f.at("status") {
					injected++
					return refusal
				}
				return 0
			})
			if injected == 0 {
				t.Fatal("fixture: refusal never reached the identity read")
			}
			got := executionResult(t, f.selection(), read, ebpf.ExecutionIndeterminate)
			if !strings.Contains(got.Evidence, refusal.Error()) || !strings.Contains(got.Evidence, "status") {
				t.Errorf("lost kernel refusal: %s", got.Evidence)
			}
		})
	}
}

func TestExecutionPIDTurnoverBetweenIdentityAndWitness(t *testing.T) {
	f := newExecutionFixture(t, "Z")
	f.task(4102, "S", 12888, 23)
	changed := false
	read, _ := executionSupervised(t, f, func(op executionIO) unix.Errno {
		if !changed && op.path == f.at("task/4102/stat") {
			changed = true
			executionWrite(t, f.at("stat"), executionStat(f.pid, "S", 99999))
			executionWrite(t, f.at("status"), executionStatus(f.pid, f.pid, 17, 17, "S"))
			f.syncThreads()
		}
		return 0
	})
	if !changed {
		t.Fatal("fixture: replacement never arrived between identity and witness")
	}
	got := ebpf.WhatBecameOf(f.selection(), read)
	if got.State != ebpf.ExecutionEnded && got.State != ebpf.ExecutionIndeterminate {
		t.Errorf("replacement borrowed as the original's live witness: %+v", got)
	}
}

func TestExecutionRefusedSiblingCanBeReplacedByAnAuthenticatedWitness(t *testing.T) {
	for _, refusal := range []unix.Errno{unix.EACCES, unix.EPERM} {
		for _, control := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/control=%t", refusal, control), func(t *testing.T) {
				f := newExecutionFixture(t, "Z")
				f.task(4102, "S", 12888, 23)
				if control {
					f.task(4103, "S", 12999, 24)
				}
				injected := 0
				var refusedTID int32
				read, _ := executionSupervised(t, f, func(op executionIO) unix.Errno {
					// Directory order is unspecified. Refuse the first declared
					// candidate actually read, then let the other supply evidence.
					for _, tid := range []int32{4102, 4103} {
						if refusedTID == 0 && op.path == f.at(fmt.Sprintf("task/%d/stat", tid)) {
							refusedTID = tid
						}
					}
					if refusedTID != 0 && op.path == f.at(fmt.Sprintf("task/%d/stat", refusedTID)) {
						injected++
						return refusal
					}
					return 0
				})
				if injected == 0 {
					t.Fatal("fixture: refusal never reached the candidate")
				}
				want := ebpf.ExecutionIndeterminate
				if control {
					want = ebpf.GrantEndedWhileRunning
				}
				got := executionResult(t, f.selection(), read, want)
				if !strings.Contains(got.Evidence, refusal.Error()) {
					t.Errorf("candidate refusal lost: %s", got.Evidence)
				}
				witnessTID := int32(4102+4103) - refusedTID
				if control && read.Witness.TID != witnessTID {
					t.Errorf("refused task supplied the witness: %+v", read.Witness)
				}
			})
		}
	}
}

func TestExecutionListedTIDTurnoverHasABoundedRecovery(t *testing.T) {
	for _, replacement := range []string{"same-group", "other-group", "gone"} {
		t.Run(replacement, func(t *testing.T) {
			f := newExecutionFixture(t, "Z")
			f.task(4102, "S", 12888, 23)
			attempts := 0
			read, ops := executionSupervised(t, f, func(op executionIO) unix.Errno {
				if op.path == f.at("task/4102/stat") {
					attempts++
					if attempts == 1 {
						if replacement == "other-group" {
							executionWrite(t, f.at("task/4102/status"), executionStatus(9001, 4102, 44, 23, "S"))
						}
						return unix.ENOENT
					}
					if replacement == "gone" {
						return unix.ENOENT
					}
				}
				return 0
			})
			if attempts < 2 {
				t.Fatalf("listed TID never received its bounded retry: attempts=%d ops=%+v", attempts, ops)
			}
			want := ebpf.ExecutionIndeterminate
			if replacement == "same-group" {
				want = ebpf.GrantEndedWhileRunning
			}
			got := executionResult(t, f.selection(), read, want)
			if replacement == "same-group" {
				retained := 0
				for _, failure := range got.Reading.Failed {
					if errors.Is(failure.Err, unix.ENOENT) && strings.Contains(failure.What, "4102") {
						retained++
					}
				}
				if retained != 1 || !strings.Contains(got.Evidence, unix.ENOENT.Error()) {
					t.Errorf("successful retry erased its earlier failed operation: retained=%d reading=%+v evidence=%s", retained, got.Reading, got.Evidence)
				}
			}
			if attempts > 3 {
				t.Errorf("candidate retry was not bounded: %d", attempts)
			}
		})
	}
}

func executionMeasuredDirentSize(t *testing.T) int {
	t.Helper()
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "10000"), 0755); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	buffer := make([]byte, 8192)
	n, err := unix.ReadDirent(fd, buffer)
	if err != nil {
		t.Fatal(err)
	}
	nameAt := int(unsafe.Offsetof(unix.Dirent{}.Name))
	lengthAt := int(unsafe.Offsetof(unix.Dirent{}.Reclen))
	for offset := 0; offset < n; {
		if n-offset <= nameAt {
			t.Fatal("fixture: kernel returned a short dirent")
		}
		size := int(binary.NativeEndian.Uint16(buffer[offset+lengthAt:]))
		if size <= nameAt || size > n-offset {
			t.Fatal("fixture: invalid native dirent length")
		}
		name := buffer[offset+nameAt : offset+size]
		end := bytes.IndexByte(name, 0)
		if end >= 0 && string(name[:end]) == "10000" {
			return size
		}
		offset += size
	}
	t.Fatal("fixture: the kernel did not enumerate the declared sample name")
	return 0
}

func TestExecutionBudgetCountsActualIO(t *testing.T) {
	construction := time.Now()
	f := newExecutionFixture(t, "Z")
	for i := int32(4200); i < 4400; i++ {
		f.task(i, "Z", 13000+uint64(i), i-4000)
	}
	// Measure the native record for these fixed-width names. More than twice
	// 64 full buffers cannot be enumerated within 64 operations, regardless of
	// how many entries the reader chooses to deliver per ReadDir call.
	recordBytes := executionMeasuredDirentSize(t)
	const budget, batchBytes = 64, 8192
	additional := 2 * (budget + 1) * (batchBytes / recordBytes)
	if additional <= 0 || 10000+additional > 100000 {
		t.Fatalf("fixture: unsupported measured dirent size %d", recordBytes)
	}
	for i := 0; i < additional; i++ {
		if err := os.Mkdir(f.at(fmt.Sprintf("task/%05d", 10000+i)), 0755); err != nil {
			t.Fatal(err)
		}
	}
	f.syncThreads()
	constructed := time.Since(construction)
	inspection := time.Now()
	read, ops := executionSupervised(t, f, nil)
	files, batches, entries := 0, 0, 0
	for _, op := range ops {
		if op.syscall == int32(unix.SYS_GETDENTS64) {
			batches++
			if op.count == 0 || op.count > 8192 {
				t.Errorf("unbounded task enumeration request: %+v", op)
			}
		}
		if strings.HasSuffix(op.path, "/stat") || strings.HasSuffix(op.path, "/status") {
			files++
		}
		if strings.Contains(op.path, "/task/") && strings.HasSuffix(op.path, "/stat") {
			entries++
		}
	}
	t.Logf("fixture: native dirent=%d bytes, additional entries=%d, build=%s, inspection=%s, file attempts=%d, getdents calls=%d", recordBytes, additional, constructed, time.Since(inspection), files, batches)
	if batches == 0 || entries == 0 {
		t.Fatalf("fixture: no actual task walk was measured: %+v", ops)
	}
	if files+batches > 64 || entries >= 200 {
		t.Errorf("budget applied after unbounded work: files=%d batches=%d task reads=%d", files, batches, entries)
	}
	if !read.Capped || read.Spent != 64 {
		t.Errorf("partial walk lost the chosen 64-operation cap: %+v", read)
	}
	executionResult(t, f.selection(), read, ebpf.ExecutionIndeterminate)
}

func TestExecutionNewSiblingAfterEnumerationCannotBeReportedEnded(t *testing.T) {
	f := newExecutionFixture(t, "Z")
	f.task(4102, "S", 12888, 23)
	inserted, losses := false, 0
	read, ops := executionSupervised(t, f, func(op executionIO) unix.Errno {
		if op.path == f.at("task/4102/stat") {
			losses++
			if !inserted {
				// After the original listing, the old worker creates a sibling
				// and exits before its stat can be read. The new sibling's birth
				// and namespace membership are fixture facts, not reader output.
				f.task(4103, "S", 12999, 24)
				f.syncThreads()
				inserted = true
			}
			return unix.ENOENT
		}
		return 0
	})
	if !inserted || losses < 2 {
		t.Fatalf("fixture: listing/lost-task/retry ordering was not established: inserted=%t losses=%d ops=%+v", inserted, losses, ops)
	}
	stat, err := os.ReadFile(f.at("task/4103/stat"))
	if err != nil || string(stat) != executionStatThreads(executionStat(4103, "S", 12999), 3) {
		t.Fatalf("fixture: newly created live sibling was not retained: %s %v", stat, err)
	}
	ns, err := os.Stat(f.at("task/4103/ns/pid"))
	if err != nil {
		t.Fatal(err)
	}
	leaderNS, err := os.Stat(f.at("ns/pid"))
	if err != nil || !os.SameFile(ns, leaderNS) {
		t.Fatalf("fixture: sibling namespace is not the group's: %v", err)
	}
	got := ebpf.WhatBecameOf(f.selection(), read)
	if got.Selection.Instance.Key() != f.selection().Instance.Key() {
		t.Errorf("turnover changed the admission being answered: %+v", got.Selection)
	}
	if got.State == ebpf.ExecutionEnded {
		t.Errorf("a same-group live sibling created after enumeration was reported ended: %+v; operations=%+v", got, ops)
	}
	if got.State == ebpf.ExecutionIndeterminate && len(got.Reading.Failed) == 0 && !got.Reading.Capped {
		t.Errorf("unresolved turnover lost its failed operation: %+v", got)
	}
}
