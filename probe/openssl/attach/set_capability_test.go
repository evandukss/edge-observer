//go:build attach

package attach_test

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
)

func sentRecords(records []fragment.Record, pid int32) []fragment.Record {
	var found []fragment.Record
	for _, record := range records {
		if record.Process.PID == pid && record.Direction == fragment.Sent {
			found = append(found, record)
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Offset < found[j].Offset })
	return found
}

func joined(records []fragment.Record) []byte {
	var payload []byte
	for _, record := range records {
		payload = append(payload, record.Payload...)
	}
	return payload
}

func waitForSentMarkers(t *testing.T, sink *collected, wanted map[int32]string) []fragment.Record {
	t.Helper()
	var taken []fragment.Record
	for range 500 {
		taken = sink.taken()
		complete := true
		for pid, marker := range wanted {
			if !bytes.Contains(joined(sentRecords(taken, pid)), []byte(marker)) {
				complete = false
			}
		}
		if complete {
			time.Sleep(300 * time.Millisecond)
			return sink.taken()
		}
		time.Sleep(10 * time.Millisecond)
	}
	return taken
}

func TestTwoSelectedProcessesInOneCgroupAreCapturedExactlyOnce(t *testing.T) {
	port := serving(t)
	one := speaking(t, port)
	two := speaking(t, port)
	shared := fmt.Sprintf("obs-selected-set-%d", os.Getpid())
	intoCgroup(t, shared, one.process.PID)
	intoCgroup(t, shared, two.process.PID)
	if first, second := unifiedCgroup(t, one.process.PID), unifiedCgroup(t, two.process.PID); first != second {
		t.Fatalf("the selected processes are in %s and %s, so whole-set placement was not measured", first, second)
	}

	sink := &collected{}
	live, err := attach.NeweBPF(process.Approval{}).Attach(requesting(one.process, two.process), capture.New(sink))
	if err != nil {
		t.Fatalf("attach to the two-process approved set: %v", err)
	}
	t.Cleanup(func() { _ = live.Close() })

	markers := map[int32]string{
		one.process.PID: "selected-process-one",
		two.process.PID: "selected-process-two",
	}
	one.ask(t, markers[one.process.PID])
	two.ask(t, markers[two.process.PID])
	taken := waitForSentMarkers(t, sink, markers)

	for _, conversation := range []conversation{one, two} {
		marker := markers[conversation.process.PID]
		source := []byte("GET /?asked=" + marker + " HTTP/1.1\r\nHost: localhost\r\n\r\n")
		records := sentRecords(taken, conversation.process.PID)
		if len(records) == 0 {
			t.Errorf("selected pid %d produced no sent records, so exactly-once capture was not measured", conversation.process.PID)
			continue
		}
		payload := joined(records)
		if copies := bytes.Count(payload, []byte(marker)); copies != 1 {
			t.Errorf("selected pid %d's bytes appear %d times, want exactly once; payload %q",
				conversation.process.PID, copies, payload)
		}

		var moved uint64
		for i, record := range records {
			if i == 0 && record.Offset != 0 {
				t.Errorf("selected pid %d's stream begins at offset %d, want 0", conversation.process.PID, record.Offset)
			}
			if i > 0 && record.Offset != records[i-1].End() {
				t.Errorf("selected pid %d advances from end %d to offset %d",
					conversation.process.PID, records[i-1].End(), record.Offset)
			}
			moved += uint64(record.Length)
		}
		if moved != uint64(len(source)) {
			t.Errorf("selected pid %d advanced %d offsets for a %d-byte call; each byte must advance once",
				conversation.process.PID, moved, len(source))
		}
	}
}

const deniedCapabilitiesChild = "OBSERVER_TEST_DENIED_CAPABILITIES"

func denyBPFCapability(t *testing.T) {
	t.Helper()
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capget(&header, &data[0]); err != nil {
		t.Fatalf("read this process's Linux capabilities: %v", err)
	}
	for _, capability := range []int{unix.CAP_SYS_ADMIN, unix.CAP_PERFMON, unix.CAP_BPF} {
		word := capability / 32
		mask := ^(uint32(1) << uint(capability%32))
		data[word].Effective &= mask
		data[word].Permitted &= mask
	}
	if err := unix.Capset(&header, &data[0]); err != nil {
		t.Fatalf("deny this process BPF capability: %v", err)
	}
}

// exerciseDeniedCapability asks for the zero request on a process that cannot
// load the program: nothing else copies plaintext, so the whole attachment is
// refused.
func exerciseDeniedCapability(t *testing.T) {
	client := speaking(t, serving(t))
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	denyBPFCapability(t)
	adapter := attach.NeweBPF(process.Approval{})

	live, err := adapter.Attach(requesting(client.process), capture.New(&collected{}))
	if live != nil {
		capability := live.Capability()
		_ = live.Close()
		t.Fatalf("a request attached with BPF capability denied, reporting capability %+v", capability)
	}
	if !errors.Is(err, probe.ErrDegraded) || !strings.Contains(err.Error(), "will not run") {
		t.Fatalf("a request got %v, want ErrDegraded naming the program this host will not run", err)
	}
}

func TestAPlaintextRequirementFailsClosedWhenBPFCapabilityIsDenied(t *testing.T) {
	if os.Getenv(deniedCapabilitiesChild) == "1" {
		exerciseDeniedCapability(t)
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestAPlaintextRequirementFailsClosedWhenBPFCapabilityIsDenied$")
	command.Env = append(os.Environ(), deniedCapabilitiesChild+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("the capability-denied attach did not fail closed:\n%s\nchild error: %v", strings.TrimSpace(string(output)), err)
	}
}

func copiedLibraryConversation(t *testing.T, port int, source process.Process) conversation {
	t.Helper()
	mappings, err := process.Mappings(procfs, source.PID)
	if err != nil {
		t.Fatalf("read the control process's mappings: %v", err)
	}
	var library string
	for _, mapping := range mappings {
		if mapping.Executable && strings.HasPrefix(filepath.Base(mapping.Path), "libssl.so") {
			library = mapping.Path
			break
		}
	}
	if library == "" {
		t.Fatalf("pid %d maps no executable libssl object", source.PID)
	}
	directory := t.TempDir()
	copyPath := filepath.Join(directory, filepath.Base(library))
	content, err := os.ReadFile(library)
	if err != nil {
		t.Fatalf("read the control libssl object: %v", err)
	}
	if err := os.WriteFile(copyPath, content, 0o755); err != nil {
		t.Fatalf("copy the libssl object: %v", err)
	}

	command := exec.Command("openssl", "s_client", "-quiet", "-no_ign_eof",
		"-connect", fmt.Sprintf("127.0.0.1:%d", port))
	command.Env = append(os.Environ(), "LD_LIBRARY_PATH="+directory)
	send, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("copied-library client stdin: %v", err)
	}
	receive, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("copied-library client stdout: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start a client using the copied library: %v", err)
	}
	t.Cleanup(func() {
		_ = send.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	return conversation{
		process: loaded(t, int32(command.Process.Pid)),
		send:    send,
		receive: bufio.NewReader(receive),
	}
}

func openFileDescriptors(t *testing.T) uint64 {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("count open file descriptors: %v", err)
	}
	return uint64(len(entries))
}

const unloadableMemberChild = "OBSERVER_TEST_UNLOADABLE_MEMBER"

// exerciseUnloadableMember gives one placement the descriptors it needs and a
// second process its own library, so the kernel cannot load the second
// placement and the whole attachment is refused.
func exerciseUnloadableMember(t *testing.T) {
	port := serving(t)
	one := speaking(t, port)
	two := copiedLibraryConversation(t, port, one.process)
	adapter := attach.NeweBPF(process.Approval{})

	baseline := openFileDescriptors(t)
	control, err := adapter.Attach(requesting(one.process), capture.New(&collected{}))
	if err != nil {
		t.Fatalf("measure one BPF placement: %v", err)
	}
	withBPF := openFileDescriptors(t)
	if withBPF <= baseline {
		_ = control.Close()
		t.Fatalf("one BPF placement opened no file descriptors: before %d, after %d", baseline, withBPF)
	}
	if capability := control.Capability(); capability.Backend != probe.BPF || !capability.Payload {
		_ = control.Close()
		t.Fatalf("the positive-control placement has capability %+v, want plaintext BPF", capability)
	}
	if err := control.Close(); err != nil {
		t.Fatalf("close the measured BPF placement: %v", err)
	}

	var limits unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limits); err != nil {
		t.Fatalf("read the file-descriptor limit: %v", err)
	}
	needed := withBPF - baseline
	limited := baseline + needed + 8
	if limited >= limits.Max {
		t.Fatalf("cannot make a selective attachment limit below hard limit %d from baseline %d and BPF cost %d",
			limits.Max, baseline, needed)
	}
	limits.Cur = limited
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limits); err != nil {
		t.Fatalf("set a file-descriptor limit for one BPF placement: %v", err)
	}

	live, err := adapter.Attach(requesting(one.process, two.process), capture.New(&collected{}))
	if live != nil {
		capability := live.Capability()
		_ = live.Close()
		t.Fatalf("a set with a member the kernel could not load was handed back, reporting %+v", capability)
	}
	if !errors.Is(err, probe.ErrDegraded) || !strings.Contains(err.Error(), "will not run") {
		t.Fatalf("a set with a member the kernel could not load returned %v, want ErrDegraded naming "+
			"the program this host will not run", err)
	}
}

func TestAProcessSetIsRefusedWholeWhenOneMemberCannotLoadTheProgram(t *testing.T) {
	if os.Getenv(unloadableMemberChild) == "1" {
		exerciseUnloadableMember(t)
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestAProcessSetIsRefusedWholeWhenOneMemberCannotLoadTheProgram$")
	command.Env = append(os.Environ(), unloadableMemberChild+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("the set with an unloadable member was not refused whole:\n%s\nchild error: %v",
			strings.TrimSpace(string(output)), err)
	}
}
