//go:build attach

package attach_test

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
)

// The actor makes real OpenSSL calls and real syscalls; only its BIO transport
// is controlled, and its binary control channel writes no log line. Peers check
// bytes and addresses independently of anything the observer reports.
type socketEvidenceActor struct {
	input, output *os.File
	process       process.Process
	peers         [2]net.Conn
	fd            int32
	collected     *collected
	live          probe.Attachment
}

func socketEvidence(t *testing.T) *socketEvidenceActor {
	t.Helper()
	return socketEvidenceWithLibc(t, false)
}

func socketEvidenceWithLibc(t *testing.T, short bool) *socketEvidenceActor {
	t.Helper()
	return socketEvidenceOnNetwork(t, short, "tcp4")
}

func socketEvidenceOnNetwork(t *testing.T, short bool, network string) *socketEvidenceActor {
	t.Helper()
	return socketEvidenceAttaching(t, short, network, beforeItsSocketsExist)
}

// when the observer attaches, relative to the actor's sockets existing. The two
// orders exercise different producers: one that learns an endpoint only from a
// state transition has nothing to observe for a connection already open, and a
// process is often admitted after its sockets exist.
type socketEvidenceAttachOrder bool

const (
	beforeItsSocketsExist socketEvidenceAttachOrder = true
	afterItsSocketsExist  socketEvidenceAttachOrder = false
)

func socketEvidenceAttaching(t *testing.T, short bool, network string,
	order socketEvidenceAttachOrder) *socketEvidenceActor {
	t.Helper()
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "socket-evidence")
	if out, err := exec.Command("cc", "-Wall", "-Werror", "-O0", "-o", binaryPath,
		"testdata/socket_evidence.c", "-lssl", "-lcrypto", "-pthread").CombinedOutput(); err != nil {
		t.Fatalf("compile controlled BIO actor: %v\n%s", err, out)
	}
	cert, key := certificate(t)
	actorRead, input, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	output, actorWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binaryPath, cert, key)
	if short {
		command.Env = append(os.Environ(), "LD_LIBRARY_PATH="+shortSocketLibc(t, dir))
	}
	command.ExtraFiles = []*os.File{actorRead, actorWrite}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = actorRead.Close()
	_ = actorWrite.Close()
	t.Cleanup(func() { _ = input.Close(); _ = output.Close(); _ = command.Process.Kill(); _ = command.Wait() })
	a := &socketEvidenceActor{input: input, output: output, collected: &collected{}}
	a.reply(t, 0)
	table, err := process.Read(procfs)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	a.process, found = table.Lookup(int32(command.Process.Pid))
	if !found {
		t.Fatal("handshaken actor is absent from procfs")
	}
	if short {
		mappings, err := process.Mappings(procfs, a.process.PID)
		if err != nil {
			t.Fatal(err)
		}
		verified := false
		for _, mapping := range mappings {
			if mapping.Executable && filepath.Base(mapping.Path) == "libc.so.6" {
				if filepath.Dir(mapping.Path) != dir {
					t.Fatalf("actor mapped original libc %s", mapping.Path)
				}
				offsets, err := probe.SymbolOffsets(mapping.Path, []string{"accept4", "write"})
				if err != nil {
					t.Fatal(err)
				}
				if _, present := offsets["accept4"]; present {
					t.Fatal("doctored mapped libc still resolves accept4")
				}
				if _, present := offsets["write"]; !present {
					t.Fatal("doctored libc lost the live write control")
				}
				verified = true
			}
		}
		if !verified {
			t.Fatal("no executable doctored libc mapping was witnessed")
		}
	}
	place := func() {
		t.Helper()
		a.live, err = attach.NeweBPF(process.Approval{}).Attach(requesting(a.process), a.collected)
		if err != nil {
			t.Fatalf("attach %s the actor opens its sockets: %v", order, err)
		}
		t.Cleanup(func() { _ = a.live.Close() })
	}
	if order == beforeItsSocketsExist {
		place()
	}
	var listeners [2]*net.TCPListener
	var ports [2]int32
	for i := range listeners {
		ip := net.IPv4(127, 0, 0, 1)
		if network == "tcp6" {
			ip = net.IPv6loopback
		}
		listeners[i], err = net.ListenTCP(network, &net.TCPAddr{IP: ip})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listeners[i].Close() })
		ports[i] = int32(listeners[i].Addr().(*net.TCPAddr).Port)
		if network == "tcp6" {
			ports[i] = -ports[i]
		}
	}
	a.command(t, 1, ports[0], ports[1])
	if order == afterItsSocketsExist {
		// The sockets are connected and the TLS handles live; the observer arrives now.
		// Nothing will transition again, so a reported endpoint came from the object a
		// call is using.
		place()
	}
	for i := range listeners {
		_ = listeners[i].SetDeadline(time.Now().Add(5 * time.Second))
		a.peers[i], err = listeners[i].Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.peers[i].Close() })
	}
	return a
}

// Rename one unused dynamic export in a private libc copy: the actor maps that
// file and the resolver sees its short symbol set, rather than imitating the
// resolver's answer.
func shortSocketLibc(t *testing.T, dir string) string {
	t.Helper()
	path, err := exec.Command("cc", "-print-file-name=libc.so.6").Output()
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(strings.TrimSpace(string(path)))
	if err != nil {
		t.Fatal(err)
	}
	object, err := elf.NewFile(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	section := object.Section(".dynstr")
	if section == nil {
		t.Fatal("libc carries no dynamic string table")
	}
	data, err := section.Data()
	if err != nil {
		t.Fatal(err)
	}
	needle := []byte("\x00accept4\x00")
	if bytes.Count(data, needle) != 1 {
		t.Fatal("libc does not carry one isolated accept4 export name")
	}
	offset := int(section.Offset) + bytes.Index(data, needle) + 1
	copy(content[offset:offset+7], "zzcept4")
	if err := os.WriteFile(filepath.Join(dir, "libc.so.6"), content, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func (a *socketEvidenceActor) reply(t *testing.T, mode int32) [4]int32 {
	t.Helper()
	_ = a.output.SetReadDeadline(time.Now().Add(10 * time.Second))
	var reply [4]int32
	if err := binary.Read(a.output, binary.LittleEndian, &reply); err != nil {
		t.Fatalf("actor response for mode %d: %v", mode, err)
	}
	if reply[0] != mode {
		t.Fatalf("actor answered mode %d, wanted %d", reply[0], mode)
	}
	a.fd = reply[1]
	return reply
}

func (a *socketEvidenceActor) command(t *testing.T, mode, first, second int32) [4]int32 {
	t.Helper()
	if err := binary.Write(a.input, binary.LittleEndian, [3]int32{mode, first, second}); err != nil {
		t.Fatal(err)
	}
	return a.reply(t, mode)
}

func (a *socketEvidenceActor) call(t *testing.T, mode int32) (connection.Association, [4]int32) {
	t.Helper()
	before := len(a.collected.moved())
	reply := a.command(t, mode, 0, 0)
	deadline := time.Now().Add(5 * time.Second)
	for len(a.collected.moved()) <= before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	// The quiet interval also exposes duplicate event emission for one call.
	time.Sleep(30 * time.Millisecond)
	moved := a.collected.moved()
	if len(moved) != before+1 {
		t.Fatalf("one successful SSL_write emitted %d transfers, want 1", len(moved)-before)
	}
	if moved[before].Length != uint32(len("independent-socket-evidence")) {
		t.Fatalf("unexpected plaintext transfer: %+v", moved[before])
	}
	one := a.project(t, moved[before])
	return one, reply
}

func (a *socketEvidenceActor) witness(t *testing.T, peer, count int) {
	t.Helper()
	if count <= 0 {
		t.Fatalf("peer witness must consume a positive count, got %d", count)
	}
	_ = a.peers[peer].SetReadDeadline(time.Now().Add(5 * time.Second))
	bytes := make([]byte, count)
	if _, err := io.ReadFull(a.peers[peer], bytes); err != nil {
		t.Fatalf("peer %d did not receive %d ciphertext bytes: %v", peer, count, err)
	}
}

// Seal a capture containing the actual transfer, constructing none of its
// binding fields. Records publishes sealed connections only. Each call's
// outcome is projected separately, so a previous call's summary cannot
// substitute for this one.
func (a *socketEvidenceActor) project(t *testing.T, transfer probe.Transfer) connection.Association {
	t.Helper()
	fragments := &collected{}
	session := capture.New(fragments)
	session.Observing(a.live.Capability())
	session.Transfer(transfer)
	// Read the live producer before sealing, the state while the call is open. The
	// seal below is the projection the final association record needs.
	if live := session.Live(time.Now()); len(live) != 1 {
		t.Fatalf("one in-flight transfer projected to %d live connections", len(live))
	}
	session.Finish(time.Now(), connection.Counted(int64(transfer.Stamp)))
	records := session.Records()
	if len(records) != 1 || len(fragments.taken()) != 1 {
		t.Fatalf("one real transfer projected to %d connections and %d fragments", len(records), len(fragments.taken()))
	}
	one, ok := records[0].Association(fragment.Sent)
	if !ok {
		t.Fatal("captured SSL_write has no association outcome")
	}
	return one
}

func (a *socketEvidenceActor) established(t *testing.T) connection.Association {
	t.Helper()
	one, reply := a.call(t, 2)
	a.witness(t, 0, int(reply[3]))
	if one.State != connection.Established || one.Descriptor != connection.Held(a.fd) || !one.Binding.Known() {
		t.Fatalf("live socket control did not establish its independently witnessed fd %d: %+v", a.fd, one)
	}
	return one
}

func expectSocketPeer(t *testing.T, one connection.Association, peer net.Conn) {
	t.Helper()
	local := peer.RemoteAddr().(*net.TCPAddr)
	remote := peer.LocalAddr().(*net.TCPAddr)
	if !one.Endpoints.Complete() || one.Endpoints.Local.Port != uint16(local.Port) ||
		one.Endpoints.Remote.Port != uint16(remote.Port) {
		t.Errorf("acquired socket does not match independent peer %s -> %s: %+v", local, remote, one)
	}
}

func TestSocketEvidenceSeparatesFileOperationsFromSockets(t *testing.T) {
	a := socketEvidence(t)
	a.established(t)
	withFile, reply := a.call(t, 15)
	a.witness(t, 0, int(reply[3]))
	if withFile.State != connection.Established {
		t.Errorf("ordinary file beside one socket made the socket unresolved: %+v", withFile)
	}
	file, reply := a.call(t, 4)
	if reply[2] <= 0 {
		t.Fatal("ordinary file write did not succeed")
	}
	if file.State != connection.Unknown || file.Reason != connection.OperationWasNotASocket || file.Basis != connection.BasisUnset {
		t.Errorf("positive ordinary file write borrowed cached socket evidence: %+v", file)
	}
}

func TestSocketEvidenceSameDescriptorReplacementStaysAmbiguous(t *testing.T) {
	a := socketEvidence(t)
	a.established(t)
	one, reply := a.call(t, 6)
	a.witness(t, 0, 1)
	a.witness(t, 1, int(reply[3])-1)
	if one.State != connection.Ambiguous || one.Joinable() || one.Basis != connection.BasisUnset {
		t.Errorf("two peer-witnessed occupancies of fd %d in one call lost ambiguity in the account: %+v", a.fd, one)
	}
}

func TestSocketEvidenceCountsCallsInsteadOfKernelOperations(t *testing.T) {
	a := socketEvidence(t)
	control := a.established(t)
	one, reply := a.call(t, 5)
	a.witness(t, 0, int(reply[3]))
	if one.State != connection.Established || one.Binding != control.Binding || one.Basis != connection.ConfirmedInCall {
		t.Errorf("two confirmed writes in one call did not produce one confirmed association: %+v", one)
	}
	a.command(t, 16, 0, 0)
	two, reply := a.call(t, 2)
	a.witness(t, 1, int(reply[3]))
	if two.State != connection.Established || two.Binding == control.Binding {
		t.Errorf("a distinct later call on another socket failed to get its own association: %+v", two)
	}
}

func TestSocketEvidenceContinuityRequiresAValidCacheAndNoIO(t *testing.T) {
	a := socketEvidence(t)
	control := a.established(t)
	noIO, _ := a.call(t, 3)
	if noIO.State != connection.Established || noIO.Binding != control.Binding || noIO.Basis != connection.Continuity {
		t.Errorf("a no-I/O call on a valid cached socket is not identified as continuity: %+v", noIO)
	}
	a.command(t, 16, 0, 0)
	invalid, _ := a.call(t, 3)
	if invalid.State == connection.Established {
		t.Errorf("a replaced descriptor donated stale continuity: %+v", invalid)
	}
	fresh, reply := a.call(t, 2)
	a.witness(t, 1, int(reply[3]))
	if fresh.State != connection.Established || fresh.Binding == control.Binding {
		t.Errorf("legitimate call after invalidation did not recover: %+v", fresh)
	}
	later, _ := a.call(t, 3)
	if later.State != connection.Established || later.Binding != fresh.Binding || later.Basis != connection.Continuity {
		t.Errorf("fresh binding never became usable for later continuity: %+v", later)
	}
}

func TestSocketEvidenceUnsupportedRouteCannotBorrowACachedBinding(t *testing.T) {
	a := socketEvidence(t)
	a.established(t)
	one, reply := a.call(t, 13)
	if reply[2] <= 0 {
		t.Fatal("unix-domain operation did not move bytes")
	}
	if one.State != connection.Unknown || one.Reason != connection.RouteUnsupported || one.Basis != connection.BasisUnset {
		t.Errorf("unsupported unix-domain operation inherited success: %+v", one)
	}
	recovered, reply := a.call(t, 2)
	a.witness(t, 0, int(reply[3]))
	if recovered.State != connection.Established {
		t.Errorf("supported call after unsupported route did not recover: %+v", recovered)
	}
}

func socketInodeAt(t *testing.T, pid, fd int32) uint64 {
	t.Helper()
	path := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	link, err := os.Readlink(path)
	if err != nil {
		t.Fatalf("wiring: read independent socket identity at %s: %v", path, err)
	}
	number, socket := strings.CutPrefix(link, "socket:[")
	number, closed := strings.CutSuffix(number, "]")
	inode, err := strconv.ParseUint(number, 10, 64)
	if !socket || !closed || err != nil || inode == 0 {
		t.Fatalf("wiring: %s does not name a nonzero socket inode: %q", path, link)
	}
	return inode
}

func TestSocketEvidenceUnixMessagingReportsTheRouteItObserved(t *testing.T) {
	a := socketEvidence(t)
	cached := a.established(t)
	before := len(a.collected.moved())
	entered := a.command(t, 25, 0, 0)
	if entered[3] <= 0 {
		t.Fatal("wiring: unix send buffer was not filled before TLS entry")
	}
	inode := socketInodeAt(t, a.process.PID, entered[1])
	// The announcement is only a request to inspect. Procfs must independently
	// name a blocked sendmsg on that fd; a scalar write moving identical bytes
	// cannot satisfy this guard. The drain thread waits for our release.
	path := fmt.Sprintf("/proc/%d/syscall", a.process.PID)
	deadline := time.Now().Add(5 * time.Second)
	for {
		snapshot, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("wiring: inspect the unix messaging syscall: %v", err)
		}
		fields := strings.Fields(string(snapshot))
		if len(fields) >= 2 {
			number, numberErr := strconv.ParseInt(fields[0], 0, 64)
			descriptor, fdErr := strconv.ParseInt(fields[1], 0, 64)
			if numberErr == nil && fdErr == nil && number == unix.SYS_SENDMSG && descriptor == int64(entered[1]) {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("wiring: procfs never witnessed sendmsg on unix fd %d: %s", entered[1], snapshot)
		}
		time.Sleep(time.Millisecond)
	}
	if err := binary.Write(a.input, binary.LittleEndian, [3]int32{28, 0, 0}); err != nil {
		t.Fatal(err)
	}
	reply := a.reply(t, 25)
	deadline = time.Now().Add(5 * time.Second)
	for len(a.collected.moved()) <= before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(30 * time.Millisecond)
	moved := a.collected.moved()[before:]
	if len(moved) != 1 || moved[0].Length != uint32(len("independent-socket-evidence")) {
		t.Fatalf("wiring: completed unix SSL_write did not emit exactly its plaintext transfer: %+v", moved)
	}
	one := a.project(t, moved[0])
	// The actor checks the peer's exact ciphertext after SSL_write has returned;
	// that scalar read must not supply evidence to the sendmsg call itself.
	if reply[2] <= 0 || reply[3] != reply[2] || reply[1] == cached.Descriptor.Number {
		t.Fatalf("wiring: unix sendmsg and its peer did not witness a distinct positive transfer: %v", reply)
	}
	if reply[1] != entered[1] || socketInodeAt(t, a.process.PID, reply[1]) != inode {
		t.Fatal("wiring: witnessed unix descriptor changed before its completed transfer")
	}
	if one.State == connection.Established {
		if one.Basis != connection.ConfirmedInCall || one.Socket != connection.Named(inode) || one.Binding == cached.Binding {
			t.Errorf("unix messaging resolved through the wrong socket or cached continuity: %+v, want socket:[%d]", one, inode)
		}
	} else if one.State != connection.Unknown || one.Reason != connection.RouteUnsupported || one.Basis != connection.BasisUnset {
		t.Errorf("positive unix messaging must resolve or explicitly report an unfollowed route: %+v", one)
	}
	recovered, reply := a.call(t, 2)
	a.witness(t, 0, int(reply[3]))
	if recovered.State != connection.Established || recovered.Basis != connection.ConfirmedInCall || recovered.Socket != cached.Socket {
		t.Errorf("TCP call after unix messaging failed to recover its own socket: %+v", recovered)
	}
}

func TestSocketEvidenceConcurrentTransfersPublishTheirOwnSocket(t *testing.T) {
	a := socketEvidence(t)
	a.command(t, 26, 0, 0)
	// Reverse peer-release order while retaining both live sockets and handles.
	// Transfer order, descriptor order and connection identity are not aliases.
	for _, first := range []int{1, 0} {
		before := len(a.collected.moved())
		if err := binary.Write(a.input, binary.LittleEndian, [3]int32{27, 0, 0}); err != nil {
			t.Fatal(err)
		}
		var entered [2][4]int32
		var seen [2]bool
		for range entered {
			reply := a.reply(t, 27)
			if reply[3] < 0 || reply[3] > 1 || seen[reply[3]] {
				t.Fatalf("wiring: duplicate or invalid concurrent BIO entry: %v", reply)
			}
			entered[reply[3]], seen[reply[3]] = reply, true
		}
		if entered[0][1] == entered[1][1] || entered[0][2] == entered[1][2] {
			t.Fatalf("wiring: concurrency requires distinct sockets and threads: %v", entered)
		}
		var inodes [2]uint64
		for slot, entry := range entered {
			inodes[slot] = socketInodeAt(t, a.process.PID, entry[1])
			stackPath := fmt.Sprintf("/proc/%d/task/%d/stack", a.process.PID, entry[2])
			deadline := time.Now().Add(5 * time.Second)
			for {
				stack, err := os.ReadFile(stackPath)
				if err != nil {
					t.Fatalf("wiring: read blocked thread stack: %v", err)
				}
				if strings.Contains(string(stack), "tcp_recvmsg") {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("wiring: connection %d never reached an acquired TCP read: %s", slot, stack)
				}
				time.Sleep(time.Millisecond)
			}
		}
		if inodes[0] == inodes[1] {
			t.Fatalf("wiring: two connections name the same socket inode: %v", inodes)
		}
		// Neither peer has sent its release byte: both witnessed reads remain
		// blocked together. Now identify each transfer by plaintext, never by
		// the descriptor or inode supplied by the observer under test.
		for _, slot := range []int{first, 1 - first} {
			if _, err := a.peers[slot].Write([]byte{byte('A' + slot)}); err != nil {
				t.Fatal(err)
			}
			// A full TLS record at this peer witnesses this call's socket before
			// releasing the other thread. The actor reports exact wire counts below.
			_ = a.peers[slot].SetReadDeadline(time.Now().Add(5 * time.Second))
			header := make([]byte, 5)
			if _, err := io.ReadFull(a.peers[slot], header); err != nil {
				t.Fatalf("wiring: peer %d received no TLS record: %v", slot, err)
			}
			if header[0] != 23 || header[1] != 3 || header[2] != 3 {
				t.Fatalf("wiring: peer %d received no TLS 1.2 application record: %x", slot, header)
			}
			count := int(binary.BigEndian.Uint16(header[3:]))
			a.witness(t, slot, count)
			entered[slot][0] = int32(5 + count)
		}
		finished := a.reply(t, 27)
		if finished[2] != entered[0][0] || finished[3] != entered[1][0] {
			t.Fatalf("wiring: peer ciphertext lengths disagree with completed calls: %v, %v", finished, entered)
		}
		deadline := time.Now().Add(5 * time.Second)
		for len(a.collected.moved()) < before+2 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(30 * time.Millisecond)
		moved := a.collected.moved()[before:]
		if len(moved) != 2 {
			t.Fatalf("two concurrent successful SSL_write calls emitted %d transfers, want 2", len(moved))
		}
		seen = [2]bool{}
		for _, transfer := range moved {
			slot := -1
			switch string(transfer.Payload) {
			case "connection-a":
				slot = 0
			case "connection-b-distinct-message":
				slot = 1
			default:
				t.Fatalf("wiring: no concurrent connection owns captured plaintext %q", transfer.Payload)
			}
			if seen[slot] || transfer.Length != uint32(len(transfer.Payload)) {
				t.Fatalf("wiring: duplicate or incomplete plaintext for connection %d: %+v", slot, transfer)
			}
			seen[slot] = true
			one := a.project(t, transfer)
			if one.State != connection.Established || one.Basis != connection.ConfirmedInCall ||
				one.Descriptor != connection.Held(entered[slot][1]) || one.Socket != connection.Named(inodes[slot]) {
				t.Errorf("connection %d transfer published another connection's socket: %+v, want fd %d socket:[%d] (other socket:[%d])",
					slot, one, entered[slot][1], inodes[slot], inodes[1-slot])
			}
		}
	}
}

func TestSocketEvidenceUsesReplacementAcquiredAfterTLSEntry(t *testing.T) {
	a := socketEvidence(t)
	old := a.established(t)
	one, reply := a.call(t, 14)
	a.witness(t, 1, int(reply[3]))
	if one.State != connection.Established || one.Binding == old.Binding || one.Basis != connection.ConfirmedInCall {
		t.Errorf("replacement performed inside BIO before acquisition used old library-entry evidence: %+v", one)
	}
	expectSocketPeer(t, one, a.peers[1])
}

func TestSocketEvidenceDirectSyscallsResolveScalarVectorAndMessages(t *testing.T) {
	for mode, name := range map[int32]string{7: "scalar", 8: "vector", 9: "message", 19: "batch"} {
		t.Run(name, func(t *testing.T) {
			a := socketEvidence(t)
			a.established(t)
			one, reply := a.call(t, mode)
			a.witness(t, 0, int(reply[3]))
			if one.State != connection.Established || one.Basis != connection.ConfirmedInCall {
				t.Errorf("direct %s syscall did not confirm its socket: %+v", name, one)
			}
			expectSocketPeer(t, one, a.peers[0])
		})
	}
}

func TestSocketEvidenceDirectReceiveSyscallsPreserveTheAcquiredSocket(t *testing.T) {
	for mode, name := range map[int32]string{20: "scalar", 21: "vector", 22: "message", 23: "batch"} {
		t.Run(name, func(t *testing.T) {
			a := socketEvidence(t)
			a.established(t)
			if _, err := a.peers[0].Write([]byte{'R'}); err != nil {
				t.Fatal(err)
			}
			one, reply := a.call(t, mode)
			if reply[2] != 1 {
				t.Fatal("actor did not receive the independently sent peer byte")
			}
			if one.State != connection.Established || one.Basis != connection.ConfirmedInCall {
				t.Errorf("direct %s receive did not confirm its acquired socket: %+v", name, one)
			}
			expectSocketPeer(t, one, a.peers[0])
		})
	}
}

func TestSocketEvidenceNonTransfersCannotDonateCachedSuccess(t *testing.T) {
	for mode, name := range map[int32]string{10: "error", 11: "zero", 12: "EAGAIN"} {
		t.Run(name, func(t *testing.T) {
			a := socketEvidence(t)
			a.established(t)
			one, reply := a.call(t, mode)
			if reply[2] > 0 || reply[3] != 0 {
				t.Fatal("nontransfer fixture performed a positive operation")
			}
			if one.State == connection.Established || one.Basis != connection.BasisUnset {
				t.Errorf("%s was treated as a transfer or no-I/O continuity: %+v", name, one)
			}
			recovered, reply := a.call(t, 2)
			a.witness(t, 0, int(reply[3]))
			if recovered.State != connection.Established {
				t.Errorf("valid call after %s did not recover: %+v", name, recovered)
			}
		})
	}
}

func TestSocketEvidenceRetainsAcquiredSocketAcrossReplacementAndMigration(t *testing.T) {
	a := socketEvidence(t)
	old := a.established(t)
	before := len(a.collected.moved())
	entered := a.command(t, 17, 0, 0)
	// A syscall-entry observation alone is insufficient: it precedes fdget.
	// The kernel stack must place the thread inside TCP receive, with the
	// original socket acquired, before replacement is released.
	stackPath := fmt.Sprintf("/proc/%d/task/%d/stack", a.process.PID, entered[2])
	deadline := time.Now().Add(5 * time.Second)
	acquired := false
	for time.Now().Before(deadline) {
		stack, err := os.ReadFile(stackPath)
		if err != nil {
			t.Fatalf("independent acquired-operation witness: %v", err)
		}
		if strings.Contains(string(stack), "tcp_recvmsg") {
			acquired = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !acquired {
		t.Fatal("kernel stack never witnessed an acquired TCP receive")
	}
	replaced := a.command(t, 18, 0, 0)
	if replaced[1] != entered[1] || replaced[3] == entered[3] {
		t.Fatal("replacement did not preserve fd number and change CPU")
	}
	if _, err := a.peers[0].Write([]byte{'A'}); err != nil {
		t.Fatal(err)
	}
	finished := a.reply(t, 17)
	if finished[2] != 1 {
		t.Fatal("original peer did not unblock the acquired operation")
	}
	deadline = time.Now().Add(5 * time.Second)
	for len(a.collected.moved()) <= before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(a.collected.moved()) != before+1 {
		t.Fatal("migrated TLS call lost its thread/call ownership")
	}
	one := a.project(t, a.collected.moved()[before])
	if one.State != connection.Established || one.Binding != old.Binding || one.Basis != connection.ConfirmedInCall {
		t.Errorf("blocked operation lost the original acquired socket after replacement/migration: %+v", one)
	}
	expectSocketPeer(t, one, a.peers[0])
	noIO, _ := a.call(t, 3)
	if noIO.State == connection.Established && noIO.Binding == old.Binding {
		t.Errorf("old completed operation overwrote the replacement's cache: %+v", noIO)
	}
	fresh, reply := a.call(t, 2)
	a.witness(t, 1, int(reply[3]))
	if fresh.State != connection.Established || fresh.Binding == old.Binding {
		t.Errorf("replacement socket did not obtain fresh evidence: %+v", fresh)
	}
	expectSocketPeer(t, fresh, a.peers[1])
}

func TestSocketEvidenceDoesNotRequireEveryLegacyLibcSymbol(t *testing.T) {
	a := socketEvidenceWithLibc(t, true)
	a.established(t)
	one, reply := a.call(t, 7)
	a.witness(t, 0, int(reply[3]))
	if capability := a.live.Capability(); !capability.SocketEvidence {
		t.Errorf("missing legacy accept4 withdrew kernel socket coverage: %+v", capability)
	}
	if one.State != connection.Established || one.Basis != connection.ConfirmedInCall {
		t.Errorf("direct syscall on short mapped libc did not resolve: %+v", one)
	}
	expectSocketPeer(t, one, a.peers[0])
}

func TestSocketEvidenceOutOfWindowSocketIOCannotDonateToTheNextTLSCall(t *testing.T) {
	a := socketEvidence(t)
	control := a.established(t)
	// Mode 24 performs the raw replacement-socket write before entering the
	// successful SSL_write; its positive TLS return is the control, not the
	// out-of-window operation's result.
	_, _ = a.call(t, 24)
	// The raw byte is independently witnessed on the replacement peer. The
	// following TLS transfer must remain on the original occupancy; a resolver
	// that joins by nearest thread/CPU event will instead select the replacement.
	a.witness(t, 1, 1)
	one, reply := a.call(t, 2)
	a.witness(t, 0, int(reply[3]))
	if one.State != connection.Established || one.Binding != control.Binding {
		t.Errorf("out-of-window socket I/O donated evidence to the next TLS call: %+v", one)
	}
	expectSocketPeer(t, one, a.peers[0])
}

func (o socketEvidenceAttachOrder) String() string {
	if o == beforeItsSocketsExist {
		return "before"
	}
	return "after"
}

// The endpoints come from the socket a call is using, whichever side of the
// attach the connection was opened on. The halves exclude different producers:
// one learning endpoints only from state transitions fails "before" (an open
// connection has no transition left), one reading only history at attach fails
// "after". The tuple is compared with the peer's own view, so it is a real
// pair of endpoints.
func TestSocketEvidenceEndpointsComeFromTheLiveSocketWhicheverSideOfAttachItOpened(t *testing.T) {
	for _, order := range []socketEvidenceAttachOrder{afterItsSocketsExist, beforeItsSocketsExist} {
		t.Run(order.String(), func(t *testing.T) {
			a := socketEvidenceAttaching(t, false, "tcp4", order)
			one := a.established(t)
			if !one.Endpoints.Complete() {
				t.Fatalf("a connection whose socket was opened %s the attach has no endpoints: %+v",
					order, one)
			}
			expectSocketPeer(t, one, a.peers[0])
		})
	}
}
