//go:build linux && attach

package attach_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/evandukss/edge-observer/activation"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/processing"
)

const p3t9ActivationMarker = "P3T9_ACTIVATION_PRIVATE_69171"

// This report contains structural evidence, never the excluded header value.
type p3t9ActivationReport struct {
	PID            int
	Stage          string
	Check          activation.Check
	Reading        activation.Posture
	Gate           probe.GateSnapshot
	ObservedMarker uint64
	Written        uint64
}

func p3t9ActivationReportToParent(t *testing.T, r p3t9ActivationReport) {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("P3T9_REPORT " + string(raw))
}

func p3t9ActivationRead(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("independent kernel reading %s: %v", path, err)
	}
	return strings.TrimSpace(string(raw))
}

func p3t9ActivationNumber(t *testing.T, path string) uint64 {
	t.Helper()
	x := p3t9ActivationRead(t, path)
	if x == "max" {
		return ^uint64(0)
	}
	n, err := strconv.ParseUint(x, 10, 64)
	if err != nil {
		t.Fatalf("independent numeric reading %s: %v", path, err)
	}
	return n
}

// Read these values independently of activation.Verify. The inherited envelope
// directory is a harness location; /proc establishes the holder's membership.
func p3t9ActivationReading(t *testing.T, peer process.Process) activation.Posture {
	t.Helper()
	table, err := process.Read(procfs)
	if err != nil {
		t.Fatal(err)
	}
	self, ok := table.Lookup(int32(os.Getpid()))
	if !ok || self.StartTime == 0 {
		t.Fatal("payload holder identity not read")
	}
	dir := os.Getenv("P3T9_ACTIVATION_CGROUP")
	want := "/" + filepath.Base(dir)
	group := unifiedCgroup(t, self.PID)
	if group != want {
		t.Fatalf("pre-exec membership not reached: actual=%s wanted=%s", group, want)
	}
	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	member := false
	for _, pid := range strings.Fields(p3t9ActivationRead(t, filepath.Join(dir, "cgroup.procs"))) {
		if pid == strconv.Itoa(os.Getpid()) {
			member = true
		}
	}
	if !member {
		t.Fatal("holder absent from its actual cgroup.procs")
	}
	return activation.Posture{
		PID: os.Getpid(), StartTime: self.StartTime, Cgroup: group,
		Domain: p3t9ActivationRead(t, filepath.Join(dir, "cgroup.type")), Member: member,
		MemoryMax:    p3t9ActivationNumber(t, filepath.Join(dir, "memory.max")),
		SwapMax:      p3t9ActivationNumber(t, filepath.Join(dir, "memory.swap.max")),
		SwapCurrent:  p3t9ActivationNumber(t, filepath.Join(dir, "memory.swap.current")),
		Dumpable:     dumpable,
		Participants: []activation.ParticipantState{{PID: peer.PID, StartTime: peer.StartTime, Cgroup: unifiedCgroup(t, peer.PID)}},
	}
}

func p3t9ActivationCompiled(t *testing.T, peer process.Process) policy.Policy {
	t.Helper()
	raw, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	watch := document["watch"].([]any)[:1]
	one := watch[0].(map[string]any)
	one["exe"], one["args"] = peer.Executable, append([]string{}, peer.Arguments[1:]...)
	document["watch"] = watch
	document["remove"] = map[string]any{"headers": []string{"authorization"}}
	raw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.CompileProcessing(raw, "")
	if err != nil || p.Processing == nil {
		t.Fatalf("valid protected policy unavailable: %v", err)
	}
	table, err := process.Read(procfs)
	if err != nil {
		t.Fatal(err)
	}
	selected := p.Approval.Select(table)
	if len(selected) != 1 || selected[0].PID != peer.PID || selected[0].StartTime != peer.StartTime {
		t.Fatalf("compiled approval did not select the exact independent participant: %+v", selected)
	}
	return p
}

// A transient witness before the real capture sink, not an executor, intake,
// authorization decision or output implementation. It retains only a count.
type p3t9ActivationWitness struct {
	recording *capture.Session
	marker    atomic.Uint64
}

func (w *p3t9ActivationWitness) Transfer(x probe.Transfer) {
	if bytes.Contains(x.Payload, []byte(p3t9ActivationMarker)) {
		w.marker.Add(1)
	}
	w.recording.Transfer(x)
}
func (w *p3t9ActivationWitness) Closed(x probe.Connection) { w.recording.Closed(x) }

func p3t9ActivationRefusal(t *testing.T, err error, want activation.Check) {
	t.Helper()
	var r *activation.Refusal
	if !errors.As(err, &r) || r.Check != want || r.PID != os.Getpid() {
		t.Fatalf("actual activation fault requires check=%s pid=%d; got %v", want, os.Getpid(), err)
	}
}

func p3t9ActivationChild(t *testing.T) {
	mode := os.Getenv("P3T9_ACTIVATION_CHILD")
	peerPID, err := strconv.ParseInt(os.Getenv("P3T9_ACTIVATION_PEER"), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	peer := loaded(t, int32(peerPID))
	// Exec resets dumpability; establish it in THIS holder, then read it back.
	dumpable := uintptr(0)
	if mode == "dumpable" {
		dumpable = 1
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, dumpable, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	reading := p3t9ActivationReading(t, peer)
	report := p3t9ActivationReport{PID: os.Getpid(), Stage: "actual_readings", Reading: reading}
	p3t9ActivationReportToParent(t, report)
	want := activation.Check("")
	switch mode {
	case "missing_gate", "zero_gate":
		want = activation.DeliveryGate
	case "no_memory_cap":
		want = activation.ExecutionMemory
		if reading.MemoryMax != ^uint64(0) {
			t.Fatal("unlimited-memory fault not reached")
		}
	case "swap_permitted":
		want = activation.AnonymousSwap
		if reading.SwapMax == 0 {
			t.Fatal("swap-permitted fault not reached")
		}
	case "dumpable":
		want = activation.CoreDumps
		if reading.Dumpable != 1 {
			t.Fatal("dumpability fault not reached")
		}
	case "participant_inside":
		want = activation.ParticipantOutsideEnvelope
		if reading.Participants[0].Cgroup != reading.Cgroup {
			t.Fatal("participant-inside fault not reached")
		}
	case "compliant":
		if reading.MemoryMax == 0 || reading.MemoryMax == ^uint64(0) || reading.SwapMax != 0 || reading.SwapCurrent != 0 || reading.Dumpable != 0 || reading.Participants[0].Cgroup == reading.Cgroup || strings.HasPrefix(reading.Participants[0].Cgroup, reading.Cgroup+"/") {
			t.Fatal("independently read compliant posture not reached")
		}
	default:
		t.Fatalf("unrecognized harness mode %q", mode)
	}
	// The fixture, like begin, opens the approved writer before checking
	// activation.
	writer, err := processing.Open(os.Getenv("P3T9_ACTIVATION_OUTPUT"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := writer.Close(); err != nil {
			t.Errorf("close approved writer during fixture cleanup: %v", err)
		}
	}()
	g, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 128})
	if err != nil {
		t.Fatal(err)
	}
	if mode == "missing_gate" {
		g = nil
	}
	if mode == "zero_gate" {
		g = &probe.DeliveryGate{}
	}
	before := g.Snapshot()
	p, err := activation.Verify(g, []process.Process{peer})
	if g.Snapshot() != before {
		t.Fatal("Verify consumed or changed the gate before attach")
	}
	if want != "" {
		p3t9ActivationRefusal(t, err, want)
		// On posture faults the assembling entry point must refuse too, returning
		// no capture. Gate faults are passed to Verify, not invented in Prepare.
		if want != activation.DeliveryGate {
			c, err := activation.Prepare(p3t9ActivationCompiled(t, peer), []process.Process{peer}, 128)
			if c != nil {
				t.Fatal("refused Prepare exposed a capture")
			}
			p3t9ActivationRefusal(t, err, want)
		}
		report.Stage, report.Check, report.Gate = "refused_before_attach", want, g.Snapshot()
		p3t9ActivationReportToParent(t, report)
		return
	}
	if err != nil {
		t.Fatalf("compliant Verify refused; attach/admission/output NOT reached: %v", err)
	}
	if p.PID != reading.PID || p.StartTime != reading.StartTime || p.Cgroup != reading.Cgroup || p.Domain != reading.Domain || p.MemoryMax != reading.MemoryMax || p.SwapMax != reading.SwapMax || p.SwapCurrent != reading.SwapCurrent || p.Dumpable != reading.Dumpable || !p.Member || len(p.Participants) != 1 || p.Participants[0] != reading.Participants[0] {
		t.Fatalf("Verify did not report the actual holder and exact participant readings: %+v", p)
	}
	compiled := p3t9ActivationCompiled(t, peer)
	c, err := activation.Prepare(compiled, []process.Process{peer}, 128)
	if err != nil || c == nil {
		t.Fatalf("compliant Prepare refused; attach/admission/output NOT reached: %v", err)
	}
	if c.Gate == nil || c.Recording == nil || c.Intake == nil {
		t.Fatal("Prepare omitted a capture component")
	}
	defer func() { _ = c.Intake.Close() }()
	if s := c.Gate.Snapshot(); s.MaxEvents != 128 || s.Charged != 0 || s.Reason != "" {
		t.Fatalf("Prepare gate is not fresh: %+v", s)
	}
	if c.Intake.Stats().LimitBytes != 128*int64(ebpf.MaxEventPayloadBytes) {
		t.Fatal("Prepare did not derive the published intake allowance")
	}
	if c.Posture.PID != os.Getpid() || c.Posture.StartTime != reading.StartTime || c.Posture.Cgroup != reading.Cgroup {
		t.Fatal("Prepare reported another holder")
	}
	if _, err := activation.Verify(c.Gate, []process.Process{peer}); err != nil {
		t.Fatalf("prepared gate failed initial verification: %v", err)
	}
	handed := &t20iHandedByRoute{next: writer}
	worker, err := processing.New(processing.Options{Plan: compiled.Processing, PolicyRevision: compiled.Revision, Session: "p3t9-activation", Intake: c.Intake, Gate: c.Gate, Output: handed})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = worker.Close() }()
	witness := &p3t9ActivationWitness{recording: c.Recording}
	request := requesting(peer)
	request.DeliveryGate = c.Gate
	live, err := attach.NeweBPF(compiled.Approval).Attach(request, witness)
	if err != nil {
		t.Fatalf("real attachment unavailable: %v", err)
	}
	defer func() {
		if err := live.Close(); err != nil {
			t.Errorf("close live attachment during fixture cleanup: %v", err)
		}
	}()
	if !live.Capability().Payload {
		t.Fatal("attachment cannot copy payload")
	}
	fmt.Println("P3T9_READY")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil || line != "exchange_done\n" {
		t.Fatal("parent did not witness a completed peer exchange")
	}
	// Wait for the independent marker witness before stopping production. Peer
	// completion by itself does not establish that userspace received the event.
	deadline := time.Now().Add(5 * time.Second)
	for witness.marker.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if witness.marker.Load() == 0 {
		t.Fatal("protected source marker never reached the real capture sink")
	}
	producer, ok := live.(connection.Producer)
	if !ok {
		t.Fatal("attachment lacks real withdrawal/drain")
	}
	withdrawn, err := producer.StopProducing()
	if err != nil || !withdrawn.Complete {
		t.Fatalf("kernel withdrawal incomplete: %+v %v", withdrawn, err)
	}
	drained, err := producer.Drain(5 * time.Second)
	if err != nil || !drained.Complete {
		t.Fatalf("real drain incomplete: %+v %v", drained, err)
	}
	counters, err := producer.Account()
	if err != nil {
		t.Fatal(err)
	}
	if c.Gate.Snapshot().Charged < 2 || c.Recording.Stats().Records < 2 {
		t.Fatal("actual admission/capture population was not reached")
	}
	refusing, ok := live.(probe.Refusing)
	if !ok {
		t.Fatal("attachment cannot report ungated delivery")
	}
	refusals, err := refusing.Refusals()
	ungated, measured := refusals[probe.DeliveryWithoutGate]
	if err != nil || !measured || ungated != 0 {
		t.Fatalf("ungated delivery was not measured zero: %v %v", refusals, err)
	}
	before = c.Gate.Snapshot()
	if _, err := activation.VerifyActive(c.Gate, []process.Process{peer}); err != nil {
		t.Fatalf("used healthy gate refused at VerifyActive: %v", err)
	}
	if c.Gate.Snapshot() != before {
		t.Fatal("VerifyActive consumed a slot or changed the gate")
	}
	_, err = activation.Verify(c.Gate, []process.Process{peer})
	p3t9ActivationRefusal(t, err, activation.DeliveryGate)
	if c.Gate.Snapshot() != before {
		t.Fatal("initial re-verification changed the active gate")
	}
	c.Recording.Finish(time.Now(), counters.Ordered)
	out, err := worker.Finish(context.Background(), processing.Finalization{Withdrawn: withdrawn.Complete, Drained: drained.Complete})
	if err != nil || handed.written(config.ExchangesPipeline) != 1 || handed.handed(config.ExchangesPipeline) != 1 || out.GateReason != "" {
		t.Fatalf("real approved-result control failed: exchanges records written %d, authorized %d, %+v %v",
			handed.written(config.ExchangesPipeline), handed.handed(config.ExchangesPipeline), out, err)
	}
	delivering, delivered := context.WithTimeout(context.Background(), 5*time.Second)
	defer delivered()
	if err := writer.Drain(delivering); err != nil {
		t.Fatalf("the approved writer did not finish the lines handed to it: %v", err)
	}
	persisted := t20iPersistedByRoute(t, os.Getenv("P3T9_ACTIVATION_OUTPUT"))
	if persisted[config.ExchangesPipeline] != 1 {
		t.Fatalf("worker result did not reach the concrete writer: exchanges records it holds %d", persisted[config.ExchangesPipeline])
	}
	report.Stage, report.Gate, report.ObservedMarker, report.Written = "useful_output", c.Gate.Snapshot(), witness.marker.Load(), uint64(persisted[config.ExchangesPipeline])
	p3t9ActivationReportToParent(t, report)
}

func p3t9ActivationArtifact(t *testing.T, dir string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, processing.ArtifactName))
	if err != nil {
		t.Fatal(err)
	}
	var exchanges [][]byte
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		if t20iPipelineOf(t, line) == config.ExchangesPipeline {
			exchanges = append(exchanges, line)
		}
	}
	if len(exchanges) != 1 {
		t.Fatalf("want one approved exchanges record, got %d", len(exchanges))
	}
	var artifact processing.Artifact
	if err := json.Unmarshal(exchanges[0], &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.Version != processing.ArtifactVersion || artifact.PolicyRevision == "" || artifact.Reconstruction == nil || len(artifact.Reconstruction.Exchanges) != 1 {
		t.Fatal("approved provenance/exchange missing")
	}
	x := artifact.Reconstruction.Exchanges[0]
	if !x.Complete || x.Request.Message == nil || x.Response.Message == nil || x.Request.Message.Target != "/?asked=p3t9-activation" || x.Response.Message.Status == nil || *x.Response.Message.Status != 200 {
		t.Fatal("approved result lost the useful exchange")
	}
	public := false
	for _, h := range x.Request.Message.Headers {
		if strings.EqualFold(h.Name, "authorization") {
			t.Fatal("excluded header persisted")
		}
		if strings.EqualFold(h.Name, "x-public") && h.Value == "benign" {
			public = true
		}
	}
	if !public {
		t.Fatal("permitted header was lost")
	}
	body, err := base64.StdEncoding.DecodeString(x.Response.Message.Body.Kept)
	if err != nil || len(body) == 0 {
		t.Fatal("approved response body is not useful decoded data")
	}
	if bytes.Contains(raw, []byte(p3t9ActivationMarker)) || bytes.Contains(body, []byte(p3t9ActivationMarker)) {
		t.Fatal("excluded marker persisted")
	}
}

// This owns live posture/admission/output evidence. It does not by itself
// establish whole-run absence of other durable writes or public cmd wiring.
func TestP3T9ActivationLive(t *testing.T) {
	if os.Getenv("P3T9_ACTIVATION_CHILD") != "" {
		p3t9ActivationChild(t)
		return
	}
	for _, fault := range []string{"missing_gate", "zero_gate", "no_memory_cap", "swap_permitted", "dumpable", "participant_inside"} {
		t.Run(fault, func(t *testing.T) {
			for _, mode := range []string{"compliant", fault} {
				t.Run(mode, func(t *testing.T) { p3t9ActivationRun(t, mode) })
			}
		})
	}
}

func p3t9ActivationRun(t *testing.T, mode string) {
	t.Helper()
	// Only a fresh owned cgroup is changed; no controller or ancestor limit is
	// changed. Missing delegation is an apparatus failure, never a skipped pass.
	name := fmt.Sprintf("p3t9-activation-%d-%d", os.Getpid(), time.Now().UnixNano())
	dir := filepath.Join(ebpf.DefaultCgroupMount, name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("cgroup apparatus unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(dir); err != nil {
			t.Errorf("remove owned envelope: %v", err)
		}
	})
	memory, swap := "1073741824", "0"
	if mode == "no_memory_cap" {
		memory = "max"
	}
	if mode == "swap_permitted" {
		swap = "4096"
	}
	for key, value := range map[string]string{"memory.max": memory, "memory.swap.max": swap} {
		if err := os.WriteFile(filepath.Join(dir, key), []byte(value), 0o644); err != nil {
			t.Fatalf("configure owned envelope %s: %v", key, err)
		}
	}
	// The peer is a real unmodified OpenSSL client. Traffic is generated by the
	// parent, outside the monitored payload-holder process and its descendants.
	port := serving(t)
	peer := speaking(t, port)
	if mode == "participant_inside" {
		if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(int(peer.process.PID))), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(t.TempDir(), "approved")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	group, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := group.Close(); err != nil {
			t.Errorf("close cgroup directory descriptor during fixture cleanup: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestP3T9ActivationLive$", "-test.count=1", "-test.timeout=35s")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(group.Fd())}
	cmd.Env = append(os.Environ(), "P3T9_ACTIVATION_CHILD="+mode, "P3T9_ACTIVATION_CGROUP="+dir, "P3T9_ACTIVATION_PEER="+strconv.Itoa(int(peer.process.PID)), "P3T9_ACTIVATION_OUTPUT="+output)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("pre-exec cgroup launch failed; activation NOT reached: %v", err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	lines := bufio.NewScanner(out)
	var reports []p3t9ActivationReport
	var transcript strings.Builder
	for lines.Scan() {
		line := lines.Text()
		transcript.WriteString(line + "\n")
		if payload, ok := strings.CutPrefix(line, "P3T9_REPORT "); ok {
			var report p3t9ActivationReport
			if err := json.Unmarshal([]byte(payload), &report); err != nil {
				t.Fatal(err)
			}
			if report.PID != cmd.Process.Pid {
				t.Fatal("evidence names parent/tracer instead of payload holder")
			}
			reports = append(reports, report)
		}
		if line == "P3T9_READY" {
			if mode != "compliant" {
				t.Fatal("noncompliant activation reached attachment")
			}
			request := "GET /?asked=p3t9-activation HTTP/1.1\r\nHost: localhost\r\nX-public: benign\r\nAuthorization: " + p3t9ActivationMarker + "\r\n\r\n"
			if _, err := io.WriteString(peer.send, request); err != nil {
				t.Fatal(err)
			}
			answered := make(chan error, 1)
			go func() {
				response, err := http.ReadResponse(peer.receive, &http.Request{Method: "GET"})
				if err == nil {
					var body []byte
					body, err = io.ReadAll(response.Body)
					_ = response.Body.Close()
					if err == nil && (response.StatusCode != 200 || len(body) == 0) {
						err = fmt.Errorf("unusable peer response: status=%d body bytes=%d", response.StatusCode, len(body))
					}
				}
				answered <- err
			}()
			select {
			case err := <-answered:
				if err != nil {
					t.Fatalf("peer did not complete the useful control exchange: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("peer exchange timed out; useful control NOT reached")
			}
			if _, err := io.WriteString(in, "exchange_done\n"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := lines.Err(); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	waited = true
	if err != nil {
		t.Fatalf("holder failed (%s): %v\n%s%s", mode, err, transcript.String(), stderr.String())
	}
	if len(reports) != 2 || reports[0].Stage != "actual_readings" {
		t.Fatalf("missing reached-state evidence: %s", transcript.String())
	}
	last := reports[1]
	if mode == "compliant" {
		if last.Stage != "useful_output" || last.ObservedMarker == 0 || last.Written != 1 || last.Gate.Charged < 2 {
			t.Fatalf("missing actual output/admission control: %+v", last)
		}
		p3t9ActivationArtifact(t, output)
	} else {
		if last.Stage != "refused_before_attach" || last.Check == "" || last.Gate.Charged != 0 || last.Written != 0 {
			t.Fatalf("refusal did not precede admission/output: %+v", last)
		}
		// The real writer existed before Prepare. Refusal must leave the output
		// directory holding nothing but, at most, the empty approved file the
		// writer may open at its stable path: no other output and no payload.
		entries, err := os.ReadDir(output)
		if err != nil || len(entries) > 1 || (len(entries) == 1 && entries[0].Name() != processing.ArtifactName) {
			t.Fatalf("refused activation changed the pre-opened output population: entries=%v error=%v", entries, err)
		}
		if len(entries) == 1 {
			info, err := entries[0].Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
				t.Fatalf("refused activation wrote to the approved file: info=%v error=%v", info, err)
			}
		}
	}
	t.Logf("actual_holder_result: mode=%s evidence=%s", mode, transcript.String())
}

// t20iHandedByRoute counts, by route.pipeline, the records the worker hands to
// the concrete writer and the ones the writer accepts. The worker authorizes
// each record immediately before handing it over, so handed is also the
// authorized count per route.
type t20iHandedByRoute struct {
	next     processing.Output
	mutex    sync.Mutex
	counts   map[string]int
	accepted map[string]int
}

func (h *t20iHandedByRoute) WriteApproved(ctx context.Context, a processing.Approved) error {
	var route struct {
		Route struct {
			Pipeline string `json:"pipeline"`
		} `json:"route"`
	}
	_ = json.Unmarshal(a.Bytes(), &route)
	h.mutex.Lock()
	if h.counts == nil {
		h.counts, h.accepted = map[string]int{}, map[string]int{}
	}
	h.counts[route.Route.Pipeline]++
	h.mutex.Unlock()
	err := h.next.WriteApproved(ctx, a)
	if err == nil {
		h.mutex.Lock()
		h.accepted[route.Route.Pipeline]++
		h.mutex.Unlock()
	}
	return err
}

func (h *t20iHandedByRoute) handed(pipeline string) int {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return h.counts[pipeline]
}

func (h *t20iHandedByRoute) written(pipeline string) int {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return h.accepted[pipeline]
}

// t20iPipelineOf is the route.pipeline of one approved line.
func t20iPipelineOf(t *testing.T, line []byte) string {
	t.Helper()
	var route struct {
		Route struct {
			Pipeline string `json:"pipeline"`
		} `json:"route"`
	}
	if err := json.Unmarshal(line, &route); err != nil {
		t.Fatalf("an approved line does not decode: %v", err)
	}
	return route.Route.Pipeline
}

// t20iPersistedByRoute is how many records of each route the approved output
// in directory holds.
func t20iPersistedByRoute(t *testing.T, directory string) map[string]int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(directory, processing.ArtifactName))
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		if len(line) != 0 {
			counts[t20iPipelineOf(t, line)]++
		}
	}
	return counts
}
