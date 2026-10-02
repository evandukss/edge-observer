//go:build attach

package attach_test

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/ebpf"
	retention "github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
)

func TestIndependentAttachmentChurnReclaimsProcessIdentity(t *testing.T) {
	port := serving(t)
	start := func() (conversation, func()) {
		cmd := exec.Command("openssl", "s_client", "-quiet", "-no_ign_eof", "-connect", fmt.Sprintf("127.0.0.1:%d", port))
		in, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		stop := func() { _ = in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() }
		t.Cleanup(stop)
		return conversation{process: loaded(t, int32(cmd.Process.Pid)), send: in, receive: bufio.NewReader(out)}, stop
	}
	seed, _ := start()
	witness := &collected{}
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	request := requesting(seed.process)
	request.DeliveryGate = gate
	ends := make(chan probe.Ended, 64)
	request.Ended = func(one probe.Ended) { ends <- one }
	live, err := attach.NeweBPF(process.Approval{}).Attach(request, witness)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = live.Close() }()
	reader, ok := live.(retention.Reader)
	if !ok {
		t.Fatal("wiring, not the property: attachment has no occupancy reader")
	}
	admitter, ok := live.(probe.Admitting)
	if !ok {
		t.Fatal("wiring, not the property: attachment cannot admit churn")
	}
	refusing, ok := live.(probe.Refusing)
	if !ok {
		t.Fatal("wiring, not the property: attachment cannot count refusals")
	}
	read := func() map[string]int {
		rows, err := reader.Retained()
		if err != nil {
			t.Fatal(err)
		}
		result := map[string]int{}
		for _, row := range rows {
			result[row.Store] = row.Held
		}
		return result
	}
	move := func(client conversation) {
		if line := client.ask(t, "retained"); !strings.Contains(line, "200") {
			t.Fatalf("wiring, not the property: real peer response %q", line)
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			for _, transfer := range witness.moved() {
				if transfer.Process.PID == client.process.PID {
					return
				}
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("wiring, not the property: real process never reached attachment identity lookup")
	}
	move(seed)
	baseline := read()
	if baseline["attach.identities"] != 1 || baseline["attach.covers"] != 1 {
		t.Fatalf("wiring, not the property: seed stores %v", baseline)
	}
	before, err := refusing.Refusals()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		client, stop := start()
		added, err := admitter.Admit(requesting(client.process))
		if err != nil || len(added.Selections) != 1 || len(added.Skipped) != 0 {
			t.Fatalf("wiring, not the property: admission %v %v", added, err)
		}
		move(client)
		if i%2 == 0 {
			admitter.Retract(added.Selections)
		}
		stop()
	}
	producer, ok := live.(connection.Producer)
	if !ok {
		t.Fatal("wiring, not the property: attachment cannot settle delivery")
	}
	withdrawn, err := producer.StopProducing()
	if err != nil || !withdrawn.Complete {
		t.Fatalf("wiring, not the property: production withdrawal %+v %v", withdrawn, err)
	}
	drained, err := producer.Drain(3 * time.Second)
	if err != nil || !drained.Complete {
		t.Fatalf("wiring, not the property: producer drain %+v %v", drained, err)
	}
	if len(ends) != 20 {
		t.Errorf("actual execution ends forwarded %d times, want 20 unretracted admissions", len(ends))
	}
	seenEnds := map[admission.Key]bool{}
	for len(ends) > 0 {
		one := <-ends
		if one.Selection.ObserverPID == seed.process.PID || seenEnds[one.Selection.Instance.Key()] || one.Evidence == "" {
			t.Errorf("end forwarded for wrong or repeated execution: %+v", one)
		}
		seenEnds[one.Selection.Instance.Key()] = true
	}
	after := read()
	for name, count := range after {
		if !strings.HasPrefix(name, "attach.") && !strings.HasPrefix(name, "ebpf.") {
			continue
		}
		if _, exists := baseline[name]; !exists {
			t.Fatalf("wiring, not the property: store %s absent from baseline", name)
		}
		if count > baseline[name] {
			t.Errorf("%s retains %d after 40 reaped/retracted processes, live baseline %d", name, count, baseline[name])
		}
	}
	counts, err := refusing.Refusals()
	if err != nil {
		t.Fatal(err)
	}
	for reason, count := range counts {
		// Each TLS connection was opened before its process was admitted, so
		// its unobserved socket creation cannot establish socket occupancy.
		if reason == string(ebpf.SocketLifetimeUnknown) {
			t.Logf("pre-admission socket association refusals %d -> %d", before[reason], count)
			continue
		}
		if reason == string(ebpf.DescriptorSeenInsideACall) || reason == string(ebpf.SocketWorkOutsideACall) || reason == string(ebpf.SocketDescriptorInvalid) {
			continue
		}
		if count != before[reason] {
			t.Errorf("process churn refusal %s moved %d -> %d", reason, before[reason], count)
		}
	}
	t.Logf("PRECONDITIONS real_process_churn=40 captured_processes=41 live_admitted=1 stores=%v", after)
}

func TestIndependentPartialAttachmentRetainsOnlyConfiguredRefusals(t *testing.T) {
	port := serving(t)
	client, excluded := speaking(t, port), speaking(t, port)
	unavailable := unobservable(t)
	exhausted := make(chan struct{})
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1000, IntakeExhausted: exhausted})
	if err != nil { t.Fatal(err) }
	request := requesting(client.process, excluded.process, unavailable)
	request.DeliveryGate = gate
	request.Deny = []admission.Denial{{Instance: excluded.process.Instance(), ObserverPID: excluded.process.PID, Provenance: admission.Provenance{Number: 1, Target: "excluded"}}}
	witness := &collected{}
	live, err := attach.NeweBPF(process.Approval{}).Attach(request, witness)
	if err != nil { t.Fatal(err) }
	defer func() { _ = live.Close() }()
	reader := live.(retention.Reader)
	read := func() map[string]int {
		rows, err := reader.Retained(); if err != nil { t.Fatal(err) }
		m := map[string]int{}; for _, row := range rows { m[row.Store] = row.Held }; return m
	}
	baseline := read()
	for name, want := range map[string]int{"attach.refusals": 2, "ebpf.denied": 1, "ebpf.excluded": 1, "ebpf.declined": 1} {
		if n, ok := baseline[name]; !ok || n != want { t.Fatalf("wiring, not the property: partial/excluded store %s = %d, want %d", name, n, want) }
	}
	if line := client.ask(t, "retained-control"); !strings.Contains(line, "200") { t.Fatal("control request failed") }
	deadline := time.Now().Add(3*time.Second)
	for len(witness.moved()) == 0 && time.Now().Before(deadline) { time.Sleep(time.Millisecond) }
	if len(witness.moved()) == 0 { t.Fatal("wiring, not the property: placed member never transferred") }
	// Inject the public intake-exhaustion boundary, then let real probe
	// deliveries repeatedly write the same refusal reason.
	close(exhausted)
	refusing := live.(probe.Refusing)
	for i := 0; i < 80; i++ {
		if line := client.ask(t, "retained-refused"); !strings.Contains(line, "200") { t.Fatal("peer request failed") }
		deadline := time.Now().Add(3*time.Second)
		var count int64
		for time.Now().Before(deadline) {
			counts, err := refusing.Refusals(); if err != nil { t.Fatal(err) }
			count = counts[probe.GateRefusal(probe.GateIntakeExhausted)]
			if count >= int64(i+1) { break }; time.Sleep(time.Millisecond)
		}
		if count < int64(i+1) { t.Fatal("wiring, not the property: repeated refusal write absent") }
		after := read()
		for _, name := range []string{"attach.refusals", "ebpf.denied", "ebpf.excluded", "ebpf.declined"} {
			if after[name] != baseline[name] { t.Errorf("%s grows with repeated events: %d -> %d", name, baseline[name], after[name]) }
		}
		if after["attach.gate_refused"] != 1 { t.Errorf("reason metadata grew beyond one repeated reason: %v", after) }
	}
	t.Logf("PRECONDITIONS partial_refusals=2 exclusions=1 actual_refused_exchanges=80 retained=%v", read())
}
