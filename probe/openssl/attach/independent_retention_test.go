//go:build attach

package attach_test

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

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
		admitter.Retract(added.Selections)
		stop()
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
		if reason == string(ebpf.DescriptorSeenInsideACall) || reason == string(ebpf.SocketWorkOutsideACall) || reason == string(ebpf.SocketDescriptorInvalid) {
			continue
		}
		if count != before[reason] {
			t.Errorf("process churn refusal %s moved %d -> %d", reason, before[reason], count)
		}
	}
	t.Logf("PRECONDITIONS real_process_churn=40 captured_processes=41 live_admitted=1 stores=%v", after)
}
