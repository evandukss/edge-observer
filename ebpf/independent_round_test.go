//go:build attach

package ebpf_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

func TestIndependentRoundMissingNormalReturn(t *testing.T) {
	r := proofFixture(t, nil)
	_, peer := r.open(t, 0)
	r.command(t, "W 0 1")
	r.consume()
	n, err := ebpf.IndependentRemoveReturn(r.session, "SSL_read")
	if err != nil || n != 1 {
		t.Fatalf("UNPROVED: return links removed=%d err=%v", n, err)
	}
	r.command(t, "O")
	if _, err := peer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if got := r.command(t, "J"); got != "J 1 0" {
		t.Fatalf("UNPROVED: lost-return read: %s", got)
	}
	if _, err := peer.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	if got := r.command(t, "V 0"); got != "V 1 1" {
		t.Fatalf("UNPROVED: later read: %s", got)
	}
	r.consume()
	blind := proofCounter(t, r.session.Unmeasurable)
	if blind != 0 {
		t.Fatalf("UNPROVED: normal path not exercised, unmeasurable=%d", blind)
	}
	later := 0
	for _, e := range r.events {
		if e.Direction == fragment.Received && e.Length == 1 {
			later++
			if e.Sequence.Number != 2 {
				t.Errorf("COUNTEREXAMPLE: normal missing return left no number: %+v", e.Sequence)
			}
		}
	}
	if later != 1 {
		t.Fatalf("UNPROVED: later read events=%d", later)
	}
	r.command(t, "F 0")
	r.consume()
	r.finish(t)
	if len(r.collected.records) != 1 {
		t.Fatalf("UNPROVED: records=%d", len(r.collected.records))
	}
	for _, rec := range r.collected.records {
		recv, _ := rec.Placement(fragment.Received)
		sent, _ := rec.Placement(fragment.Sent)
		if recv.Whole() || !sent.Whole() {
			t.Errorf("COUNTEREXAMPLE: recv=%+v sent=%+v", recv, sent)
		}
	}
	t.Logf("PRECONDITIONS removed_returns=%d successful_reads=2 unmeasurable=%d later_events=%d", n, blind, later)
}

func TestIndependentRoundSendfile(t *testing.T) {
	r := proofFixture(t, nil)
	_, peer := r.open(t, 0)
	confirmed := 0
	for _, p := range r.session.Placed() {
		if p.Point.Symbol == "SSL_sendfile" && p.Confirmed {
			confirmed++
		}
	}
	if confirmed != 1 {
		t.Fatalf("UNPROVED: confirmed sendfile=%d", confirmed)
	}
	r.command(t, "W 0 1")
	r.consume()
	ktls := r.command(t, "K 0")
	result := r.command(t, "S 0")
	r.command(t, "W 0 1")
	r.consume()
	if _, err := peer.Write([]byte("r")); err != nil {
		t.Fatal(err)
	}
	if got := r.command(t, "V 0"); got != "V 1 1" {
		t.Fatalf("UNPROVED: recv control %s", got)
	}
	r.consume()
	r.command(t, "F 0")
	r.consume()
	r.finish(t)
	numbers := []uint64{}
	for _, e := range r.events {
		if e.Direction == fragment.Sent && e.Length == 512 {
			numbers = append(numbers, e.Sequence.Number)
		}
	}
	if fmt.Sprint(numbers) != "[1 3]" {
		t.Errorf("COUNTEREXAMPLE: sendfile left no gap: %v", numbers)
	}
	if len(r.collected.records) != 1 {
		t.Fatalf("UNPROVED: records=%d", len(r.collected.records))
	}
	for _, rec := range r.collected.records {
		sent, _ := rec.Placement(fragment.Sent)
		recv, _ := rec.Placement(fragment.Received)
		if sent.Whole() || !recv.Whole() {
			t.Errorf("COUNTEREXAMPLE: sent=%+v recv=%+v", sent, recv)
		}
	}
	t.Logf("PRECONDITIONS sendfile_calls=1 confirmed_entries=%d %s %s sent_numbers=%v; successful_kTLS_byte_moves=0 UNPROVED", confirmed, ktls, result, numbers)
}

func TestIndependentRoundBirthWithDataAbsent(t *testing.T) {
	r := proofConfigured(t, nil, func(o *ebpf.Options) {
		o.DeferCaptureLive = true
		var life []ebpf.Point
		for _, p := range o.Points {
			if p.Symbol == "SSL_new" || p.Symbol == "SSL_free" {
				life = append(life, p)
			}
		}
		o.Points = life
	})
	old, _ := r.open(t, 0)
	r.command(t, "W 0 1")
	deadline := time.Now().Add(time.Second)
	for r.bytes.Load() < 512 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if r.bytes.Load() != 512 {
		t.Fatalf("UNPROVED: pre-live peer bytes=%d", r.bytes.Load())
	}
	r.consume()
	if len(r.events) != 0 {
		t.Fatalf("UNPROVED: pre-live data events=%d", len(r.events))
	}
	var data []ebpf.Point
	for _, p := range r.points {
		if p.Symbol != "SSL_new" && p.Symbol != "SSL_free" {
			data = append(data, p)
		}
	}
	if err := ebpf.IndependentPlace(r.session, data); err != nil {
		t.Fatal(err)
	}
	if err := r.session.MarkCaptureLive(); err != nil {
		t.Fatal(err)
	}
	r.command(t, "W 0 1")
	r.consume()
	fresh, _ := r.open(t, 1)
	r.command(t, "W 1 1")
	r.consume()
	observedOld, observedFresh := 0, 0
	for _, e := range r.events {
		if e.Length != 512 {
			continue
		}
		if e.SSL == old {
			observedOld++
			if e.Sequence.Born {
				t.Errorf("COUNTEREXAMPLE: pre-data birth promoted Born: %+v", e.Sequence)
			}
		}
		if e.SSL == fresh {
			observedFresh++
			if !e.Sequence.Born || e.Sequence.Number != 1 {
				t.Errorf("COUNTEREXAMPLE: new birth not fresh: %+v", e.Sequence)
			}
		}
	}
	if observedOld != 1 || observedFresh != 1 {
		t.Fatalf("UNPROVED: old=%d fresh=%d", observedOld, observedFresh)
	}
	r.command(t, "F 0")
	r.consume()
	r.command(t, "F 1")
	r.consume()
	r.finish(t)
	t.Logf("PRECONDITIONS actual_absent_data_probes=%d pre_live_byte_calls=1 pre_live_peer_bytes=512 old_after_live=%d new_births=%d", len(data), observedOld, observedFresh)
}

func TestIndependentRoundPartialPlacement(t *testing.T) {
	refused := 0
	r := proofConfigured(t, nil, func(o *ebpf.Options) {
		for i := range o.Points {
			if o.Points[i].Symbol == "SSL_write" || o.Points[i].Symbol == "SSL_write_ex" || o.Points[i].Symbol == "SSL_sendfile" {
				o.Points[i].Path = "/independent-proof-missing-library"
				refused++
			}
		}
	})
	if refused != 3 {
		t.Fatalf("UNPROVED: refused=%d", refused)
	}
	liveCoverage := r.session.Coverage()
	_, peer := r.open(t, 0)
	r.command(t, "W 0 1")
	deadline := time.Now().Add(time.Second)
	for r.bytes.Load() < 512 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if r.bytes.Load() != 512 {
		t.Fatalf("UNPROVED: missing-probe peer bytes=%d", r.bytes.Load())
	}
	if got := r.command(t, "T 0"); got != "T 1 512" {
		t.Fatalf("UNPROVED: surviving sent route: %s", got)
	}
	r.consume()
	if _, err := peer.Write([]byte("r")); err != nil {
		t.Fatal(err)
	}
	if got := r.command(t, "V 0"); got != "V 1 1" {
		t.Fatalf("UNPROVED: recv control %s", got)
	}
	r.consume()
	r.command(t, "F 0")
	r.consume()
	r.finish(t)
	born := 0
	for _, e := range r.events {
		if e.Sequence.Born {
			born++
		}
	}
	t.Logf("LIVE_COVERAGE %+v", liveCoverage)
	t.Logf("ACCOUNT_CAPABILITY %s; unprobed=%v", account.Describe(liveCoverage.Narrow(probe.Capability{Payload: true, Backend: probe.BPF, Filtered: true})), r.session.Unprobed())
	if len(r.collected.records) != 1 {
		t.Fatalf("UNPROVED: records=%d", len(r.collected.records))
	}
	for _, rec := range r.collected.records {
		sent, _ := rec.Placement(fragment.Sent)
		t.Logf("OBSERVED missing_plaintext_bytes=512 born_events=%d sent=%+v", born, sent)
		if born > 0 || sent.Whole() {
			t.Errorf("COUNTEREXAMPLE: partial placement marked Born and whole despite 512 missing sent bytes")
		}
	}
	t.Logf("PRECONDITIONS refused_data_routes=%d missing_byte_calls=1 peer_bytes=512", refused)
}

func TestIndependentRoundSendfileRefusalCoverage(t *testing.T) {
	r := proofConfigured(t, nil, func(o *ebpf.Options) {
		for i := range o.Points {
			if o.Points[i].Symbol == "SSL_sendfile" {
				o.Points[i].Path = "/independent-proof-missing-library"
			}
		}
	})
	refused := 0
	for _, p := range r.session.Placed() {
		if p.Point.Symbol == "SSL_sendfile" && !p.Confirmed {
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("UNPROVED: refused sendfile=%d", refused)
	}
	c := r.session.Coverage()
	if err := (probe.Request{}).Unmet(c.Narrow(probe.Capability{Payload: true})); err != nil {
		t.Fatalf("UNPROVED: attachment refused: %v", err)
	}
	if !strings.Contains(strings.Join(c.Unobserved, ","), "SSL_sendfile") {
		t.Errorf("COUNTEREXAMPLE: refused byte-moving route missing from Unobserved: %+v", c)
	}
	t.Logf("PRECONDITIONS sendfile_refusals=%d attachment_accepted=1", refused)
}
