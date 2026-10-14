package processing_test

import (
	"bytes"
	"testing"

	"github.com/evandukss/edge-observer/contentcoding"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/processing"
)

type contentChargeSample struct {
	event processing.DecodeCharge
	stats intake.Stats
}

type contentChargeKey struct {
	request bool
	charge  contentcoding.Charge
}

// The observer is only evidence when a real reservation reached the shared
// allowance. A zero final balance alone would also pass a decoder that charged
// nothing at all. Every successful reservation must visibly increase that
// allowance's ownership, and each exact charge must have one return.
func TestDecodedChargesReachSharedAllowanceAndReturnOnce(t *testing.T) {
	plain := append([]byte(`{"value":"`), bytes.Repeat([]byte("body-value-"), 8192)...)
	plain = append(plain, []byte(`"}`)...)
	requestBody := contentEncoded(t, "br", plain)
	responseBody := contentEncoded(t, "gzip", plain)
	request := contentWire("POST /coded HTTP/1.1", "br", requestBody, false)
	response := contentWire("HTTP/1.1 200 OK", "gzip", responseBody, false)
	c := contentCaptured(t, append(bytes.Clone(request), []byte("GET /later HTTP/1.1\r\nHost: fixture\r\n\r\n")...), append(bytes.Clone(response), []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nNEXT")...), false)
	s := contentNew(t, nil)
	s.give(t, c)
	var reserved int
	for _, sample := range s.charges {
		if sample.event.Event == processing.ChargeReserved {
			reserved++
		}
	}
	if reserved == 0 {
		t.Fatal("wiring, not the property: no decoded reservation reached the observer; PENDING until the decode-path implementation emits reservation events")
	}
	contentPairs(t, s)
	beforeRetirement := len(s.charges)
	contentRetire(t, s, c)
	if len(s.charges) != beforeRetirement {
		t.Error("retirement returned charges again after the open exchange had been released")
	}

	live := map[contentChargeKey]int{}
	workspaces := map[[2]int]int{}
	outputs := map[[2]int]int{}
	largest := map[[2]int]int64{}
	var pending *contentChargeSample
	for i, sample := range s.charges {
		e := sample.event
		side, stages := 0, 1
		if e.Request {
			side, stages = 1, 1
		}
		stageKey := [2]int{side, e.Charge.Stage}
		key := contentChargeKey{request: e.Request, charge: e.Charge}
		if e.Process != c.fragments[0].Process || e.Connection != c.fragments[0].Connection || e.Index != 0 {
			t.Errorf("event %d has wrong fixture identity: %+v", i, e)
		}
		if e.Charge.Stage < 1 || e.Charge.Stage > stages || e.Charge.Bytes <= 0 || (e.Charge.Kind != contentcoding.WorkspaceCharge && e.Charge.Kind != contentcoding.OutputCharge) {
			t.Fatalf("invalid observed charge: %+v", e)
		}
		if sample.stats.Bytes < 0 || sample.stats.Parsing < 0 || sample.stats.Policy < 0 {
			t.Errorf("negative shared ownership at event %d: %+v", i, sample.stats)
		}
		total := sample.stats.Bytes + sample.stats.Parsing + sample.stats.Policy
		switch e.Event {
		case processing.ChargeReserving:
			if pending != nil {
				t.Fatal("a new reservation began before its predecessor was decided")
			}
			saved := sample
			pending = &saved
		case processing.ChargeReserved:
			if pending == nil || pending.event.Charge != e.Charge || pending.event.Request != e.Request {
				t.Fatalf("reservation has no matching admission event: %+v", e)
			}
			before := pending.stats.Bytes + pending.stats.Parsing + pending.stats.Policy
			if total-before != e.Charge.Bytes {
				t.Errorf("reservation event without actual shared charge: delta %d, want %d", total-before, e.Charge.Bytes)
			}
			pending = nil
			live[key]++
			if e.Charge.Kind == contentcoding.WorkspaceCharge {
				workspaces[stageKey]++
			} else {
				outputs[stageKey]++
				largest[stageKey] = max(largest[stageKey], e.Charge.Bytes)
			}
		case processing.ChargeRefused:
			t.Fatalf("healthy, generously funded fixture refused a charge: %+v", e)
		case processing.ChargeReturned:
			if pending != nil {
				t.Error("return interleaved inside a pending reservation")
			}
			if live[key] == 0 {
				t.Errorf("charge returned without ownership, or returned twice: %+v", e)
			} else {
				live[key]--
			}
		default:
			t.Fatalf("unknown charge event: %+v", e)
		}
	}
	if pending != nil {
		t.Error("last reservation was never decided")
	}
	for key, n := range live {
		if n != 0 {
			t.Errorf("charge not returned exactly once: %+v has %d still held", key, n)
		}
	}
	for _, stage := range [][2]int{{1, 1}, {0, 1}} {
		if workspaces[stage] != 1 || outputs[stage] == 0 {
			t.Errorf("wiring, not the property: side/stage %v admitted %d workspaces and %d outputs", stage, workspaces[stage], outputs[stage])
		}
	}
	for _, stage := range [][2]int{{1, 1}, {0, 1}} {
		if largest[stage] < int64(len(plain)) {
			t.Errorf("final decoded output was not fully charged: side/stage %v largest charge %d, content %d", stage, largest[stage], len(plain))
		}
	}
}
