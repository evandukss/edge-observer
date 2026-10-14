package processing_test

import (
	"testing"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contentcoding"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/processing"
)

func encodingNoDecodeAdmission(t *testing.T, events []processing.DecodeCharge) {
	t.Helper()
	for _, e := range events {
		if e.Event == processing.ChargeReserving {
			t.Errorf("header-only classification admitted decoder work: %+v", e)
		}
	}
}
func encodingRefundLedger(t *testing.T, events []processing.DecodeCharge) {
	t.Helper()
	type key struct {
		index   int
		request bool
		charge  contentcoding.Charge
	}
	live := map[key]int{}
	requested := map[key]int{}
	granted, returned, refused := 0, 0, 0
	for _, e := range events {
		k := key{e.Index, e.Request, e.Charge}
		if e.Charge.Bytes <= 0 || e.Connection == 0 || e.Process.PID == 0 {
			t.Errorf("charge event has no positive charge or connection identity: %+v", e)
		}
		switch e.Event {
		case processing.ChargeReserving:
			requested[k]++
		case processing.ChargeReserved:
			if requested[k] != 1 {
				t.Errorf("grant did not follow one reservation attempt: %+v", e)
			}
			requested[k]--
			live[k]++
			granted++
		case processing.ChargeRefused:
			if requested[k] != 1 {
				t.Errorf("refusal did not follow one reservation attempt: %+v", e)
			}
			requested[k]--
			refused++
		case processing.ChargeReturned:
			if live[k] <= 0 {
				t.Errorf("charge returned without ownership or returned twice: %+v", e)
			}
			live[k]--
			returned++
		default:
			t.Errorf("unknown charge event: %+v", e)
		}
	}
	for k, n := range live {
		if n != 0 {
			t.Errorf("charge ledger retains %d of %+v", n, k)
		}
	}
	for k, n := range requested {
		if n != 0 {
			t.Errorf("reservation has no result: %d of %+v", n, k)
		}
	}
	if granted == 0 || returned != granted || refused != 1 {
		t.Errorf("decode ledger granted/returned/refused=%d/%d/%d, want nonzero equal grants and returns, one refusal", granted, returned, refused)
	}
}

// The growth-refusal cases run under the larger body bound. The decoder
// reserves its first output buffer at the smallest of the limit and its
// halvings that is still 4096 bytes or more, so at a 4096-byte bound the
// whole limit is reserved once and the output never grows; the growth step
// these cases fill the allowance at exists only under a larger bound.
func TestEncodingGrowthRefusalCutsWithoutAnotherIntakeEvent(t *testing.T) {
	for _, side := range []string{"request", "response"} {
		t.Run(side, func(t *testing.T) {
			pairs := []encodingPair{encodingPlain(0), encodingBadWithin(t, 1, processing.ReasonContentDecodedTooLarge, side, encodingCostlyBodyBound), encodingPlain(2)}
			c := encodingConversation(t, pairs)
			f := encodingWorkerWithin(t, "", 4096, encodingCostlyBodyBound)
			out := f.feed(t, c.fragments[:2])
			f.checkOnline(t, pairs[:1], out)
			var pressure int64
			filled := false
			oldOutput := int64(0)
			takenAtRefusal := 0
			f.onCharge = func(e processing.DecodeCharge) {
				if e.Index != 1 {
					return
				}
				if e.Event == processing.ChargeReserved && e.Charge.Kind == contentcoding.OutputCharge {
					oldOutput = e.Charge.Bytes
				}
				if e.Event == processing.ChargeReserving && e.Charge.Kind == contentcoding.OutputCharge && oldOutput > 0 && e.Charge.Bytes > oldOutput && !filled {
					stats := f.store.Stats()
					pressure = stats.LimitBytes - stats.Bytes - stats.Parsing - stats.Policy
					if pressure <= 0 || !f.store.Reserve(intake.Policy, pressure) {
						t.Fatal("wiring, not the property: could not fill remaining allowance at output growth")
					}
					filled = true
					takenAtRefusal = f.taken
				}
				if filled && f.taken != takenAtRefusal {
					t.Error("new intake event occurred inside the refused decoding transaction")
				}
			}
			t.Cleanup(func() {
				if pressure > 0 {
					f.store.Return(intake.Policy, pressure)
				}
			})
			out = f.feed(t, c.fragments[2:4])
			if !filled {
				t.Fatal("wiring, not the property: decoder output-growth seam did not fire; this case is pending while decoding is only vocabulary")
			}
			if out.ConnectionsCut != 1 || out.AllowanceCut != 1 || out.Excluded.Total() != 0 {
				t.Errorf("refused output growth became an exclusion or uncounted stop: cuts=%d allowance=%d exclusions=%+v", out.ConnectionsCut, out.AllowanceCut, out.Excluded)
			}
			stats := f.store.Stats()
			if stats.ParsingRefused != 1 || stats.FragmentsRefused != 0 || stats.ConnectionsRefused != 0 {
				t.Errorf("refusal was not exactly one parsing-work admission: %+v", stats)
			}
			if stats.Parsing != 0 || stats.Bytes != 0 || stats.Leased != 0 || stats.Policy != pressure {
				t.Errorf("cut failed to return all owned charges before another intake event: %+v, fixture pressure=%d", stats, pressure)
			}
			encodingRefundLedger(t, f.charges)
			for _, e := range f.charges {
				if side == "request" && !e.Request {
					t.Errorf("response decoding ran after request refusal: %+v", e)
				}
			}
			f.onCharge = nil
			f.store.Return(intake.Policy, pressure)
			pressure = 0
			out = f.feed(t, c.fragments[4:])
			out = f.retire(t, c.finals[0])
			if out.InputCut != 4 || out.ExchangeIDs != 1 || out.ProcessingFailures != 0 || out.Excluded.Total() != 0 {
				t.Errorf("refusal suffix counted incorrectly: %+v", out)
			}
			if out.Withheld != connection.Uncounted("connection_cut") {
				t.Errorf("refusal changed existing withheld cause: %+v", out.Withheld)
			}
			encodingCheckSuffixBoundary(t, f.output, pairs[:1])
			f.checkFinal(t, pairs[:1], true)
			if len(f.output.artifacts) != 2 {
				t.Errorf("refusal lost prefix or emitted later content: %d lines, want one prefix plus retirement", len(f.output.artifacts))
			}
			for _, a := range f.output.artifacts {
				if a.ReconstructionTruncation != nil {
					for _, stop := range a.ReconstructionTruncation.Stops {
						if stop.Reason != processing.TruncationConnectionCut {
							t.Errorf("refused reservation reason=%s, want connection_cut", stop.Reason)
						}
					}
				}
			}
			t.Logf("growth refused with no new intake: side=%s events=%d charged_before_growth=%d", side, len(f.charges), oldOutput)
		})
	}
}

func TestExtensionEncodingGrowthRefusalCutsWithoutAnotherIntakeEvent(t *testing.T) {
	for _, side := range []string{"request", "response"} {
		t.Run(side, func(t *testing.T) {
			pairs := []encodingPair{encodingPlain(0), encodingBadWithin(t, 1, processing.ReasonContentDecodedTooLarge, side, encodingCostlyBodyBound), encodingPlain(2)}
			c := encodingConversation(t, pairs)
			f := encodingExtensionWithin(t, 1, 4096, encodingCostlyBodyBound, nil)
			f.give(t, c.fragments[:2])
			f.checkOnline(t, pairs[:1])
			var pressure, oldOutput, takenAtRefusal int64
			filled := false
			f.chargeMu.Lock()
			f.onCharge = func(e processing.DecodeCharge) {
				if e.Index != 1 {
					return
				}
				if e.Event == processing.ChargeReserved && e.Charge.Kind == contentcoding.OutputCharge {
					oldOutput = e.Charge.Bytes
				}
				if e.Event == processing.ChargeReserving && e.Charge.Kind == contentcoding.OutputCharge && oldOutput > 0 && e.Charge.Bytes > oldOutput && !filled {
					stats := f.store.Stats()
					pressure = stats.LimitBytes - stats.Bytes - stats.Parsing - stats.Policy
					if pressure <= 0 || !f.store.Reserve(intake.Policy, pressure) {
						t.Error("wiring, not the property: could not fill remaining allowance at output growth")
						pressure = 0
						return
					}
					filled = true
					takenAtRefusal = f.taken.Load()
				}
				if filled && f.taken.Load() != takenAtRefusal {
					t.Error("new intake event occurred inside the refused decoding transaction")
				}
			}
			f.chargeMu.Unlock()
			t.Cleanup(func() {
				f.chargeMu.Lock()
				defer f.chargeMu.Unlock()
				f.onCharge = nil
				if pressure > 0 {
					f.store.Return(intake.Policy, pressure)
					pressure = 0
				}
			})
			f.give(t, c.fragments[2:4])
			if !f.await(t, "wiring, not the property: decoder output-growth seam did not fire; pending while decoding is only vocabulary", func() bool { f.chargeMu.Lock(); defer f.chargeMu.Unlock(); return filled }) {
				t.FailNow()
			}
			f.await(t, "refused growth did not publish its cut", func() bool { return f.run.Snapshot().ConnectionsCut == 1 })
			f.chargeMu.Lock()
			f.onCharge = nil
			heldPressure := pressure
			f.chargeMu.Unlock()
			out := f.run.Snapshot()
			if out.ConnectionsCut != 1 || out.AllowanceCut != 1 || out.Excluded.Total() != 0 {
				t.Errorf("refused growth became an exclusion or uncounted stop: %+v", out)
			}
			stats := f.store.Stats()
			if stats.ParsingRefused != 1 || stats.FragmentsRefused != 0 || stats.ConnectionsRefused != 0 {
				t.Errorf("refusal was not exactly one parsing-work admission: %+v", stats)
			}
			if stats.Parsing != 0 || stats.Bytes != 0 || stats.Leased != 0 || stats.Policy != heldPressure {
				t.Errorf("cut retained owned charges before another intake event: %+v, fixture pressure=%d", stats, heldPressure)
			}
			events := f.chargeSnapshot()
			encodingRefundLedger(t, events)
			for _, e := range events {
				if side == "request" && !e.Request {
					t.Errorf("response decoded after request refusal: %+v", e)
				}
			}
			f.chargeMu.Lock()
			f.store.Return(intake.Policy, pressure)
			pressure = 0
			f.chargeMu.Unlock()
			f.give(t, c.fragments[4:])
			out = f.finish(t, c.finals[0])
			if out.InputCut != 4 || out.ExchangeIDs != 1 || out.ProcessingFailures != 0 || out.Excluded.Total() != 0 {
				t.Errorf("refusal suffix counted incorrectly: %+v", out)
			}
			if out.Withheld != connection.Uncounted("connection_cut") {
				t.Errorf("refusal changed existing withheld cause: %+v", out.Withheld)
			}
			f.checkDone(t, 1)
			output := f.output.snapshot()
			encodingCheckSuffixBoundary(t, output, pairs[:1])
			helper := &encodingWorker{output: output, finalOutcome: &out}
			helper.checkFinal(t, pairs[:1], true)
			if len(output.artifacts) != 2 {
				t.Errorf("refusal lost prefix or emitted later content: %d lines", len(output.artifacts))
			}
			for _, m := range f.messages(t, 0) {
				if m.Type == "exchange" && m.Index != 0 {
					t.Errorf("extension received content at or beyond refused exchange: %+v", m)
				}
			}
		})
	}
}
