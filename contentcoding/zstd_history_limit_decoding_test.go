package contentcoding

import (
	"bytes"
	"runtime"
	"testing"
)

// The zstd history limit (criterion 119 row 1a rev 53; decision 586). A stream
// whose frames declare rising windows makes the decoder's history buffer anew
// for each larger window. The limit admits the base making and two growths and
// refuses the third growth as content_decoding_too_costly, allocating no history
// for the frame it denies. An error or overrun established before the third
// growth keeps its own reason, and a clean prefix is never returned as a
// shortened successful decode.
//
// These are GRADED cases, authored from the criterion, not from T12's
// implementation. They run on T12's final tip with the history limit; on a tree
// without it the rising stream decodes and the refusal cases are red, which is
// the independent check that the limit is actually present.
//
// The windows are chosen so each frame's required history is strictly larger
// than the last, forcing a distinct making: descriptor d declares window
// 1<<(10+d>>3) (mantissa 0), and history below the threshold is twice the
// window. Descriptors 0, 8, 16, 24 give windows 1,2,4,8 KiB and histories
// 2,4,8,16 KiB: a base and three growths.

func zstdRisingStream(descriptors ...byte) (encoded, plain []byte) {
	for _, d := range descriptors {
		encoded = append(encoded, decodingZstdRawFrame(d, []byte{'a'})...)
		plain = append(plain, 'a')
	}
	return encoded, plain
}

// zstdHistoryMakings is the count of distinct, strictly increasing required
// histories a descriptor sequence forces: the base plus one per growth.
func zstdHistoryMakings(descriptors ...byte) int {
	makings, last := 0, int64(-1)
	for _, d := range descriptors {
		h := decodingHistory(int64(1) << (10 + uint(d>>3)))
		if h > last {
			makings++
			last = h
		}
	}
	return makings
}

func TestZstdHistoryLimitAdmitsTwoGrowthsAndRefusesTheThird(t *testing.T) {
	const bound = 8 << 20
	// Base plus two growths: three makings, admitted.
	admitted := []byte{0, 8, 16}
	// Base plus three growths: the fourth making, refused.
	refused := []byte{0, 8, 16, 24}
	if zstdHistoryMakings(admitted...) != 3 || zstdHistoryMakings(refused...) != 4 {
		t.Fatalf("wiring, not the property: makings admitted=%d refused=%d, want 3 and 4",
			zstdHistoryMakings(admitted...), zstdHistoryMakings(refused...))
	}

	okEncoded, okPlain := zstdRisingStream(admitted...)
	if !bytes.Equal(decodingReference(t, "zstd", okEncoded), okPlain) {
		t.Fatal("wiring, not the property: the admitted rising stream does not decode with the reference")
	}
	badEncoded, badPlain := zstdRisingStream(refused...)
	if !bytes.Equal(decodingReference(t, "zstd", badEncoded), badPlain) {
		t.Fatal("wiring, not the property: the refused rising stream is not a valid zstd stream")
	}

	t.Run("two-growths-admitted", func(t *testing.T) {
		ledger := &decodingLedger{t: t, list: decodingList(Zstd), bound: bound}
		got := Decode(decodingList(Zstd), okEncoded, Options{Bound: bound, Reserver: ledger})
		if got.Outcome != Decoded || !bytes.Equal(got.Body, okPlain) {
			t.Fatalf("base and two growths did not decode: outcome=%v body=%q", got.Outcome, got.Body)
		}
		if got.Charge > 0 {
			ledger.Release(Charge{Kind: OutputCharge, Stage: 1, Bytes: got.Charge})
		}
		if ledger.total() != 0 {
			t.Errorf("admitted decode leaked %d bytes", ledger.total())
		}
	})

	t.Run("third-growth-refused-too-costly", func(t *testing.T) {
		ledger := &decodingLedger{t: t, list: decodingList(Zstd), bound: bound}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		got := Decode(decodingList(Zstd), badEncoded, Options{Bound: bound, Reserver: ledger})
		runtime.ReadMemStats(&after)
		if got.Outcome != DecodingTooCostly || got.Outcome.Reason() != ReasonDecodingTooCostly {
			t.Fatalf("third growth: outcome=%v reason=%q, want DecodingTooCostly/%s", got.Outcome, got.Outcome.Reason(), ReasonDecodingTooCostly)
		}
		if got.Body != nil || got.Charge != 0 || ledger.total() != 0 {
			t.Errorf("refused decode retained body/charge or leaked: body=%d charge=%d held=%d", len(got.Body), got.Charge, ledger.total())
		}
		// No history for the denied frame: the extra allocation over the admitted
		// decode is far below the denied growth's history (16 KiB doubled and then
		// some). A decode that made the fourth history would allocate at least it.
		denied := decodingHistory(1 << (10 + 24>>3))
		okLedger := &decodingLedger{t: t, list: decodingList(Zstd), bound: bound}
		var okBefore, okAfter runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&okBefore)
		okGot := Decode(decodingList(Zstd), okEncoded, Options{Bound: bound, Reserver: okLedger})
		runtime.ReadMemStats(&okAfter)
		if okGot.Charge > 0 {
			okLedger.Release(Charge{Kind: OutputCharge, Stage: 1, Bytes: okGot.Charge})
		}
		refusedAlloc := int64(after.TotalAlloc - before.TotalAlloc)
		admittedAlloc := int64(okAfter.TotalAlloc - okBefore.TotalAlloc)
		if refusedAlloc > admittedAlloc+denied {
			t.Errorf("the denied frame allocated history: refused %d, admitted %d, denied-history %d", refusedAlloc, admittedAlloc, denied)
		}
		t.Logf("history-limit refusal: refusedAlloc=%d admittedAlloc=%d denied-history=%d", refusedAlloc, admittedAlloc, denied)
	})

	t.Run("clean-prefix-is-not-a-shortened-decode", func(t *testing.T) {
		got := Decode(decodingList(Zstd), badEncoded, Options{Bound: bound})
		if got.Outcome == Decoded || got.Body != nil {
			t.Errorf("the clean prefix was returned as a shortened decode: outcome=%v body=%q", got.Outcome, got.Body)
		}
	})
}

func TestZstdHistoryLimitKeepsAnEarlierReason(t *testing.T) {
	const bound = 8 << 20
	// A corrupt second frame establishes content_decoding_failed before the third
	// growth would be reached, and that reason stands.
	encoded, _ := zstdRisingStream(0, 8, 16, 24)
	frame0 := decodingZstdRawFrame(0, []byte{'a'})
	corrupt := bytes.Clone(encoded)
	// Set the second frame's block type to the reserved value (3) by raising the
	// two type bits in its block-header low byte, at offset len(frame0)+6. The
	// decoder rejects that frame as content_decoding_failed, before the fourth
	// frame's history growth would be refused. A literal-byte flip would decode
	// to a different byte and still be valid, which is why the type is corrupted.
	corrupt[len(frame0)+6] |= 0x06
	if bytes.Equal(corrupt, encoded) {
		t.Fatal("wiring, not the property: corruption did not change the stream")
	}
	got := Decode(decodingList(Zstd), corrupt, Options{Bound: bound})
	if got.Outcome != DecodingFailed {
		t.Errorf("an earlier corruption did not keep its reason: outcome=%v, want DecodingFailed", got.Outcome)
	}

	// An output overrun before the third growth keeps content_decoded_too_large:
	// a large first frame that overflows the bound decides before any later
	// growth is considered.
	small := 64
	big := bytes.Repeat([]byte{'a'}, small+1)
	overrun := decodingZstdRawFrame(0, big)
	overrun = append(overrun, decodingZstdRawFrame(24, []byte{'a'})...)
	if got := Decode(decodingList(Zstd), overrun, Options{Bound: small}); got.Outcome != DecodedTooLarge {
		t.Errorf("an overrun before the third growth did not keep its reason: outcome=%v, want DecodedTooLarge", got.Outcome)
	}
}
