package contentcoding

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"runtime"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func decodingList(codings ...Coding) List {
	var l List
	copy(l.codings[:], codings)
	l.n = uint8(len(codings))
	return l
}

func decodingEncode(t *testing.T, name string, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w io.WriteCloser
	switch name {
	case "gzip", "x-gzip":
		w = gzip.NewWriter(&buf)
	case "deflate":
		w = zlib.NewWriter(&buf)
	case "raw":
		var err error
		w, err = flate.NewWriter(&buf, flate.BestCompression)
		if err != nil {
			t.Fatal(err)
		}
	case "br":
		w = brotli.NewWriterOptions(&buf, brotli.WriterOptions{Quality: 5, LGWin: 10})
	case "zstd":
		var err error
		w, err = zstd.NewWriter(&buf, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(1024), zstd.WithSingleSegment(false), zstd.WithEncoderCRC(true))
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("wiring, not the property: unknown fixture encoder %q", name)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	encoded := buf.Bytes()
	decoded := decodingReference(t, name, encoded)
	if !bytes.Equal(decoded, plain) {
		t.Fatal("wiring, not the property: fixture does not round-trip through its codec")
	}
	return encoded
}

func decodingReference(t *testing.T, name string, encoded []byte) []byte {
	t.Helper()
	var r io.Reader
	var closer io.Closer
	var err error
	switch name {
	case "gzip", "x-gzip":
		closer, err = gzip.NewReader(bytes.NewReader(encoded))
		if err == nil {
			r = closer.(io.Reader)
		}
	case "deflate":
		closer, err = zlib.NewReader(bytes.NewReader(encoded))
		if err == nil {
			r = closer.(io.Reader)
		}
	case "raw":
		closer = flate.NewReader(bytes.NewReader(encoded))
		r = closer.(io.Reader)
	case "br":
		r = brotli.NewReader(bytes.NewReader(encoded))
	case "zstd":
		var zr *zstd.Decoder
		zr, err = zstd.NewReader(bytes.NewReader(encoded), zstd.WithDecoderConcurrency(1))
		if err == nil {
			defer zr.Close()
			r = zr
		}
	}
	if err != nil {
		t.Fatalf("wiring, not the property: reference reader: %v", err)
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}
	if r == nil {
		t.Fatal("wiring, not the property: no reference reader")
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("wiring, not the property: reference decode: %v", err)
	}
	return out
}

type decodingLedger struct {
	t               *testing.T
	list            List
	bound           int
	held            [4][3]int64
	peak            int64
	calls           int
	refuse          int
	refused         bool
	workspaceStages int
	workspace       [4]int64
	outputs         [4][2]int64
	expectedFirst   int64
}

func (l *decodingLedger) Reserve(c Charge) bool {
	l.calls++
	if c.Stage < 1 || c.Stage > l.list.Len() || c.Kind < WorkspaceCharge || c.Kind > OutputCharge || c.Bytes <= 0 {
		l.t.Fatalf("invalid reservation: %+v", c)
	}
	if l.calls == l.refuse {
		l.refused = true
		return false
	}
	if c.Kind == WorkspaceCharge {
		l.workspace[c.Stage] = c.Bytes
		if c.Stage == 1 && l.expectedFirst != 0 && c.Bytes != l.expectedFirst {
			l.t.Errorf("workspace charge = %d, want plan %d", c.Bytes, l.expectedFirst)
		}
		l.workspaceStages++
		for stage := 1; stage <= l.list.Len(); stage++ {
			if l.held[stage][WorkspaceCharge] != 0 {
				l.t.Errorf("stage %d overlaps workspace of stage %d", c.Stage, stage)
			}
		}
	}
	if c.Kind == OutputCharge {
		if c.Bytes > int64(l.bound+1) {
			l.t.Errorf("output buffer %d exceeds B+1", c.Bytes)
		}
		if l.outputs[c.Stage][0] == 0 {
			l.outputs[c.Stage][0] = c.Bytes
		} else if l.outputs[c.Stage][1] == 0 {
			l.outputs[c.Stage][1] = c.Bytes
		} else {
			l.t.Fatal("more than old and new output buffer live")
		}
	}
	l.held[c.Stage][c.Kind] += c.Bytes
	l.peak = max(l.peak, l.total())
	if l.peak > Charges(l.list.At(0), l.bound) {
		l.t.Errorf("held peak %d exceeds ceiling %d", l.peak, Charges(l.list.At(0), l.bound))
	}
	return true
}

func (l *decodingLedger) Release(c Charge) {
	if c.Stage < 1 || c.Stage > l.list.Len() || c.Kind < WorkspaceCharge || c.Kind > OutputCharge || c.Bytes <= 0 {
		l.t.Fatalf("invalid release: %+v", c)
	}
	if c.Kind == OutputCharge {
		found := false
		for i, held := range l.outputs[c.Stage] {
			if held == c.Bytes {
				l.outputs[c.Stage][i] = 0
				found = true
				break
			}
		}
		if !found {
			l.t.Errorf("output release has no matching live buffer: %+v", c)
		}
	} else if l.held[c.Stage][c.Kind] != c.Bytes {
		l.t.Errorf("release %+v differs from held %d", c, l.held[c.Stage][c.Kind])
	}
	l.held[c.Stage][c.Kind] -= c.Bytes
}

func (l *decodingLedger) total() int64 {
	var sum int64
	for _, stage := range l.held {
		for _, n := range stage {
			sum += n
		}
	}
	return sum
}

func decodingRun(t *testing.T, list List, encoded []byte, bound int, want Outcome, stage int, plain []byte) []StageIO {
	t.Helper()
	before := bytes.Clone(encoded)
	ledger := &decodingLedger{t: t, list: list, bound: bound, expectedFirst: Workspace(list.At(list.Len()-1), encoded, bound)}
	var observed []StageIO
	got := Decode(list, encoded, Options{Bound: bound, Reserver: ledger, Observe: func(s StageIO) { observed = append(observed, s) }})
	// Direct invocation fixes the subject and arguments. The fixture's round-trip
	// guard precedes it; this guard distinguishes an unentered stub from a verdict.
	if got.Outcome == 0 {
		t.Fatal("wiring, not the property: Decode returned no outcome")
	}
	if got.Outcome != want || got.Stage != stage {
		t.Errorf("outcome/stage = %v/%d, want %v/%d", got.Outcome, got.Stage, want, stage)
	}
	wantReason := ""
	if want == DecodingFailed {
		wantReason = "content_decoding_failed"
	}
	if want == DecodedTooLarge {
		wantReason = "content_decoded_too_large"
	}
	if got.Outcome.Reason() != wantReason {
		t.Errorf("reason = %q, want %q", got.Outcome.Reason(), wantReason)
	}
	if !bytes.Equal(encoded, before) {
		t.Error("decoder mutated captured input")
	}
	if want == Decoded {
		if !bytes.Equal(got.Body, plain) {
			t.Errorf("decoded body differs: got %d bytes, want %d", len(got.Body), len(plain))
		}
		if ledger.total() != got.Charge || got.Charge != int64(cap(got.Body)) {
			t.Errorf("final charge = %d, capacity = %d, held = %d", got.Charge, cap(got.Body), ledger.total())
		}
		if ledger.workspaceStages != list.Len() {
			t.Errorf("reserved %d workspaces, want %d", ledger.workspaceStages, list.Len())
		}
		if got.Charge > 0 {
			ledger.Release(Charge{Kind: OutputCharge, Stage: list.Len(), Bytes: got.Charge})
		}
	} else if got.Body != nil || got.Charge != 0 {
		t.Errorf("failure retained partial body or charge: body=%d charge=%d", len(got.Body), got.Charge)
	}
	if ledger.total() != 0 {
		t.Errorf("decode leaked %d bytes", ledger.total())
	}
	if len(observed) == 0 && want != DecodingFailed {
		t.Fatal("wiring, not the property: no stage I/O observed")
	}
	if len(observed) > list.Len() {
		t.Fatalf("observed %d stages for %d codings", len(observed), list.Len())
	}
	for i, s := range observed {
		if s.Stage != i+1 || s.Coding != list.At(list.Len()-i-1) {
			t.Errorf("stage order: %+v", observed)
			break
		}
		if s.Planned < 0 || s.Planned > s.Input || s.Workspace != ledger.workspace[s.Stage] {
			t.Errorf("stage plan differs from admitted workspace: %+v, admitted=%d", s, ledger.workspace[s.Stage])
		}
		if s.Read < 0 || s.Read > s.Input || s.Returned < 0 || s.Returned > int64(bound+1) {
			t.Errorf("stage I/O budget exceeded: %+v, bound=%d", s, bound)
		}
	}
	return observed
}

func TestCodingListsPreserveCapturedOrder(t *testing.T) {
	cases := []struct {
		name    string
		fields  []string
		want    Verdict
		codings []Coding
	}{
		{"absent", nil, Supported, nil},
		{"identity", []string{"identity, IDENTITY", " , \t,"}, Supported, nil},
		{"alias-among-identities", []string{"identity", " X-GZip, identity", "IDENTITY"}, Supported, []Coding{Gzip}},
		{"two", []string{"br, gzip"}, Unsupported, nil},
		{"duplicates", []string{"gzip", "gzip"}, Unsupported, nil},
		{"alias-duplicates", []string{"gzip", "x-gzip"}, Unsupported, nil},
		{"zstd", []string{"zstd"}, Supported, []Coding{Zstd}},
		{"unknown-first", []string{"compress, gzip"}, Unsupported, nil},
		{"unknown-last", []string{"gzip, compress"}, Unsupported, nil},
		{"four", []string{"gzip, br, zstd, deflate"}, Unsupported, nil},
		{"malformed-after-unknown", []string{"compress, gzip;level=1"}, Malformed, nil},
		{"quoted", []string{`"gzip"`}, Malformed, nil},
		{"embedded-space", []string{"g zip"}, Malformed, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list, got := ParseList(tc.fields)
			if got == 0 {
				t.Fatal("wiring, not the property: ParseList returned no verdict")
			}
			if got != tc.want || list.Len() != len(tc.codings) {
				t.Fatalf("verdict/count = %v/%d, want %v/%d", got, list.Len(), tc.want, len(tc.codings))
			}
			for i, c := range tc.codings {
				if list.At(i) != c {
					t.Errorf("coding %d = %v, want %v", i, list.At(i), c)
				}
			}
			wantReason := ""
			if tc.want == Unsupported {
				wantReason = "content_coding_unsupported"
			}
			if got.Reason() != wantReason {
				t.Errorf("reason = %q, want %q", got.Reason(), wantReason)
			}
		})
	}
}

func TestBodiesDecodeAtTheLimit(t *testing.T) {
	plain := bytes.Repeat([]byte("decoded-content/"), 128)
	for _, tc := range []struct {
		name   string
		coding Coding
	}{{"gzip", Gzip}, {"x-gzip", Gzip}, {"deflate", Deflate}, {"raw", Deflate}, {"br", Brotli}, {"zstd", Zstd}} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := decodingEncode(t, tc.name, plain)
			t.Run("at-limit", func(t *testing.T) { decodingRun(t, decodingList(tc.coding), encoded, len(plain), Decoded, 0, plain) })
			t.Run("one-over", func(t *testing.T) {
				decodingRun(t, decodingList(tc.coding), encoded, len(plain)-1, DecodedTooLarge, 1, nil)
			})
		})
	}
}

func TestConcatenatedCodingMembersValidateEveryPart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		coding Coding
	}{{"gzip", Gzip}, {"zstd", Zstd}} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := []byte("first/"), []byte("second")
			one, two := decodingEncode(t, tc.name, a), decodingEncode(t, tc.name, b)
			joined := append(bytes.Clone(one), two...)
			t.Run("valid", func(t *testing.T) {
				decodingRun(t, decodingList(tc.coding), joined, 1024, Decoded, 0, append(bytes.Clone(a), b...))
			})
			bad := bytes.Clone(joined)
			bad[len(one)] ^= 0xff
			t.Run("bad-later-member", func(t *testing.T) { decodingRun(t, decodingList(tc.coding), bad, 1024, DecodingFailed, 1, nil) })
		})
	}
}

func TestInvalidBodiesDiscardEveryPrefix(t *testing.T) {
	plain := []byte(`{"useful":"prefix","sentinel":"must-not-escape"}`)
	for _, tc := range []struct {
		name   string
		coding Coding
	}{{"gzip", Gzip}, {"deflate", Deflate}, {"raw", Deflate}, {"br", Brotli}, {"zstd", Zstd}} {
		t.Run(tc.name, func(t *testing.T) {
			valid := decodingEncode(t, tc.name, plain)
			cases := map[string][]byte{"truncated": bytes.Clone(valid[:len(valid)-1]), "trailing": append(bytes.Clone(valid), 0x7f), "empty": {}}
			if tc.name == "gzip" || tc.name == "deflate" || tc.name == "zstd" {
				bad := bytes.Clone(valid)
				at := len(bad) - 1
				if tc.name == "gzip" {
					at = len(bad) - 8
				}
				bad[at] ^= 0x80
				cases["checksum"] = bad
			}
			for name, encoded := range cases {
				t.Run(name, func(t *testing.T) {
					if bytes.Equal(valid, encoded) {
						t.Fatal("wiring, not the property: corruption did not change fixture")
					}
					// Empty brotli is rejected by its header check, before an observer exists.
					if tc.name == "br" && len(encoded) == 0 {
						got := Decode(decodingList(Brotli), encoded, Options{Bound: 4096})
						if got.Outcome != DecodingFailed || got.Body != nil || got.Charge != 0 {
							t.Fatalf("empty brotli result: %+v", got)
						}
						return
					}
					decodingRun(t, decodingList(tc.coding), encoded, 4096, DecodingFailed, 1, nil)
				})
			}
		})
	}
}

func TestChecksumBeyondOutputBoundIsNotSought(t *testing.T) {
	plain := bytes.Repeat([]byte("a"), 1<<20)
	for _, tc := range []struct {
		name   string
		coding Coding
	}{{"gzip", Gzip}, {"deflate", Deflate}} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := decodingEncode(t, tc.name, plain)
			at := len(encoded) - 1
			if tc.name == "gzip" {
				at = len(encoded) - 8
			}
			encoded[at] ^= 0x80
			observed := decodingRun(t, decodingList(tc.coding), encoded, 1024, DecodedTooLarge, 1, nil)
			if observed[0].Returned != 1025 {
				t.Errorf("lookahead returned %d, want 1025", observed[0].Returned)
			}
		})
	}
}

func TestDeflateHeaderDiscriminatorDoesNotRetry(t *testing.T) {
	// A raw stored block can begin with the valid zlib prefix 78 01.
	// The next two bytes are its length, not a zlib payload. Retrying raw
	// after zlib rejects this stream would turn a required failure into success.
	raw := []byte{0x78, 0x01, 0x00, 0xfe, 0xff, 'Q', 0x01, 0x00, 0x00, 0xff, 0xff}
	if got := decodingReference(t, "raw", raw); !bytes.Equal(got, []byte{'Q'}) {
		t.Fatal("wiring, not the property: discriminator collision is not raw deflate")
	}
	if (int(raw[0])*256+int(raw[1]))%31 != 0 {
		t.Fatal("wiring, not the property: collision misses zlib predicate")
	}
	t.Run("zlib-collision", func(t *testing.T) { decodingRun(t, decodingList(Deflate), raw, 1024, DecodingFailed, 1, nil) })
	// Changing only ignored stored-block padding breaks the predicate.
	raw[0] = 0x70
	if got := decodingReference(t, "raw", raw); !bytes.Equal(got, []byte{'Q'}) {
		t.Fatal("wiring, not the property: neighbouring raw stream is invalid")
	}
	t.Run("raw-method", func(t *testing.T) { decodingRun(t, decodingList(Deflate), raw, 1024, Decoded, 0, []byte{'Q'}) })
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevelDict(&buf, zlib.BestCompression, []byte("dictionary"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("dictionary payload")); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if buf.Bytes()[1]&0x20 == 0 {
		t.Fatal("wiring, not the property: dictionary flag missing")
	}
	t.Run("dictionary", func(t *testing.T) { decodingRun(t, decodingList(Deflate), buf.Bytes(), 1024, DecodingFailed, 1, nil) })
}

func TestWorkspaceRefusalAllocatesOnlyAdmission(t *testing.T) {
	for _, tc := range []struct {
		name   string
		coding Coding
	}{{"gzip", Gzip}, {"deflate", Deflate}, {"br", Brotli}, {"zstd", Zstd}} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := decodingEncode(t, tc.name, bytes.Repeat([]byte("a"), 512))
			refuser := &decodingAdmission{}
			options := Options{Bound: 1024, Reserver: refuser}
			list := decodingList(tc.coding)
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			got := Decode(list, encoded, options)
			runtime.ReadMemStats(&after)
			if refuser.calls != 1 || !refuser.refused {
				t.Fatal("wiring, not the property: workspace refusal was not reached exactly once")
			}
			if refuser.charge.Kind != WorkspaceCharge || refuser.charge.Bytes != Workspace(tc.coding, encoded, 1024) {
				t.Errorf("workspace admission: %+v", refuser.charge)
			}
			if got.Outcome != Refused || got.Body != nil || got.Charge != 0 || refuser.releases != 0 {
				t.Errorf("refusal retained state: result=%+v releases=%d", got, refuser.releases)
			}
			if delta := after.TotalAlloc - before.TotalAlloc; delta > AdmissionAllocation {
				t.Errorf("allocation before refused workspace = %d, bound = %d", delta, AdmissionAllocation)
			}
			t.Logf("admission allocation=%d bound=%d", after.TotalAlloc-before.TotalAlloc, AdmissionAllocation)
		})
	}
}

type decodingAdmission struct {
	calls, releases int
	refused         bool
	charge          Charge
}

func (r *decodingAdmission) Reserve(c Charge) bool {
	r.calls++
	r.refused = true
	r.charge = c
	return false
}
func (r *decodingAdmission) Release(Charge) { r.releases++ }

func TestReservationRefusalReleasesAllPartialOutputs(t *testing.T) {
	plain := bytes.Repeat([]byte("body/"), 4096)
	encoded := decodingEncode(t, "gzip", plain)
	list := decodingList(Gzip)
	control := &decodingLedger{t: t, list: list, bound: len(plain)}
	got := Decode(list, encoded, Options{Bound: len(plain), Reserver: control})
	if control.calls < 2 || got.Outcome != Decoded {
		t.Fatal("wiring, not the property: admitted control did not reach workspace and output reservations")
	}
	if got.Charge > 0 {
		control.Release(Charge{Kind: OutputCharge, Stage: 1, Bytes: got.Charge})
	}
	for refusal := 1; refusal <= control.calls; refusal++ {
		t.Run(fmt.Sprint(refusal), func(t *testing.T) {
			ledger := &decodingLedger{t: t, list: list, bound: len(plain), refuse: refusal}
			got := Decode(list, encoded, Options{Bound: len(plain), Reserver: ledger})
			if !ledger.refused {
				t.Fatal("wiring, not the property: selected reservation was not attempted")
			}
			if got.Outcome != Refused || got.Outcome.Reason() != "" || got.Body != nil || got.Charge != 0 || ledger.total() != 0 {
				t.Errorf("refusal result=%+v held=%d", got, ledger.total())
			}
		})
	}
}

func TestLargeDeclaredWindowsWithSmallBodies(t *testing.T) {
	plain := []byte("small body")
	var br bytes.Buffer
	w := brotli.NewWriterOptions(&br, brotli.WriterOptions{Quality: 5, LGWin: 20})
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodingReference(t, "br", br.Bytes()), plain) {
		t.Fatal("wiring, not the property: large-window brotli fixture")
	}
	// Window descriptor 80 declares 1 MiB, followed by one last raw block.
	zs := []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 80}
	h := uint32(len(plain)<<3 | 1)
	zs = append(zs, byte(h), byte(h>>8), byte(h>>16))
	zs = append(zs, plain...)
	if !bytes.Equal(decodingReference(t, "zstd", zs), plain) {
		t.Fatal("wiring, not the property: large-window zstd fixture")
	}
	for _, tc := range []struct {
		name string
		c    Coding
		b    []byte
	}{{"br", Brotli, br.Bytes()}, {"zstd", Zstd, zs}} {
		t.Run(tc.name, func(t *testing.T) {
			ledger := &decodingLedger{t: t, list: decodingList(tc.c), bound: 1024}
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			got := Decode(ledger.list, tc.b, Options{Bound: 1024, Reserver: ledger})
			runtime.ReadMemStats(&after)
			if got.Outcome == 0 {
				t.Fatal("wiring, not the property: Decode returned no outcome")
			}
			if got.Outcome != DecodedTooLarge || got.Body != nil || got.Charge != 0 || ledger.total() != 0 {
				t.Errorf("large window result=%+v held=%d", got, ledger.total())
			}
			if delta := after.TotalAlloc - before.TotalAlloc; delta > uint64(Cumulative(tc.c, 1024)) {
				t.Errorf("large-window allocation %d exceeds A", delta)
			}
		})
	}
}

type decodingRepeatedByte struct {
	value     byte
	different bool
}

func (w *decodingRepeatedByte) Write(p []byte) (int, error) {
	w.different = w.different || bytes.Count(p, []byte{w.value}) != len(p)
	return len(p), nil
}

func TestBombAllocationAndStageIOStayBounded(t *testing.T) {
	// The complete expansion alone exceeds A; fixture creation and reference
	// decoding happen before the allocation counters surrounding the subject.
	plain := bytes.Repeat([]byte{'a'}, 32<<20)
	for _, tc := range []struct {
		name string
		c    Coding
	}{{"gzip", Gzip}, {"raw", Deflate}, {"br", Brotli}, {"zstd", Zstd}} {
		t.Run(tc.name, func(t *testing.T) {
			bound := 1024
			expansion := len(plain)
			var encoded []byte
			if tc.c == Zstd {
				const block = 32 << 10
				bound = block
				expansion = 256 << 20
				encoded = []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 40}
				for n := 0; n < expansion; n += block {
					h := uint32(block<<3 | 2)
					if n+block == expansion {
						h |= 1
					}
					var raw [4]byte
					binary.LittleEndian.PutUint32(raw[:], h)
					encoded = append(encoded, raw[:3]...)
					encoded = append(encoded, 'a')
				}
				reader, err := zstd.NewReader(bytes.NewReader(encoded), zstd.WithDecoderConcurrency(1))
				if err != nil {
					t.Fatal(err)
				}
				checked := &decodingRepeatedByte{value: 'a'}
				n, err := io.Copy(checked, reader)
				reader.Close()
				if err != nil || n != int64(expansion) || checked.different {
					t.Fatalf("wiring, not the property: RLE reference bytes=%d error=%v different=%t", n, err, checked.different)
				}
			} else {
				encoded = decodingEncode(t, tc.name, plain)
			}
			// A(coding, B) assumes capture admitted at most B encoded bytes.
			bound = max(bound, len(encoded))
			list := decodingList(tc.c)
			allowance := Cumulative(tc.c, bound)
			if int64(expansion) <= allowance {
				t.Fatalf("wiring, not the property: expansion %d does not exceed cumulative allowance %d", expansion, allowance)
			}
			ledger := &decodingLedger{t: t, list: list, bound: bound}
			var observed StageIO
			calls := 0
			opts := Options{Bound: bound, Reserver: ledger, Observe: func(s StageIO) { observed = s; calls++ }}
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			got := Decode(list, encoded, opts)
			runtime.ReadMemStats(&after)
			if calls != 1 {
				t.Fatal("wiring, not the property: bomb did not reach one observed stage")
			}
			if got.Outcome != DecodedTooLarge || got.Body != nil || got.Charge != 0 || ledger.total() != 0 {
				t.Errorf("bomb result=%+v held=%d", got, ledger.total())
			}
			if observed.Input != int64(len(encoded)) || observed.Read > observed.Input || observed.Returned != int64(bound+1) {
				t.Errorf("bomb I/O=%+v, want output %d", observed, bound+1)
			}
			if delta := after.TotalAlloc - before.TotalAlloc; delta > uint64(allowance) {
				t.Errorf("cumulative allocation %d exceeds A=%d", delta, allowance)
			}
			t.Logf("expanded=%d encoded=%d B=%d allocation=%d A=%d peak-charge=%d stage=%+v", expansion, len(encoded), bound, after.TotalAlloc-before.TotalAlloc, allowance, ledger.peak, observed)
		})
	}
}

func TestIdentityUsesNoDecoderOrReservation(t *testing.T) {
	plain := []byte("unchanged captured body")
	refuser := &decodingAdmission{}
	observations := 0
	got := Decode(List{}, plain, Options{Bound: 0, Reserver: refuser, Observe: func(StageIO) { observations++ }})
	if got.Outcome == 0 {
		t.Fatal("wiring, not the property: identity returned no outcome")
	}
	if got.Outcome != Identity || got.Stage != 0 || got.Body != nil || got.Charge != 0 || refuser.calls != 0 || observations != 0 {
		t.Errorf("identity entered decoding or retained data: result=%+v reservations=%d observations=%d", got, refuser.calls, observations)
	}
}

func TestSmallBoundsAdmitMinimumWindows(t *testing.T) {
	for _, tc := range []struct {
		name   string
		coding Coding
	}{{"br", Brotli}, {"zstd", Zstd}} {
		t.Run(tc.name, func(t *testing.T) {
			plain := []byte("tiny")
			encoded := decodingEncode(t, tc.name, plain)
			decodingRun(t, decodingList(tc.coding), encoded, len(plain), Decoded, 0, plain)
		})
	}
}

func TestGzipHeaderIntegrity(t *testing.T) {
	plain := []byte("header-protected content")
	valid := decodingEncode(t, "gzip", plain)
	for _, flag := range []byte{0x20, 0x40, 0x80} {
		t.Run(fmt.Sprintf("reserved-%02x", flag), func(t *testing.T) {
			bad := bytes.Clone(valid)
			bad[3] |= flag
			if bad[3] == valid[3] {
				t.Fatal("wiring, not the property: reserved header bit unchanged")
			}
			decodingRun(t, decodingList(Gzip), bad, 1024, DecodingFailed, 1, nil)
		})
	}
	header := bytes.Clone(valid[:10])
	header[3] |= 2
	crc := crc32.ChecksumIEEE(header)
	withCRC := append(header, byte(crc), byte(crc>>8))
	withCRC = append(withCRC, valid[10:]...)
	if !bytes.Equal(decodingReference(t, "gzip", withCRC), plain) {
		t.Fatal("wiring, not the property: header CRC control is invalid")
	}
	t.Run("valid-crc", func(t *testing.T) { decodingRun(t, decodingList(Gzip), withCRC, 1024, Decoded, 0, plain) })
	t.Run("invalid-crc", func(t *testing.T) {
		bad := bytes.Clone(withCRC)
		bad[10] ^= 1
		decodingRun(t, decodingList(Gzip), bad, 1024, DecodingFailed, 1, nil)
	})
}

func TestDeflatePredicateBoundaryAcceptsRawNeighbours(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cmf, length byte
	}{{"checksum", 0x78, 2}, {"window", 0x88, 28}} {
		t.Run(tc.name, func(t *testing.T) {
			plain := bytes.Repeat([]byte{'Q'}, int(tc.length))
			raw := []byte{tc.cmf, tc.length, 0, ^tc.length, 0xff}
			raw = append(raw, plain...)
			raw = append(raw, 1, 0, 0, 0xff, 0xff)
			if !bytes.Equal(decodingReference(t, "raw", raw), plain) {
				t.Fatal("wiring, not the property: neighbouring raw block invalid")
			}
			if tc.name == "checksum" && (int(tc.cmf)*256+int(tc.length))%31 == 0 {
				t.Fatal("wiring, not the property: checksum predicate still holds")
			}
			if tc.name == "window" && (int(tc.cmf)*256+int(tc.length))%31 != 0 {
				t.Fatal("wiring, not the property: window fixture does not isolate CINFO")
			}
			decodingRun(t, decodingList(Deflate), raw, 1024, Decoded, 0, plain)
		})
	}
}

func decodingZstdRawFrame(window byte, plain []byte) []byte {
	frame := []byte{0x28, 0xb5, 0x2f, 0xfd, 0, window}
	h := uint32(len(plain)<<3 | 1)
	frame = append(frame, byte(h), byte(h>>8), byte(h>>16))
	return append(frame, plain...)
}

func TestZstdEarlierBoundWinsOverLaterFrameErrors(t *testing.T) {
	// Two 1 KiB RLE blocks exceed B without declaring an oversized window or
	// content size. Every suffix is beyond the first decisive output bound.
	first := []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0}
	for i := 0; i < 2; i++ {
		h := uint32(1024<<3 | 2 | i)
		first = append(first, byte(h), byte(h>>8), byte(h>>16), 'a')
	}
	if got := decodingReference(t, "zstd", first); !bytes.Equal(got, bytes.Repeat([]byte{'a'}, 2048)) {
		t.Fatal("wiring, not the property: first frame is not a valid overflowing output")
	}
	for _, tc := range []struct {
		name   string
		suffix []byte
	}{
		{"later-window", decodingZstdRawFrame(8, []byte("small"))},
		{"truncated-header", []byte{0x28, 0xb5, 0x2f, 0xfd, 0}},
		{"reserved-block", []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0, 7, 0, 0}},
		{"trailing-byte", []byte{0x7f}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := append(bytes.Clone(first), tc.suffix...)
			if len(encoded) <= len(first) {
				t.Fatal("wiring, not the property: later error was not appended")
			}
			decodingRun(t, decodingList(Zstd), encoded, 1024, DecodedTooLarge, 1, nil)
		})
	}
}
