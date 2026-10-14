package contentcoding

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"io"
	"math/rand"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// ledger is a Reserver that records every charge, can refuse chosen ones, and
// fails the test on a release it never granted.
type ledger struct {
	t      *testing.T
	refuse func(Charge) bool
	held   map[[2]int]int64
	total  int64
	peak   int64
	asked  []Charge
	events []event
}

// event is one granted reservation, or one release.
type event struct {
	Charge
	reserved bool
}

func newLedger(t *testing.T) *ledger { return &ledger{t: t, held: map[[2]int]int64{}} }

func (l *ledger) Reserve(c Charge) bool {
	l.asked = append(l.asked, c)
	if c.Bytes <= 0 {
		l.t.Errorf("a charge of %d bytes was asked for: %+v", c.Bytes, c)
	}
	if l.refuse != nil && l.refuse(c) {
		return false
	}
	l.held[[2]int{int(c.Kind), c.Stage}] += c.Bytes
	l.total += c.Bytes
	l.peak = max(l.peak, l.total)
	l.events = append(l.events, event{c, true})
	return true
}

func (l *ledger) Release(c Charge) {
	key := [2]int{int(c.Kind), c.Stage}
	if c.Bytes <= 0 || l.held[key] < c.Bytes {
		l.t.Errorf("released %+v holding %d", c, l.held[key])
	}
	l.held[key] -= c.Bytes
	l.total -= c.Bytes
	l.events = append(l.events, event{c, false})
}

// settled asserts that what the ledger holds is exactly what the result
// passed to the caller.
func (l *ledger) settled(r Result, stages int) {
	l.t.Helper()
	if r.Outcome == Decoded {
		if r.Charge != int64(cap(r.Body)) {
			l.t.Errorf("charge %d for a body of capacity %d", r.Charge, cap(r.Body))
		}
		if l.total != r.Charge || l.held[[2]int{int(OutputCharge), stages}] != r.Charge {
			l.t.Errorf("held %d (%v) beside a passed charge of %d", l.total, l.held, r.Charge)
		}
		return
	}
	if r.Body != nil || r.Charge != 0 {
		l.t.Errorf("outcome %d returned a body of %d and a charge of %d", r.Outcome, len(r.Body), r.Charge)
	}
	if l.total != 0 {
		l.t.Errorf("outcome %d left %d held: %v", r.Outcome, l.total, l.held)
	}
}

func list(t *testing.T, values ...string) List {
	t.Helper()
	l, v := ParseList(values)
	if v != Supported {
		t.Fatalf("ParseList(%q) = %d", values, v)
	}
	return l
}

// decodeChecked runs one Decode with a fresh ledger, checks what it holds afterwards
// and returns both.
func decodeChecked(t *testing.T, l List, encoded []byte, bound int) (Result, *ledger) {
	t.Helper()
	led := newLedger(t)
	original := bytes.Clone(encoded)
	r := Decode(l, encoded, Options{Bound: bound, Reserver: led})
	led.settled(r, l.Len())
	if !bytes.Equal(original, encoded) {
		t.Error("Decode wrote to its input")
	}
	if l.Len() == 1 && led.peak > Charges(l.At(0), bound) {
		t.Errorf("held %d at once, above Charges %d", led.peak, Charges(l.At(0), bound))
	}
	return r, led
}

func text(n int, seed int64) []byte {
	r := rand.New(rand.NewSource(seed))
	words := []string{"order", "id", "user", "true", "null", "value", "name", `"key":`, "{", "}", ",", " "}
	var b bytes.Buffer
	for b.Len() < n {
		b.WriteString(words[r.Intn(len(words))])
	}
	return b.Bytes()[:n]
}

// written writes p through w and closes it. A writer into memory returns no
// error, so one is a broken fixture and panics.
func written(w io.WriteCloser, p []byte) {
	if _, err := w.Write(p); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
}

func gzipOf(p []byte) []byte {
	var b bytes.Buffer
	written(gzip.NewWriter(&b), p)
	return b.Bytes()
}

func zlibOf(p []byte) []byte {
	var b bytes.Buffer
	written(zlib.NewWriter(&b), p)
	return b.Bytes()
}

func rawOf(p []byte) []byte {
	var b bytes.Buffer
	w, err := flate.NewWriter(&b, flate.DefaultCompression)
	if err != nil {
		panic(err)
	}
	written(w, p)
	return b.Bytes()
}

func brotliOf(p []byte, lgwin int) []byte {
	var b bytes.Buffer
	written(brotli.NewWriterOptions(&b, brotli.WriterOptions{Quality: 5, LGWin: lgwin}), p)
	return b.Bytes()
}

// zstdOf writes a stream of one frame with the window given, its content size
// left out, and a checksum.
func zstdOf(p []byte, window int) []byte {
	e, err := zstd.NewWriter(nil, zstd.WithWindowSize(window), zstd.WithEncoderConcurrency(1), zstd.WithEncoderCRC(true))
	if err != nil {
		panic(err)
	}
	var b bytes.Buffer
	e.Reset(&b)
	written(e, p)
	return b.Bytes()
}

func encode(c Coding, p []byte) []byte {
	switch c {
	case Gzip:
		return gzipOf(p)
	case Deflate:
		return zlibOf(p)
	case Brotli:
		return brotliOf(p, 16)
	case Zstd:
		return zstdOf(p, 1<<16)
	}
	panic("coding")
}

func expect(t *testing.T, r Result, outcome Outcome, body []byte) {
	t.Helper()
	if r.Outcome != outcome {
		t.Fatalf("outcome %d (stage %d), want %d", r.Outcome, r.Stage, outcome)
	}
	if outcome == Decoded && !bytes.Equal(r.Body, body) {
		t.Fatalf("decoded %d bytes, not the %d encoded", len(r.Body), len(body))
	}
}

func TestEachCodingRoundTrips(t *testing.T) {
	body := text(200<<10, 1)
	for _, c := range []struct {
		name, header string
		encoded      []byte
	}{
		{"gzip", "gzip", gzipOf(body)},
		{"x-gzip", "x-gzip", gzipOf(body)},
		{"deflate as zlib", "deflate", zlibOf(body)},
		{"deflate as raw", "deflate", rawOf(body)},
		{"br", "br", brotliOf(body, 18)},
		{"zstd", "zstd", zstdOf(body, 1<<17)},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, _ := decodeChecked(t, list(t, c.header), c.encoded, 8<<20)
			expect(t, r, Decoded, body)
		})
	}
}

func TestIdentityDecodesNothing(t *testing.T) {
	r, led := decodeChecked(t, List{}, []byte("plain"), 8<<20)
	if r.Outcome != Identity || len(led.asked) != 0 {
		t.Fatalf("outcome %d after %d reservations", r.Outcome, len(led.asked))
	}
}

func TestEmptyBodyIsNotAStream(t *testing.T) {
	for _, c := range []string{"gzip", "deflate", "br", "zstd"} {
		r, _ := decodeChecked(t, list(t, c), nil, 8<<20)
		expect(t, r, DecodingFailed, nil)
	}
}

func TestEmptyContentRoundTrips(t *testing.T) {
	for _, c := range []Coding{Gzip, Deflate, Brotli, Zstd} {
		r, _ := decodeChecked(t, list(t, c.String()), encode(c, nil), 8<<20)
		expect(t, r, Decoded, nil)
	}
}

func TestConcatenatedMembersAndFrames(t *testing.T) {
	a, b, c := text(3000, 3), text(1, 4), text(70000, 5)
	want := append(append(bytes.Clone(a), b...), c...)
	gz := append(append(gzipOf(a), gzipOf(b)...), gzipOf(c)...)
	r, _ := decodeChecked(t, list(t, "gzip"), gz, 8<<20)
	expect(t, r, Decoded, want)
	zs := append(append(zstdOf(a, 1<<16), zstdOf(b, 1<<16)...), zstdOf(c, 1<<17)...)
	r, _ = decodeChecked(t, list(t, "zstd"), zs, 8<<20)
	expect(t, r, Decoded, want)
	// A skippable frame between them carries nothing.
	skippable := []byte{0x50, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 'x', 'y', 'z'}
	zs = append(append(zstdOf(a, 1<<16), skippable...), zstdOf(c, 1<<17)...)
	r, _ = decodeChecked(t, list(t, "zstd"), zs, 8<<20)
	expect(t, r, Decoded, append(bytes.Clone(a), c...))
}

func TestGzipHeaderFieldsAreSkipped(t *testing.T) {
	body := text(1000, 6)
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Extra = bytes.Repeat([]byte{7}, 5000)
	w.Name = "name.json"
	w.Comment = "a comment"
	written(w, body)
	r, _ := decodeChecked(t, list(t, "gzip"), b.Bytes(), 8<<20)
	expect(t, r, Decoded, body)
}

// gzipWithHeaderCRC is a member whose header carries FHCRC.
func gzipWithHeaderCRC(body []byte, corrupt bool) []byte {
	member := gzipOf(body)
	header := append([]byte{0x1f, 0x8b, 8, 0x02}, member[4:10]...) // FHCRC
	sum := crc32.ChecksumIEEE(header)
	if corrupt {
		sum++
	}
	header = binary.LittleEndian.AppendUint16(header, uint16(sum))
	return append(header, member[10:]...)
}

func TestGzipHeaderChecks(t *testing.T) {
	body := text(500, 7)
	r, _ := decodeChecked(t, list(t, "gzip"), gzipWithHeaderCRC(body, false), 8<<20)
	expect(t, r, Decoded, body)
	r, _ = decodeChecked(t, list(t, "gzip"), gzipWithHeaderCRC(body, true), 8<<20)
	expect(t, r, DecodingFailed, nil)
	reserved := gzipOf(body)
	reserved[3] |= 0x20
	r, _ = decodeChecked(t, list(t, "gzip"), reserved, 8<<20)
	expect(t, r, DecodingFailed, nil)
	method := gzipOf(body)
	method[2] = 7
	r, _ = decodeChecked(t, list(t, "gzip"), method, 8<<20)
	expect(t, r, DecodingFailed, nil)
}

func TestLateFailuresLeaveNothing(t *testing.T) {
	body := text(100<<10, 8)
	flip := func(b []byte, i int) []byte {
		b = bytes.Clone(b)
		b[i] ^= 0x55
		return b
	}
	gz := gzipOf(body)
	zl := zlibOf(body)
	zs := zstdOf(body, 1<<17)
	br := brotliOf(body, 18)
	for _, c := range []struct {
		name, header string
		encoded      []byte
	}{
		{"gzip CRC-32", "gzip", flip(gz, len(gz)-8)},
		{"gzip length", "gzip", flip(gz, len(gz)-1)},
		{"gzip trailer truncated", "gzip", gz[:len(gz)-3]},
		{"gzip trailer missing", "gzip", gz[:len(gz)-8]},
		{"zlib Adler-32", "deflate", flip(zl, len(zl)-1)},
		{"zlib trailer truncated", "deflate", zl[:len(zl)-2]},
		{"raw deflate truncated", "deflate", rawOf(body)[:100]},
		{"zstd checksum", "zstd", flip(zs, len(zs)-1)},
		{"zstd truncated", "zstd", zs[:len(zs)-5]},
		{"br truncated", "br", br[:len(br)-1]},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, _ := decodeChecked(t, list(t, c.header), c.encoded, 8<<20)
			expect(t, r, DecodingFailed, nil)
		})
	}
}

func TestABadLaterMemberFailsTheBody(t *testing.T) {
	first, second := gzipOf(text(2000, 9)), gzipOf(text(2000, 10))
	second[len(second)-6] ^= 1
	r, _ := decodeChecked(t, list(t, "gzip"), append(first, second...), 8<<20)
	expect(t, r, DecodingFailed, nil)
	z1, z2 := zstdOf(text(2000, 9), 1<<16), zstdOf(text(2000, 10), 1<<16)
	z2[len(z2)-1] ^= 1
	r, _ = decodeChecked(t, list(t, "zstd"), append(z1, z2...), 8<<20)
	expect(t, r, DecodingFailed, nil)
}

func TestTrailingBytesFail(t *testing.T) {
	body := text(4000, 12)
	for _, c := range []Coding{Gzip, Deflate, Brotli, Zstd} {
		for _, extra := range [][]byte{{0}, {1, 2, 3}, encode(c, body)[:4]} {
			t.Run(fmt.Sprintf("%s %x", c, extra), func(t *testing.T) {
				encoded := append(encode(c, body), extra...)
				r, _ := decodeChecked(t, list(t, c.String()), encoded, 8<<20)
				expect(t, r, DecodingFailed, nil)
			})
		}
	}
	raw := append(rawOf(body), 0)
	r, _ := decodeChecked(t, list(t, "deflate"), raw, 8<<20)
	expect(t, r, DecodingFailed, nil)
}

// zlibAround wraps a raw deflate stream of body in the two header bytes given
// and body's Adler-32.
func zlibAround(cmf, flg byte, body []byte) []byte {
	stream := append([]byte{cmf, flg}, rawOf(body)...)
	return binary.BigEndian.AppendUint32(stream, adler32.Checksum(body))
}

func TestDeflateChoosesZlibByItsHeaderAlone(t *testing.T) {
	body := text(3000, 13)
	z := zlibOf(body)
	r, _ := decodeChecked(t, list(t, "deflate"), z, 8<<20)
	expect(t, r, Decoded, body)
	// Headers either side of each condition, around the same stream: a
	// passing one is read as zlib and decodes, a failing one is read as raw
	// deflate, which these bytes are not.
	for _, c := range []struct {
		cmf, flg byte
		zlib     bool
	}{
		{0x78, 0x9c, true},  // the default header
		{0x78, 0x01, true},  // 0x7801 = 31 * 991
		{0x78, 0xda, true},  // 0x78da = 31 * 998
		{0x08, 0x1d, true},  // CINFO 0: 0x081d = 31 * 67
		{0x78, 0x9d, false}, // check bits one over
		{0x78, 0x9b, false}, // check bits one under
		{0x79, 0x18, false}, // CM 9: 0x7918 = 31 * 1000
		{0x77, 0x09, false}, // CM 7: 0x7709 = 31 * 983
		{0x88, 0x1c, false}, // CINFO 8: 0x881c = 31 * 1124
	} {
		r, _ := decodeChecked(t, list(t, "deflate"), zlibAround(c.cmf, c.flg, body), 8<<20)
		if decoded := r.Outcome == Decoded && bytes.Equal(r.Body, body); decoded != c.zlib {
			t.Fatalf("header %#x %#x: outcome %d, read as zlib %v", c.cmf, c.flg, r.Outcome, decoded)
		}
	}
	// Every CINFO with valid check bits: up to 7 is zlib.
	for cinfo := byte(0); cinfo <= 15; cinfo++ {
		cmf := cinfo<<4 | 8
		flg := byte(31 - int(cmf)*256%31)
		r, _ := decodeChecked(t, list(t, "deflate"), zlibAround(cmf, flg, body), 8<<20)
		if decoded := r.Outcome == Decoded && bytes.Equal(r.Body, body); decoded != (cinfo <= 7) {
			t.Fatalf("CINFO %d: outcome %d, read as zlib %v", cinfo, r.Outcome, decoded)
		}
	}
	// A raw stream that happens to start with a passing header follows the
	// zlib branch and is refused rather than retried as raw.
	forged := append([]byte{0x78, 0x01}, rawOf(body)...)
	r, _ = decodeChecked(t, list(t, "deflate"), forged, 8<<20)
	expect(t, r, DecodingFailed, nil)
	// One byte is too short for a header, and is raw deflate.
	r, _ = decodeChecked(t, list(t, "deflate"), []byte{0x78}, 8<<20)
	expect(t, r, DecodingFailed, nil)
}

func TestPresetDictionaryFails(t *testing.T) {
	var b bytes.Buffer
	w, err := zlib.NewWriterLevelDict(&b, zlib.DefaultCompression, []byte("a dictionary"))
	if err != nil {
		t.Fatal(err)
	}
	written(w, text(1000, 14))
	encoded := b.Bytes()
	if encoded[1]&0x20 == 0 { // FDICT
		t.Fatal("wiring, not the property: the stream asks for no dictionary")
	}
	r, _ := decodeChecked(t, list(t, "deflate"), encoded, 8<<20)
	expect(t, r, DecodingFailed, nil)
}

func TestZstdDictionaryFrameFails(t *testing.T) {
	body := text(1000, 15)
	encoded := zstdOf(body, 1<<16)
	r, _ := decodeChecked(t, list(t, "zstd"), encoded, 8<<20)
	expect(t, r, Decoded, body)
	// Name dictionary 7 in the frame header: Dictionary_ID_flag 1, one byte,
	// after the window descriptor.
	if encoded[4]&3 != 0 || encoded[4]&(1<<5) != 0 {
		t.Fatal("wiring, not the property: the frame names a dictionary already, or has no window descriptor")
	}
	named := append(bytes.Clone(encoded[:6]), 7)
	named[4] |= 1
	named = append(named, encoded[6:]...)
	r, _ = decodeChecked(t, list(t, "zstd"), named, 8<<20)
	expect(t, r, DecodingFailed, nil)
}

func TestBrotliLargeWindowMarkerFails(t *testing.T) {
	// WBITS bits 1, 000, 001: the large-window marker.
	r, _ := decodeChecked(t, list(t, "br"), []byte{0x11, 0x00, 0x00}, 8<<20)
	expect(t, r, DecodingFailed, nil)
	if r.Stage != 1 {
		t.Fatalf("stage %d", r.Stage)
	}
}

// windowBits reads WBITS from a brotli stream's first byte (RFC 7932 section
// 9.1).
func windowBits(first byte) int {
	switch {
	case first&1 == 0:
		return 16
	case first>>1&7 != 0:
		return 17 + int(first>>1&7)
	case first>>4&7 == 0:
		return 17
	}
	return 8 + int(first>>4&7)
}

func TestBrotliWindowIsDecidedFromTheHeader(t *testing.T) {
	body := text(100, 16)
	for lgwin := 10; lgwin <= 24; lgwin++ {
		encoded := brotliOf(body, lgwin)
		if windowBits(encoded[0]) != lgwin {
			t.Fatalf("wiring, not the property: lgwin %d written as WBITS %d", lgwin, windowBits(encoded[0]))
		}
		window := 1<<lgwin - 16
		r, _ := decodeChecked(t, list(t, "br"), encoded, window)
		expect(t, r, Decoded, body)
		r, led := decodeChecked(t, list(t, "br"), encoded, window-1)
		if lgwin == 10 {
			// The smallest window is admitted under any bound.
			expect(t, r, Decoded, body)
			continue
		}
		expect(t, r, DecodedTooLarge, nil)
		if len(led.asked) != 0 {
			t.Fatalf("lgwin %d: the header check reserved %v", lgwin, led.asked)
		}
	}
}

func TestTheSmallestZstdWindowIsAdmittedUnderAnyBound(t *testing.T) {
	body := text(500, 17)
	encoded := zstdOf(body, 1<<10)
	if frameWindow(t, encoded) != 1<<10 {
		t.Fatalf("wiring, not the property: the frame declares %d", frameWindow(t, encoded))
	}
	r, _ := decodeChecked(t, list(t, "zstd"), encoded, len(body))
	expect(t, r, Decoded, body)
	encoded = withWindow(encoded, 1, 0)
	if frameWindow(t, encoded) != 1<<11 {
		t.Fatalf("wiring, not the property: the frame declares %d", frameWindow(t, encoded))
	}
	r, _ = decodeChecked(t, list(t, "zstd"), encoded, len(body))
	expect(t, r, DecodedTooLarge, nil)
}
