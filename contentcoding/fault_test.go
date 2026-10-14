package contentcoding

import (
	"bytes"
	"io"
	"slices"
	"testing"
)

// tripwire is a panic value that records any use of its methods. Formatting
// it, as an error or as a string, calls one of them.
type tripwire struct{ used *bool }

func (w tripwire) Error() string  { *w.used = true; return "tripwire" }
func (w tripwire) String() string { *w.used = true; return "tripwire" }

// faulting passes its source through until left bytes have gone, then panics
// with value inside whichever library call is reading it.
type faulting struct {
	src   *input
	left  int
	value any
	fired bool
}

func (f *faulting) Read(p []byte) (int, error) {
	if f.left <= 0 {
		f.fired = true
		panic(f.value)
	}
	n, err := f.src.Read(p[:min(len(p), f.left)])
	f.left -= n
	return n, err
}

func (f *faulting) ReadByte() (byte, error) {
	if f.left <= 0 {
		f.fired = true
		panic(f.value)
	}
	c, err := f.src.ReadByte()
	if err == nil {
		f.left--
	}
	return c, err
}

// faultAfter decodes encoded as c with a ledger, its library's input panicking
// after left bytes, and returns the result, the stage's I/O, the ledger and
// the feed.
func faultAfter(t *testing.T, c Coding, encoded []byte, left int, value any) (Result, StageIO, *ledger, *faulting) {
	t.Helper()
	led := newLedger(t)
	var stages []StageIO
	var feed *faulting
	w := within{
		budget: workBudget{BrotliWorkBase, BrotliWorkPerByte, brotliWorkCeiling},
		feed: func(r io.Reader) io.Reader {
			feed = &faulting{src: r.(*input), left: left, value: value}
			return feed
		},
	}
	r := decodeWithin(list(t, c.String()), encoded, Options{Bound: 1 << 20, Reserver: led, Observe: func(s StageIO) { stages = append(stages, s) }}, w)
	led.settled(r, 1)
	if feed == nil || !feed.fired || len(stages) != 1 {
		t.Fatalf("wiring, not the property: %s: the feed was made %v, fired %v, %d stages observed", c, feed != nil, feed != nil && feed.fired, len(stages))
	}
	return r, stages[0], led, feed
}

var allCodings = []Coding{Gzip, Deflate, Brotli, Zstd}

// consumed is how many bytes of encoded the library reads in a whole decode
// as c.
func consumed(t *testing.T, c Coding, encoded []byte) int {
	t.Helper()
	var feed *faulting
	w := within{
		budget: workBudget{BrotliWorkBase, BrotliWorkPerByte, brotliWorkCeiling},
		feed: func(r io.Reader) io.Reader {
			feed = &faulting{src: r.(*input), left: len(encoded) + 1}
			return feed
		},
	}
	r := decodeWithin(list(t, c.String()), encoded, Options{Bound: 1 << 20}, w)
	if r.Outcome != Decoded || feed == nil {
		t.Fatalf("wiring, not the property: %s decoded as %d through the feed", c, r.Outcome)
	}
	return len(encoded) + 1 - feed.left
}

func TestADecoderLibraryPanicIsAFault(t *testing.T) {
	// Several blocks of every coding, so that output has been returned
	// before the library's last read: a zstd block is returned whole, and
	// flate returns output a window at a time.
	body := text(300<<10, 6)
	for _, c := range allCodings {
		encoded := encode(c, body)
		for _, at := range []struct {
			name string
			left int
		}{{"at the first read", 0}, {"at the library's last read, after output", consumed(t, c, encoded) - 1}} {
			used := false
			r, stage, led, _ := faultAfter(t, c, encoded, at.left, tripwire{&used})
			// The ledger has checked that nothing is held and nothing was
			// released twice; late, there was output reserved and returned
			// to discard.
			reserved := slices.ContainsFunc(led.asked, func(ch Charge) bool { return ch.Kind == OutputCharge })
			if at.left > 0 && (stage.Returned == 0 || !reserved) {
				t.Fatalf("wiring, not the property: %s faulted with %d bytes returned and output reserved %v", c, stage.Returned, reserved)
			}
			if r.Outcome != DecodingFailed || !r.Fault || r.Outcome.Reason() != ReasonDecodingFailed {
				t.Fatalf("%s, %s: outcome %d, fault %v, reason %q", c, at.name, r.Outcome, r.Fault, r.Outcome.Reason())
			}
			if used {
				t.Fatalf("%s, %s: the panic's value was formatted", c, at.name)
			}
		}
	}
}

func TestAPanicOutsideTheLibraryIsNotContained(t *testing.T) {
	type sentinel struct{}
	body := text(64<<10, 7)
	for _, c := range allCodings {
		encoded := encode(c, body)
		for _, where := range []string{"the Reserver", "the Observe callback"} {
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				led := newLedger(t)
				options := Options{Bound: 1 << 20, Reserver: led}
				if where == "the Reserver" {
					led.refuse = func(ch Charge) bool {
						if ch.Kind == OutputCharge {
							panic(sentinel{})
						}
						return false
					}
				} else {
					options.Observe = func(StageIO) { panic(sentinel{}) }
				}
				r := Decode(list(t, c.String()), encoded, options)
				t.Errorf("%s: a panic in %s was contained as outcome %d, fault %v", c, where, r.Outcome, r.Fault)
			}()
			if _, ok := recovered.(sentinel); !ok {
				t.Fatalf("%s: a panic in %s reached the caller as %v", c, where, recovered)
			}
		}
	}
}

func TestDecodingContinuesAfterAFault(t *testing.T) {
	body := text(64<<10, 8)
	for _, c := range allCodings {
		encoded := encode(c, body)
		for i := range 3 {
			used := false
			faultAfter(t, c, encoded, len(encoded)/(2+i), tripwire{&used})
			r, _ := decodeChecked(t, list(t, c.String()), encoded, 1<<20)
			if r.Outcome != Decoded || r.Fault || !bytes.Equal(r.Body, body) {
				t.Fatalf("%s, after fault %d: outcome %d, fault %v, %d bytes of %d", c, i, r.Outcome, r.Fault, len(r.Body), len(body))
			}
		}
	}
}

func TestOrdinaryOutcomesAreNoFault(t *testing.T) {
	body := text(64<<10, 9)
	for _, c := range allCodings {
		encoded := encode(c, body)
		corrupt := bytes.Clone(encoded)
		for i := len(corrupt) / 3; i < len(corrupt)/3+64; i++ {
			corrupt[i] ^= 0xa5
		}
		for _, d := range []struct {
			name    string
			encoded []byte
			bound   int
			want    Outcome
		}{
			{"decoded", encoded, 1 << 20, Decoded},
			{"too large", encoded, 65535, DecodedTooLarge},
			{"corrupt", corrupt, 1 << 20, DecodingFailed},
		} {
			r, _ := decodeChecked(t, list(t, c.String()), d.encoded, d.bound)
			if r.Outcome != d.want || r.Fault {
				t.Fatalf("%s, %s: outcome %d, fault %v, want %d without a fault", c, d.name, r.Outcome, r.Fault, d.want)
			}
		}
	}
}

// injecting decodes encoded as c with a ledger it checks, calling at with each
// guarded operation and how many of that operation have run, and returns the
// result and the operations, in order.
func injecting(t *testing.T, c Coding, encoded []byte, at func(op operation, n int)) (Result, []operation) {
	t.Helper()
	led := newLedger(t)
	var ops []operation
	counts := map[operation]int{}
	w := within{
		budget: workBudget{BrotliWorkBase, BrotliWorkPerByte, brotliWorkCeiling},
		inject: func(got Coding, op operation) {
			if got != c {
				t.Errorf("an operation of %s reported as %s", c, got)
			}
			ops = append(ops, op)
			counts[op]++
			if at != nil {
				at(op, counts[op])
			}
		},
	}
	r := decodeWithin(list(t, c.String()), encoded, Options{Bound: 1 << 20, Reserver: led}, w)
	led.settled(r, 1)
	return r, ops
}

// guardedCases are a body in each coding, gzip in two members so that its
// decoder is reset once, and the operations the guard runs for each.
func guardedCases() []struct {
	coding  Coding
	body    []byte
	encoded []byte
	closes  bool
} {
	first, second := text(40<<10, 10), text(30<<10, 11)
	body := append(bytes.Clone(first), second...)
	return []struct {
		coding  Coding
		body    []byte
		encoded []byte
		closes  bool
	}{
		{Gzip, body, append(gzipOf(first), gzipOf(second)...), true},
		{Deflate, body, encode(Deflate, body), true},
		{Brotli, body, encode(Brotli, body), false},
		{Zstd, body, encode(Zstd, body), true},
	}
}

func TestTheGuardRunsEveryLibraryOperation(t *testing.T) {
	for _, c := range guardedCases() {
		r, ops := injecting(t, c.coding, c.encoded, nil)
		expect(t, r, Decoded, c.body)
		count := func(op operation) int {
			n := 0
			for _, o := range ops {
				if o == op {
					n++
				}
			}
			return n
		}
		resets := 0
		if c.coding == Gzip {
			resets = 1
		}
		closes := 0
		if c.closes {
			closes = 1
		}
		if len(ops) == 0 || ops[0] != operationMake || count(operationMake) != 1 || count(operationReset) != resets ||
			count(operationRead) == 0 || count(operationClose) != closes || (c.closes && ops[len(ops)-1] != operationClose) {
			t.Fatalf("%s: the guard ran %v", c.coding, ops)
		}
	}
}

func TestAPanicInEveryGuardedOperationIsAFault(t *testing.T) {
	for _, c := range guardedCases() {
		targets := []struct {
			op operation
			n  int
		}{{operationMake, 1}, {operationRead, 1}, {operationRead, 3}}
		if c.coding == Gzip {
			targets = append(targets, struct {
				op operation
				n  int
			}{operationReset, 1})
		}
		if c.closes {
			targets = append(targets, struct {
				op operation
				n  int
			}{operationClose, 1})
		}
		for _, target := range targets {
			used, fired := false, false
			r, ops := injecting(t, c.coding, c.encoded, func(op operation, n int) {
				if op == target.op && n == target.n {
					fired = true
					panic(tripwire{&used})
				}
			})
			if !fired {
				t.Fatalf("wiring, not the property: %s never reached operation %d number %d: %v", c.coding, target.op, target.n, ops)
			}
			if r.Outcome != DecodingFailed || !r.Fault || used {
				t.Fatalf("%s, a panic in operation %d number %d: outcome %d, fault %v, value formatted %v", c.coding, target.op, target.n, r.Outcome, r.Fault, used)
			}
			if target.op != operationClose && slices.Contains(ops, operationClose) {
				t.Fatalf("%s: the faulted decoder was closed: %v", c.coding, ops)
			}
		}
	}
}
