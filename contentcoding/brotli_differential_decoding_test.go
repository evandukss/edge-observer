package contentcoding

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	original "github.com/andybalholm/brotli"
	patched "github.com/evandukss/edge-observer/internal/brotli"
)

// The internal brotli decoder is the original's with its context-map storage
// kept for the Reader's life. These tests feed both the same streams and
// require the same plaintext and the same outcome: whole, truncated at every
// byte, with the input failing, corrupted, read in pieces of every size, and
// reused through Reset after every kind of end.
type differentialResetReader interface {
	io.Reader
	Reset(io.Reader) error
}

var errDifferentialInput = errors.New("fixture input failure")

type differentialInput struct {
	b     []byte
	chunk int
	fail  bool
}

func (r *differentialInput) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		if r.fail {
			return 0, errDifferentialInput
		}
		return 0, io.EOF
	}
	n := copy(p, r.b[:min(len(r.b), r.chunk)])
	r.b = r.b[n:]
	return n, nil
}

func differentialCompare(t *testing.T, left, right io.Reader) {
	t.Helper()
	want, wantErr := io.ReadAll(left)
	got, gotErr := io.ReadAll(right)
	if !bytes.Equal(got, want) || (gotErr == nil) != (wantErr == nil) {
		t.Fatalf("patched plaintext/outcome differs: got %x/%v want %x/%v", got, gotErr, want, wantErr)
	}
	if errors.Is(gotErr, errDifferentialInput) != errors.Is(wantErr, errDifferentialInput) {
		t.Errorf("input error propagation differs: got %v want %v", gotErr, wantErr)
	}
}

// differentialFixture is one authored stream and its plaintext.
type differentialFixture struct {
	name           string
	encoded, plain []byte
}

// differentialFixtures are the eight authored streams: literal and distance
// maps of 1 and 256 block types, one and two trees, map contents 0 and 1, and
// sequences of metablocks whose map sizes shrink, stay and grow while their
// contents change.
func differentialFixtures(t *testing.T) []differentialFixture {
	t.Helper()
	block := func(types, trees int, value byte) brotliBlock {
		return brotliBlock{types: types, trees: trees, literal: value, distance: value, length: 1}
	}
	var alternating []brotliBlock
	for i := 0; i < 4; i++ {
		alternating = append(alternating, block(256, 2, 1), block(1, 1, 0), block(256, 2, 0), block(1, 2, 1))
	}
	cases := []struct {
		name   string
		blocks []brotliBlock
	}{
		{"one-small", []brotliBlock{block(1, 1, 0)}},
		{"one-large", []brotliBlock{block(256, 1, 0)}},
		{"two-zero", []brotliBlock{block(256, 2, 0)}},
		{"two-one", []brotliBlock{block(256, 2, 1)}},
		{"shrink-clear", []brotliBlock{block(256, 2, 1), block(1, 1, 0)}},
		{"same-size-clear", []brotliBlock{block(256, 2, 1), block(256, 1, 0)}},
		{"grow-change", []brotliBlock{block(1, 2, 1), block(256, 2, 0), block(256, 2, 1)}},
		{"alternating", alternating},
	}
	var out []differentialFixture
	for _, c := range cases {
		encoded, plain := brotliStream(c.blocks...)
		brotliCheckAuthored(t, c.name, encoded)
		out = append(out, differentialFixture{name: c.name, encoded: encoded, plain: plain})
	}
	return out
}

// differentialMatrix compares the two decoders over encoded fed 1, 7 and all
// bytes at a time: whole, truncated at every byte, with the input failing at
// four points, and with one byte corrupted at three.
func differentialMatrix(t *testing.T, encoded []byte) {
	t.Helper()
	for _, chunk := range []int{1, 7, len(encoded)} {
		t.Run(fmt.Sprintf("fragment-%d", chunk), func(t *testing.T) {
			compare := func(t *testing.T, b []byte, fail bool) {
				differentialCompare(t,
					original.NewReader(&differentialInput{b: bytes.Clone(b), chunk: chunk, fail: fail}),
					patched.NewReader(&differentialInput{b: bytes.Clone(b), chunk: chunk, fail: fail}))
			}
			compare(t, encoded, false)
			// Every input boundary exercises suspension within header,
			// map and tree reads as well as incomplete trailers.
			for end := 0; end < len(encoded); end++ {
				t.Run(fmt.Sprintf("truncate-%d", end), func(t *testing.T) { compare(t, encoded[:end], false) })
			}
			for _, end := range []int{0, 1, len(encoded) / 2, len(encoded) - 1} {
				t.Run(fmt.Sprintf("input-error-%d", end), func(t *testing.T) { compare(t, encoded[:end], true) })
			}
			for _, at := range []int{0, len(encoded) / 2, len(encoded) - 1} {
				bad := bytes.Clone(encoded)
				bad[at] ^= 0xff
				t.Run(fmt.Sprintf("corrupt-%d", at), func(t *testing.T) { compare(t, bad, false) })
			}
		})
	}
}

func TestBrotliContextMapsAgreeWithOriginal(t *testing.T) {
	fixtures := differentialFixtures(t)
	if len(fixtures) != 8 {
		t.Fatalf("fixture corpus has %d streams, want 8", len(fixtures))
	}
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			// Qualification is against authored plaintext, before using the
			// original's result as the differential oracle for malformed variants.
			qualified, err := io.ReadAll(original.NewReader(bytes.NewReader(f.encoded)))
			if err != nil || !bytes.Equal(qualified, f.plain) {
				t.Fatalf("fixture invalid: %x/%v want %x", qualified, err, f.plain)
			}
			differentialMatrix(t, f.encoded)
		})
	}
}

func TestBrotliResetAgreesWithOriginal(t *testing.T) {
	fixtures := differentialFixtures(t)
	read := func(name string) []byte {
		for _, f := range fixtures {
			if f.name == name {
				return f.encoded
			}
		}
		t.Fatalf("wiring, not the property: no fixture is named %s", name)
		return nil
	}
	large, small := read("alternating"), read("one-small")
	for _, state := range []string{"complete", "partial", "truncated", "input-error", "corrupt"} {
		t.Run(state, func(t *testing.T) {
			first := bytes.Clone(large)
			if state == "truncated" || state == "input-error" {
				first = first[:len(first)/2]
			}
			if state == "corrupt" {
				first[0] ^= 0xff
			}
			left := original.NewReader(&differentialInput{b: bytes.Clone(first), chunk: 1, fail: state == "input-error"})
			right := patched.NewReader(&differentialInput{b: bytes.Clone(first), chunk: 1, fail: state == "input-error"})
			if state == "partial" {
				differentialCompare(t, io.LimitReader(left, 7), io.LimitReader(right, 7))
			} else {
				differentialCompare(t, left, right)
			}
			for _, next := range [][]byte{small, large, small} {
				for _, r := range []differentialResetReader{left, right} {
					if err := r.Reset(&differentialInput{b: bytes.Clone(next), chunk: 1, fail: false}); err != nil {
						t.Fatal(err)
					}
				}
				differentialCompare(t, left, right)
			}
		})
	}
}

// Maps whose literal and distance contents differ, and a literal map that
// names a different tree per context: storage shared between the two maps, or
// between the modes and a map, or an entry kept from an earlier map, changes
// the plaintext of these where it does not change the plaintext of maps whose
// entries are all alike.
func TestBrotliMapContentsAgreeWithOriginal(t *testing.T) {
	mixed := make([]byte, 64)
	for i := 1; i < len(mixed); i++ {
		mixed[i] = 1
	}
	for _, c := range []struct {
		name   string
		blocks []brotliBlock
	}{
		{"split-maps", []brotliBlock{
			{types: 256, trees: 2, literal: 1, distance: 0, length: 1},
			{types: 256, trees: 2, literal: 0, distance: 1, length: 1},
			{types: 1, trees: 2, literal: 1, distance: 0, length: 1},
		}},
		{"mixed-map", []brotliBlock{
			{types: 1, trees: 2, entries: mixed, length: 3},
			{types: 256, trees: 2, literal: 0, distance: 1, length: 1},
			{types: 1, trees: 2, entries: mixed, length: 3},
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			encoded, plain := brotliStream(c.blocks...)
			qualified, err := io.ReadAll(original.NewReader(bytes.NewReader(encoded)))
			if err != nil || !bytes.Equal(qualified, plain) {
				t.Fatalf("fixture invalid: %x/%v want %x", qualified, err, plain)
			}
			differentialMatrix(t, encoded)
		})
	}
}
