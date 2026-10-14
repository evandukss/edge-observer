package brotli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"slices"
	"testing"

	upstream "github.com/andybalholm/brotli"
)

// The copy's only change is where its context maps and modes live, so it must
// decode every stream exactly as the module it was copied from: the same bytes
// in the same order, and the same error at the same point. These tests decode
// each stream with both and compare.

// result is everything a decode returned: the bytes, and how it ended.
type result struct {
	out []byte
	err string
}

// feeder returns its input in pieces of the sizes rng chooses, 1 to most bytes.
type feeder struct {
	b    []byte
	rng  *rand.Rand
	most int
}

func (f *feeder) Read(p []byte) (int, error) {
	if len(f.b) == 0 {
		return 0, io.EOF
	}
	n := min(len(p), len(f.b), 1+f.rng.Intn(f.most))
	copy(p, f.b[:n])
	f.b = f.b[n:]
	return n, nil
}

// drain reads r to its end in reads of 1 to most bytes, as rng chooses, and
// calls each after every read.
func drain(r io.Reader, rng *rand.Rand, most int, each func()) result {
	var out []byte
	buf := make([]byte, most)
	for range 1 << 26 {
		n, err := r.Read(buf[:1+rng.Intn(most)])
		out = append(out, buf[:n]...)
		if each != nil {
			each()
		}
		if errors.Is(err, io.EOF) {
			return result{out, ""}
		}
		if err != nil {
			return result{out, err.Error()}
		}
	}
	return result{out, "no end"}
}

// both decodes encoded with the copy and with the module, input fed and output
// read in pieces of the same sizes, and fails the test where they differ. It
// returns what the copy's maps looked like along the way.
func both(t *testing.T, name string, encoded []byte, in, out int, seed int64) maps {
	t.Helper()
	ours := NewReader(&feeder{b: encoded, rng: rand.New(rand.NewSource(seed)), most: in})
	var seen maps
	got := drain(ours, rand.New(rand.NewSource(seed+1)), out, func() { seen.note(ours) })
	theirs := upstream.NewReader(&feeder{b: encoded, rng: rand.New(rand.NewSource(seed)), most: in})
	want := drain(theirs, rand.New(rand.NewSource(seed+1)), out, nil)
	if got.err != want.err || !bytes.Equal(got.out, want.out) {
		t.Fatalf("%s: the copy returned %d bytes and %q, the module %d bytes and %q", name, len(got.out), got.err, len(want.out), want.err)
	}
	return seen
}

// maps records the context maps a Reader held between reads.
type maps struct {
	literalSizes, distanceSizes, literalTrees []int
}

func (m *maps) note(r *Reader) {
	add := func(list *[]int, v int) {
		if v > 0 && !slices.Contains(*list, v) {
			*list = append(*list, v)
		}
	}
	add(&m.literalSizes, len(r.context_map))
	add(&m.distanceSizes, len(r.dist_context_map))
	add(&m.literalTrees, int(r.num_literal_htrees))
}

func (m *maps) merge(o maps) {
	for _, pair := range [][2]*[]int{{&m.literalSizes, &o.literalSizes}, {&m.distanceSizes, &o.distanceSizes}, {&m.literalTrees, &o.literalTrees}} {
		for _, v := range *pair[1] {
			if !slices.Contains(*pair[0], v) {
				*pair[0] = append(*pair[0], v)
			}
		}
	}
}

func encode(p []byte, quality, lgwin int) []byte {
	var b bytes.Buffer
	w := upstream.NewWriterOptions(&b, upstream.WriterOptions{Quality: quality, LGWin: lgwin})
	if _, err := w.Write(p); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// mixed is content whose statistics change every few kilobytes, so that an
// encoder at high quality writes metablocks with different block types,
// context maps and tree counts.
func mixed(n int, seed int64) []byte {
	rng := rand.New(rand.NewSource(seed))
	words := []string{"order", "id", "user", "true", "null", "value", "name", `"key":`, "{", "}", ",", " ", "\n"}
	var b bytes.Buffer
	for b.Len() < n {
		size := 512 + rng.Intn(8192)
		switch rng.Intn(4) {
		case 0:
			for i := 0; i < size; i++ {
				b.WriteString(words[rng.Intn(len(words))])
			}
		case 1:
			chunk := make([]byte, size)
			rng.Read(chunk)
			b.Write(chunk)
		case 2:
			b.Write(bytes.Repeat([]byte{byte(rng.Intn(256))}, size))
		default:
			for i := 0; i < size; i++ {
				b.WriteByte(byte('a' + rng.Intn(1+rng.Intn(26))))
			}
		}
	}
	return b.Bytes()[:n]
}

func corpus() map[string][]byte {
	streams := map[string][]byte{}
	for _, n := range []int{0, 1, 100, 5000, 70000, 300000} {
		for _, q := range []int{0, 1, 5, 9, 10, 11} {
			for _, lgwin := range []int{10, 16, 22} {
				if n == 300000 && q >= 10 && lgwin != 22 {
					continue
				}
				streams[fmt.Sprintf("mixed %d q%d w%d", n, q, lgwin)] = encode(mixed(n, int64(n+q)), q, lgwin)
			}
		}
	}
	return streams
}

func TestTheCopyDecodesAsTheModuleDoes(t *testing.T) {
	var seen maps
	streams := corpus()
	for name, encoded := range streams {
		for i, shape := range [][2]int{{1 << 20, 1 << 20}, {1, 7}, {13, 1}, {300, 4096}} {
			seen.merge(both(t, fmt.Sprint(name, " ", shape), encoded, shape[0], shape[1], int64(i)))
		}
	}
	// What the comparison covered: maps of several sizes, read with one tree
	// and with many.
	if len(seen.literalSizes) < 3 || len(seen.distanceSizes) < 2 || !slices.Contains(seen.literalTrees, 1) || slices.Max(seen.literalTrees) < 3 {
		t.Fatalf("wiring, not the property: the corpus held literal maps of %v bytes, distance maps of %v and %v literal trees", seen.literalSizes, seen.distanceSizes, seen.literalTrees)
	}
	t.Logf("%d streams; literal maps %v bytes, distance maps %v, literal trees %v", len(streams), seen.literalSizes, seen.distanceSizes, seen.literalTrees)
}

func TestTheCopyFailsWhereTheModuleFails(t *testing.T) {
	encoded := encode(mixed(40000, 7), 11, 18)
	// Every truncation of a stream whose metablocks carry maps.
	for n := 0; n < len(encoded); n += 1 + n/64 {
		both(t, fmt.Sprint("truncated to ", n), encoded[:n], 5, 97, int64(n))
	}
	// Corruption anywhere, and bytes after the end.
	rng := rand.New(rand.NewSource(8))
	for range 400 {
		corrupt := bytes.Clone(encoded)
		at := rng.Intn(len(corrupt))
		corrupt[at] ^= byte(1 + rng.Intn(255))
		both(t, fmt.Sprint("corrupt at ", at), corrupt, 1+rng.Intn(64), 1+rng.Intn(512), int64(at))
	}
	both(t, "trailing bytes", append(bytes.Clone(encoded), 0, 1, 2), 9, 33, 1)
}

// sized are streams whose literal context maps differ in size: the encoder
// keeps one size for a whole stream, so a Reader meets a new size on Reset.
// Measured: 5440, 256, 4160 and 192 bytes.
func sized() [][]byte {
	return [][]byte{
		encode(mixed(300000, 13), 9, 22),
		encode(mixed(300000, 11), 10, 22),
		encode(mixed(300000, 11), 9, 22),
		encode(mixed(300000, 11), 11, 22),
	}
}

func TestTheCopyResetsAsTheModuleDoes(t *testing.T) {
	maps := sized()
	large, small := maps[0], maps[1]
	broken := bytes.Clone(large)
	broken[len(broken)/3] ^= 0x5a
	plain := encode([]byte("a short body, one tree"), 5, 16)
	// Each sequence is decoded by one Reader of the copy, Reset between
	// streams, and each stream by a fresh Reader of the module.
	for _, sequence := range [][]string{
		{"large", "small", "plain", "large"},
		{"broken", "small"},
		{"broken", "large", "broken", "plain"},
		{"small", "large", "small"},
		{"q9", "q10", "q9b", "q11", "q9"},
	} {
		streams := map[string][]byte{"large": large, "small": small, "broken": broken, "plain": plain,
			"q9": maps[0], "q10": maps[1], "q9b": maps[2], "q11": maps[3]}
		ours := NewReader(bytes.NewReader(nil))
		for i, name := range sequence {
			if err := ours.Reset(bytes.NewReader(streams[name])); err != nil {
				t.Fatal(err)
			}
			got := drain(ours, rand.New(rand.NewSource(int64(i))), 1000, nil)
			want := drain(upstream.NewReader(bytes.NewReader(streams[name])), rand.New(rand.NewSource(int64(i))), 1000, nil)
			if got.err != want.err || !bytes.Equal(got.out, want.out) {
				t.Fatalf("%v, stream %d (%s): the copy returned %d bytes and %q, the module %d bytes and %q", sequence, i, name, len(got.out), got.err, len(want.out), want.err)
			}
		}
	}
}

func TestTheMapsAreMadeOncePerReader(t *testing.T) {
	r := NewReader(bytes.NewReader(nil))
	var literal, distance, modes []*byte
	note := func(storage []byte, seen *[]*byte) {
		if cap(storage) > 0 && !slices.Contains(*seen, &storage[:1][0]) {
			*seen = append(*seen, &storage[:1][0])
		}
	}
	var seen maps
	for i, encoded := range sized() {
		if err := r.Reset(bytes.NewReader(encoded)); err != nil {
			t.Fatal(err)
		}
		if got := drain(r, rand.New(rand.NewSource(int64(i))), 4096, func() {
			note(r.context_map_storage, &literal)
			note(r.dist_context_map_storage, &distance)
			note(r.context_modes_storage, &modes)
			seen.note(r)
		}); got.err != "" {
			t.Fatalf("stream %d: %s", i, got.err)
		}
	}
	if len(seen.literalSizes) < 3 {
		t.Fatalf("wiring, not the property: one Reader saw literal maps of %v bytes only", seen.literalSizes)
	}
	if len(literal) != 1 || len(distance) != 1 || len(modes) != 1 {
		t.Fatalf("storage made %d, %d and %d times over maps of %v bytes", len(literal), len(distance), len(modes), seen.literalSizes)
	}
	if cap(r.context_map_storage) != maxLiteralContextMap || cap(r.dist_context_map_storage) != maxDistanceContextMap || cap(r.context_modes_storage) != maxNumberOfBlockTypes {
		t.Fatalf("storage of %d, %d and %d bytes", cap(r.context_map_storage), cap(r.dist_context_map_storage), cap(r.context_modes_storage))
	}
}
