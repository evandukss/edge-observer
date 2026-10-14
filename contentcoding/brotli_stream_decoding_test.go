package contentcoding

import (
	"crypto/sha256"
	"encoding/hex"
	"math/bits"
	"testing"
)

// brotliBits authors a brotli stream bit by bit, least significant bit first
// (RFC 7932 section 1.5.1), from the metablocks the tests here need: a window
// of WBITS 10, compressed metablocks of a few literals whose block-type counts,
// tree counts and context-map contents are chosen,
// and the last empty metablock. A stream it writes is checked against the
// original decoder before it is used as an expectation, and the streams it
// shares with an earlier generator are checked against that generator's
// output byte for byte (brotliCheckAuthored).
type brotliBits struct {
	out []byte
	pos int
}

func (b *brotliBits) put(value uint64, n int) {
	for i := 0; i < n; i++ {
		if b.pos%8 == 0 {
			b.out = append(b.out, 0)
		}
		b.out[len(b.out)-1] |= byte(value>>uint(i)&1) << uint(b.pos%8)
		b.pos++
	}
}

// header is the stream header declaring WBITS 10, a window of 1008 bytes.
func (b *brotliBits) header() {
	b.put(1, 1)
	b.put(0, 3)
	b.put(2, 3)
}

// simple is a simple prefix code of one symbol, which then costs no bits per
// use; width is the alphabet's symbol width.
func (b *brotliBits) simple(symbol uint64, width int) {
	b.put(1, 2)
	b.put(0, 2)
	b.put(symbol, width)
}

// simplePair is a simple prefix code of two symbols, one bit each: 0 selects
// the smaller symbol and 1 the larger.
func (b *brotliBits) simplePair(first, second uint64, width int) {
	b.put(1, 2)
	b.put(1, 2)
	b.put(first, width)
	b.put(second, width)
}

// varLenUint8 is the variable-length code of a count minus one (RFC 7932
// section 9.2, NBLTYPES and NTREES).
func (b *brotliBits) varLenUint8(value int) {
	if value == 0 {
		b.put(0, 1)
		return
	}
	n := bits.Len(uint(value)) - 1
	b.put(1, 1)
	b.put(uint64(n), 3)
	b.put(uint64(value-1<<n), n)
}

// symbolWidth is the width of a symbol of an alphabet of the given size in a
// simple prefix code.
func symbolWidth(alphabet int) int { return bits.Len(uint(alphabet - 1)) }

// blockTypes declares count block types of one category. With more than one,
// the block-type code and the block-count code are one symbol each, and every
// block is one symbol long.
func (b *brotliBits) blockTypes(count int) {
	b.varLenUint8(count - 1)
	if count == 1 {
		return
	}
	b.simple(0, symbolWidth(count+2))
	b.simple(0, symbolWidth(26))
	b.put(0, 2)
}

// contextMap is a context map over trees trees. With one tree there is no map
// to read. Otherwise every entry is value, coded with a one-symbol tree that
// costs no bits per entry, or, over two trees, entries, coded one bit each.
// No run-length coding of zeros and no move-to-front transform.
func (b *brotliBits) contextMap(trees int, value byte, entries []byte) {
	if trees == 1 {
		b.put(0, 1)
		return
	}
	b.varLenUint8(trees - 1)
	b.put(0, 1)
	if entries == nil {
		b.simple(uint64(value), symbolWidth(trees))
	} else {
		b.simplePair(0, 1, symbolWidth(trees))
		for _, e := range entries {
			b.put(uint64(e), 1)
		}
	}
	b.put(0, 1)
}

// brotliBlock is one compressed metablock of length literals, length at most
// 5: its one command inserts them, and the metablock ends before the copy the
// command also names. types is its count of literal and of distance block
// types, trees its count of literal and of distance trees. literal and
// distance are the value of every entry of the respective context map, unless
// entries gives the literal map entry by entry, over two trees and one block
// type. Literal tree i emits 'a' + i.
type brotliBlock struct {
	types, trees      int
	literal, distance byte
	entries           []byte
	length            int
}

func (b *brotliBits) metablock(blk brotliBlock) {
	b.put(0, 1)
	b.put(0, 2)
	b.put(uint64(blk.length-1), 16)
	b.put(0, 1)
	b.blockTypes(blk.types)
	b.blockTypes(1)
	b.blockTypes(blk.types)
	b.put(0, 6)
	for i := 0; i < blk.types; i++ {
		b.put(0, 2)
	}
	b.contextMap(blk.trees, blk.literal, blk.entries)
	b.contextMap(blk.trees, blk.distance, nil)
	for tree := 0; tree < blk.trees; tree++ {
		b.simple(uint64('a'+tree), 8)
	}
	b.simple(uint64(blk.length)<<3, 10)
	for tree := 0; tree < blk.trees; tree++ {
		b.simple(0, 6)
	}
}

// plain is the bytes the metablock emits: for each literal, the tree its
// literal context map names for the literal's context, which under mode LSB6
// is the low six bits of the previous byte, 0 at the start of the stream (RFC
// 7932 section 7.1). previous is the last byte emitted so far, and is updated.
func (blk brotliBlock) plain(previous *byte) []byte {
	out := make([]byte, 0, blk.length)
	for i := 0; i < blk.length; i++ {
		tree := blk.literal
		if blk.entries != nil {
			tree = blk.entries[*previous&0x3f]
		}
		c := 'a' + tree
		out = append(out, c)
		*previous = c
	}
	return out
}

// finish adds the last, empty metablock and returns the stream.
func (b *brotliBits) finish() []byte {
	b.put(1, 1)
	b.put(1, 1)
	return b.out
}

// brotliStream is a stream of WBITS 10 holding the given metablocks, and the
// bytes it decodes to.
func brotliStream(blocks ...brotliBlock) (encoded, plain []byte) {
	var b brotliBits
	b.header()
	var previous byte
	for _, blk := range blocks {
		b.metablock(blk)
		plain = append(plain, blk.plain(&previous)...)
	}
	return b.finish(), plain
}

// brotliContextStream is count metablocks of types literal and distance block
// types, one tree each, every one emitting 'a': the streams whose context
// maps cost the decoder the most for the output they carry.
func brotliContextStream(types, count int) (encoded, plain []byte) {
	blocks := make([]brotliBlock, count)
	for i := range blocks {
		blocks[i] = brotliBlock{types: types, trees: 1, length: 1}
	}
	return brotliStream(blocks...)
}

// brotliAuthoredStreams is the sha256 of each stream the generator that first
// authored these fixtures wrote, by name. The writer above reproduces every
// one of them, which is what makes its other streams trustworthy.
var brotliAuthoredStreams = map[string]string{
	"one-small":         "4ebfc0fd3ba683803f17999b3f29ea5b92c53458acf5dbe23deaab48e2fa89cc",
	"one-large":         "eba7ee2f3544c4caeb192e5c8eae9bc9c6e8b7b999fc9250274a425d177a9bb5",
	"two-zero":          "f5b769b4bf798b03ccfa6ee43aa788e4df8765a2c6123c17608c2afa42f4047d",
	"two-one":           "a5815484fc7dafb30e2f08eff2a5058498c9279d1d54d8a7c0443e604765c68d",
	"shrink-clear":      "67a50d2fdf72097ceab509558591d4c5244f6a38ad1150c26d072dc858438e71",
	"same-size-clear":   "def825b3631bf0b8ffb98b939cd60e29d11955104a7dd93d42cdda7ba3bcfd1b",
	"grow-change":       "c52caa00770a518c17271c24b79ef0425ea34995f5a82f4673bbde8ea57608d2",
	"alternating":       "03589f87aedc0b99f174972bc8b59f8bfef235ce68ace9f5e16b52400218bea3",
	"context-1-1024":    "14a10a7576c41156e454b1d71fbf2806a3f735c6dd0c06e487614a590c4e9804",
	"context-256-1024":  "601c5e66e580b25b82009837f2d2c5a3123fd4c142e3685b058052407f1a598d",
	"context-256-65536": "60753075af9625471ed108e812b1ff1d9c0790fe76783d7a0922dbeb0c61e311",
}

// brotliCheckAuthored fails the test, as a wiring failure, unless encoded is
// byte for byte the authored stream of that name.
func brotliCheckAuthored(t *testing.T, name string, encoded []byte) {
	t.Helper()
	want, ok := brotliAuthoredStreams[name]
	if !ok {
		t.Fatalf("wiring, not the property: no authored stream is named %s", name)
	}
	sum := sha256.Sum256(encoded)
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("wiring, not the property: the stream writer does not reproduce the authored %s: sha256 %s, want %s", name, got, want)
	}
}

func TestBrotliStreamWriterReproducesTheAuthoredStreams(t *testing.T) {
	for _, tc := range []struct {
		name         string
		types, count int
	}{{"context-1-1024", 1, 1024}, {"context-256-1024", 256, 1024}, {"context-256-65536", 256, 65536}} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, plain := brotliContextStream(tc.types, tc.count)
			brotliCheckAuthored(t, tc.name, encoded)
			if len(plain) != tc.count {
				t.Errorf("%d bytes of plaintext, want %d", len(plain), tc.count)
			}
		})
	}
}
