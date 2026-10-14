package contentcoding

import "encoding/binary"

// The bounds below are derived from the pinned decoders, github.com/klauspost/compress
// v1.20.1 (flate and zstd) and internal/brotli, the decoder of
// github.com/andybalholm/brotli v1.2.6 with its context maps kept (its
// PROVENANCE), and from this package's own buffers, and are confirmed by
// measurement on go1.27.1.
// Each counts what the Go runtime would count, allocated: see allocated.
//
// Two quantities are bounded, and they answer different questions:
//   - what one decode holds at once, which bounds its charges: Workspace for the
//     decoder, planned from the stage's input, the output buffers, and Charges
//     and Peak, the ceiling for the whole decode;
//   - what one decode allocates in total, garbage included, which bounds its
//     work on the heap: StageAllocation, mechanism by mechanism, and
//     Cumulative, A(coding, B).
// A decoder that holds little can still allocate much, and the second is what
// an unchecked decode followed by a length check exceeds.

// AdmissionAllocation is the most Decode allocates before it asks for a
// stage's workspace. Nothing is allocated before the first stage's workspace
// reservation, the plan read from the stream header included, so a decode
// whose first workspace is refused allocates at most this, which is far below
// any Workspace. The allowance is for the runtime, not the decode.
const AdmissionAllocation = 1024

// pageSize is the runtime's page; an object over sizeClassLimit takes whole
// pages.
const (
	sizeClassLimit = 32 << 10
	pageSize       = 8 << 10
)

// allocated is at least what the runtime counts for one allocation of n bytes:
// a small object takes a size class at most 18.75% and 16 bytes larger, which
// n/4 + 16 covers, and a large one takes whole pages.
func allocated(n int64) int64 {
	if n <= 0 {
		return 0
	}
	if n <= sizeClassLimit {
		return n + n/4 + 16
	}
	return (n + pageSize - 1) / pageSize * pageSize
}

// stageOverhead is this package's own state for one stage: its input and
// output records and the deflate reader's interface value, a few hundred
// bytes.
const stageOverhead = 1024

// decodeOverhead covers what one decode allocates once whatever its stages:
// first-use initialisation inside the decoders and the standard library (the
// fixed Huffman table of klauspost/compress/flate, 1 KiB, and the CRC-32
// tables) and the runtime's own allocations between two readings of its
// counters, measured at up to 5 KiB.
const decodeOverhead = 64 << 10

// DecodeOverhead is what Cumulative adds once to the stages' sum.
const DecodeOverhead = decodeOverhead

// The deflate decoder of klauspost/compress/flate, for gzip and deflate. One
// decoder serves every gzip member, its window and tables kept.
var (
	// flateFixed: NewReader's decompressor (416 bytes), its two code-length
	// arrays (316 and 19 ints) and its 32 KiB window, measured at 36032 bytes
	// together, and the two 512-entry chunk tables made on first use.
	flateFixed = allocated(416) + allocated(316*8) + allocated(19*8) + allocated(32<<10) + 2*allocated(1024)
	// flateLinks is what the overflow link tables of the two Huffman decoders
	// hold at once (inflate.go, huffmanDecoder.init). A link table covers one
	// 9-bit prefix filled by codes of 10 to 15 bits, so at least two codes:
	// at most 143 for the 286 literal/length codes and 15 for the 30 distance
	// codes, each at most 64 entries of 2 bytes. A larger slice replaces the
	// old one without copying, so both are counted.
	flateLinks = 2*(allocated(143*24)+143*allocated(128)) + 2*(allocated(15*24)+15*allocated(128))
	// flateLinkGrowth is everything the link tables can allocate over one
	// stage. The decoders keep their tables between blocks and members, and
	// reallocate only to grow: the slice of tables to a strictly larger count,
	// each table through 2, 4 ... 64 entries.
	flateLinkGrowth = linkGrowth(143) + linkGrowth(15)
)

func linkGrowth(most int64) int64 {
	var steps int64
	for entries := int64(2); entries <= 64; entries *= 2 {
		steps += allocated(entries * 2)
	}
	var sum int64
	for n := int64(1); n <= most; n++ {
		sum += allocated(n*24) + n*steps
	}
	return sum
}

// The brotli decoder of internal/brotli.
var (
	// brotliFixed: the Reader (5608 bytes) and its 32 KiB input buffer, and
	// the block-type and block-length trees, 3 * (632 + 396) codes of 4 bytes.
	brotliFixed = allocated(5608) + allocated(32<<10) + allocated(3*(632+396)*4)
	// brotliTrees is the most the three Huffman tree groups hold once: up to
	// 256 trees each of 630 literal, 1080 insert-and-copy and 920 distance
	// codes of 4 bytes (kMaxHuffmanTableSize), and a slice header per tree. The
	// stream header does not say how many trees a stream uses. A group keeps
	// its capacity and reallocates, without copying, only to grow, so
	// Workspace counts it twice.
	brotliTrees = treeGroup(630, 256) + treeGroup(1080, 256) + treeGroup(920, 256)
	// brotliMaps is the context maps and modes: at most 256 block types of 64
	// literal contexts, 4 distance contexts and one mode. The Reader makes
	// them once, at these sizes, and keeps them (internal/brotli/storage.go).
	brotliMaps = allocated(256*64) + allocated(256*4) + allocated(256)
	// brotliTreeGrowth is every allocation the tree groups can make: each
	// group grows only, one tree count after another up to 256.
	brotliTreeGrowth = treeGrowth(630) + treeGrowth(1080) + treeGrowth(920)
)

func treeGroup(codes, trees int64) int64 {
	return allocated(trees*codes*4) + allocated(trees*24)
}

func treeGrowth(codes int64) int64 {
	var sum int64
	for trees := int64(1); trees <= 256; trees++ {
		sum += treeGroup(codes, trees)
	}
	return sum
}

// brotliTreeBytesPerInputByte bounds the tree groups' growth by the input
// that pays for it: a metablock that grows a group reads every tree of it, and
// an insert-and-copy tree, the costliest, is 4320 bytes of codes and a slice
// header for at least 14 bits of input, under 3125 per byte with size classes.
const brotliTreeBytesPerInputByte = 3125

// brotliRingSlack is kRingBufferWriteAheadSlack, what the ring buffer is
// allocated beyond its size.
const brotliRingSlack = 42

// brotliRing is the ring buffer a stream declaring WBITS bits can grow to,
// 1 << WBITS.
func brotliRing(bits uint) int64 {
	return int64(1) << bits
}

// brotliLargestRing is the largest ring buffer a stage admits under bound:
// 1 << WBITS for the largest WBITS whose window, (1 << WBITS) - 16, the header
// check admits.
func brotliLargestRing(bound int) int64 {
	bound = clampBound(bound)
	ring := int64(1) << 10
	for bits := 11; bits <= 24; bits++ {
		if 1<<bits-16 > max(bound, brotliSmallestWindow) {
			break
		}
		ring = 1 << bits
	}
	return ring
}

// brotliRingHeld is what the ring buffer holds at most at once: the decoder
// sizes it to the output it knows of, from 1 KiB, and doubles it up to the
// window, copying, so the old and the new are held together.
func brotliRingHeld(ring int64) int64 {
	return allocated(ring+brotliRingSlack) + allocated(ring/2+brotliRingSlack)
}

// brotliRingGrowth is every ring buffer one stage allocates, each size at most
// once.
func brotliRingGrowth(ring int64) int64 {
	var sum int64
	for size := int64(1 << 10); size <= ring; size *= 2 {
		sum += allocated(size + brotliRingSlack)
	}
	return sum
}

// brotliWindowBits reads WBITS from a stream's first byte (RFC 7932 section
// 9.1), the bits taken from the least significant end. large is the
// large-window extension's marker, which RFC 7932 does not define.
func brotliWindowBits(first byte) (bits uint, large bool) {
	switch {
	case first&1 == 0:
		return 16, false
	case first>>1&7 != 0:
		return 17 + uint(first>>1&7), false
	}
	switch n := first >> 4 & 7; n {
	case 0:
		return 17, false
	case 1:
		return 0, true
	default:
		return 8 + uint(n), false
	}
}

// The zstd decoder of klauspost/compress, one stage alone, lowmem, concurrency
// one.
const (
	// zstdFixed: NewReader's Decoder, block and frame decoders and options,
	// measured at 1896 bytes, and the pooled tables a frame takes: a huff0
	// Scratch (1632 bytes) with its 2048-entry table, its 1 KiB stream buffers
	// and decoder, and three FSE decoders of 5128 bytes. 32 KiB covers them.
	zstdFixed = 32 << 10
	// zstdPoolBytesPerInputByte bounds what the decoder takes again from
	// pools that a garbage collection has emptied, by the input that asks for
	// it: the tables above, at most 27832 bytes for a compressed block of at
	// least 5 bytes (5567 per byte), and the 8 KiB buffer a skippable frame of
	// at least 8 bytes is discarded through (1024 per byte).
	zstdPoolBytesPerInputByte = 5600
	// zstdBlockDataBytesPerInputByte bounds the compressed-data buffer, grown
	// to a block's compressed size and paid for by that block's bytes and
	// header: 1.25 per byte and a size class's 36 for at least 4 bytes.
	zstdBlockDataBytesPerInputByte = 10
	// zstdBlock is a compressed block's largest size, and zstdSequences the
	// most sequences one block can declare, of 24 bytes each, which the
	// decoder allocates for before it checks the block.
	zstdBlock     = 128 << 10
	zstdSequences = 0x7f00 + 0xffff
	// zstdLargeWindow is maxBlockSize: from it a lowmem frame's history is its
	// window plus half of it rather than twice the window, so the history is
	// not monotone in the window there.
	zstdLargeWindow = 1<<21 - 1
)

// zstdHistory is the history buffer a frame of the given window takes
// (framedec.go, allocFrameBuffer).
func zstdHistory(window uint64) int64 {
	if window < zstdLargeWindow {
		return int64(2 * window)
	}
	return int64(window) + zstdLargeWindow/2
}

// zstdHistoryEnvelope is the largest history any window up to limit takes:
// the history at limit, or just below the threshold where it drops.
func zstdHistoryEnvelope(limit uint64) int64 {
	return max(zstdHistory(limit), zstdHistory(min(limit, zstdLargeWindow-1)))
}

// zstdBlockBuffers is the block decoder's buffers once at their largest: the
// compressed data, the decoded block, the literals, each a block and a little,
// and the sequences. Each grows without copying, so Workspace counts them
// twice.
var zstdBlockBuffers = 3*allocated(zstdBlock+17) + allocated(zstdSequences*24)

// zstdPlan walks the frames of a zstd stream by their headers alone, without
// allocating, and returns the most history the decoder holds at once while
// decoding them under limit, and how many bytes the walk read.
//
// For each frame in turn it takes the window the frame declares, a
// single-segment frame's being max(content size, 1024). The decoder keeps the
// largest history it has made and replaces it, without copying, only when a
// frame needs more, so a frame needing more holds the retained history and the
// new one at once, and a later, smaller window releases nothing.
//
// The walk goes no further than the decoder could: it stops at a frame whose
// window is over limit, which the decoder refuses before making its history,
// and at anything it cannot read whole, a header, a block layout or a frame's
// end, after counting the frame whose header it read, so it plans for every
// frame the decoder can reach. It decides nothing: what it stops at is decided
// by the decoder when, and if, it gets there.
//
// It also stops at the frame that would make the history a fourth time
// (zstdHistoryAllocations), counting the header it read but not the history:
// the stage never lets the decoder read that frame. A frame counts from its
// header alone, so a frame the decoder would refuse before making its history,
// for a dictionary, a reserved bit or a first block header that is missing or
// invalid, still counts, and a fourth allocation there ends the stage as too
// costly rather than failed. A skippable frame makes no history and never
// counts; a frame of one empty block makes its history like any other.
func zstdPlan(b []byte, limit uint64) (held int64, read int) {
	held, read, _ = zstdPlanned(b, limit)
	return held, read
}

// zstdHistoryAllocations is how many times one stage lets the decoder make its
// history: the first time, and two growths.
const zstdHistoryAllocations = 3

// zstdPlanned is zstdPlan, and where the stage cuts the input: the start of
// the frame that would make the history a fourth time, or -1.
func zstdPlanned(b []byte, limit uint64) (held int64, read, cut int) {
	var retained int64
	allocations, pos := 0, 0
	for {
		if len(b)-pos < 4 {
			return held, read + len(b) - pos, -1
		}
		magic := binary.LittleEndian.Uint32(b[pos:])
		if magic&0xfffffff0 == 0x184d2a50 {
			if len(b)-pos < 8 {
				return held, read + len(b) - pos, -1
			}
			size := uint64(binary.LittleEndian.Uint32(b[pos+4:]))
			read += 8
			if size > uint64(len(b)-pos-8) {
				return held, read, -1
			}
			pos += 8 + int(size)
			continue
		}
		read += 4
		if magic != zstdMagic || len(b)-pos < 5 {
			return held, read, -1
		}
		descriptor := b[pos+4]
		header := 5 + [4]int{0, 1, 2, 4}[descriptor&3] + [4]int{0, 2, 4, 8}[descriptor>>6]
		if descriptor&(1<<5) == 0 || descriptor>>6 == 0 {
			// A window descriptor, or a single segment's one-byte content size.
			header++
		}
		if len(b)-pos < header {
			return held, read + len(b) - pos - 4, -1
		}
		read += header - 4
		window, _ := zstdDeclaredWindow(b[pos:])
		if window > limit {
			return held, read, -1
		}
		need := zstdHistory(window)
		if need > retained {
			if allocations == zstdHistoryAllocations {
				return held, read, pos
			}
			allocations++
			held = max(held, allocated(retained)+allocated(need))
			retained = need
		}
		end, blocks := zstdFrameEnd(b[pos:], header, descriptor&(1<<2) != 0)
		read += blocks
		if end == 0 {
			return held, read, -1
		}
		pos += end
	}
}

// zstdFrameEnd walks a frame's blocks from the end of its header at pos and
// returns where the frame ends, or 0 when its blocks or checksum are not all
// there or a block's type is reserved, and how many bytes of block headers it
// read.
func zstdFrameEnd(b []byte, pos int, checksum bool) (end, read int) {
	for {
		if len(b)-pos < 3 {
			return 0, read + len(b) - pos
		}
		header := uint32(b[pos]) | uint32(b[pos+1])<<8 | uint32(b[pos+2])<<16
		pos += 3
		read += 3
		size := int(header >> 3)
		switch header >> 1 & 3 {
		case 0, 2:
		case 1:
			size = 1
		default:
			return 0, read
		}
		if len(b)-pos < size {
			return 0, read
		}
		pos += size
		if header&1 != 0 {
			break
		}
	}
	if checksum {
		pos += 4
	}
	if pos > len(b) {
		return 0, read
	}
	return pos, read
}

// zstdMagic is a frame's magic number, read little-endian.
const zstdMagic = 0xfd2fb528

// zstdDeclaredWindow is the window a frame header declares (RFC 8878 section
// 3.1.1.1.2), or for a single-segment frame max(content size, 1024), the
// window the decoder then gives it. b holds the header whole.
func zstdDeclaredWindow(b []byte) (uint64, bool) {
	if len(b) < 5 || binary.LittleEndian.Uint32(b) != zstdMagic {
		return 0, false
	}
	descriptor := b[4]
	if descriptor&(1<<5) == 0 {
		if len(b) < 6 {
			return 0, false
		}
		exponent, mantissa := uint64(b[5]>>3), uint64(b[5]&7)
		base := uint64(1) << (10 + exponent)
		return base + base/8*mantissa, true
	}
	pos := 5 + [4]int{0, 1, 2, 4}[descriptor&3]
	size := [4]int{1, 2, 4, 8}[descriptor>>6]
	if len(b)-pos < size {
		return 0, false
	}
	var content uint64
	for i := size - 1; i >= 0; i-- {
		content = content<<8 | uint64(b[pos+i])
	}
	if size == 2 {
		content += 256
	}
	return max(content, zstdSmallestWindow), true
}

// zstdWindowGrowth is every decoded-block buffer that frames declaring rising
// windows below a block in their window descriptors allocate: a descriptor
// names one of 8 sizes per power of two, so every size up to limit is counted
// once.
func zstdWindowGrowth(limit uint64) (blocks int64) {
	for exponent := uint64(0); exponent < 32; exponent++ {
		base := uint64(1) << (10 + exponent)
		if base > limit {
			break
		}
		for mantissa := uint64(0); mantissa < 8; mantissa++ {
			window := base + base/8*mantissa
			if window > limit {
				break
			}
			if window < zstdBlock {
				blocks += allocated(int64(window) + 17)
			}
		}
	}
	return blocks
}

// outputGrowth is every buffer one stage's output allocates: the capacities
// grow reserves, each ceil(limit/2^k), from the first of them at least
// firstCapacity up to limit.
func outputGrowth(bound int64) int64 {
	limit := bound + 1
	var sum, previous int64
	for shift := 62; shift >= 0; shift-- {
		capacity := ceilShift(limit, shift)
		if capacity < firstCapacity && capacity < limit {
			continue
		}
		if capacity > previous {
			sum += allocated(capacity)
			previous = capacity
		}
	}
	return sum
}

// ceilShift is ceil(n / 2^shift) for n >= 0.
func ceilShift(n int64, shift int) int64 {
	q := n >> shift
	if n&(1<<shift-1) != 0 {
		q++
	}
	return q
}

// isqrt is floor(sqrt(n)) for n >= 0.
func isqrt(n int64) int64 {
	r := int64(0)
	for bit := int64(1) << 30; bit > 0; bit >>= 1 {
		if (r+bit)*(r+bit) <= n {
			r += bit
		}
	}
	return r
}

// maxBound is the largest bound honoured: a larger one is read as it, so that
// no capacity or bound overflows.
const maxBound = 1 << 40

// clampBound reads a bound as Decode does: negative as zero, and above
// maxBound as maxBound.
func clampBound(bound int) int {
	return min(max(bound, 0), maxBound)
}

// Workspace is W(plan): what Decode reserves for one stage of the coding over
// input under bound, before the stage's decoder exists. It bounds what the
// decoder holds at once besides the stage's input and output buffers, planned
// from what the stream declares:
//
//	gzip, deflate  fixed, whatever the stream: the decoder, its 32 KiB window and
//	               its link tables, about 112 KB, one decoder for every member
//	br             the decoder and its input buffer, its tree groups twice (5.4 MB,
//	               the header does not say how many trees), its context maps,
//	               and its ring buffer for the WBITS the header declares while it
//	               doubles: 1.5 times 1 << WBITS
//	zstd           the decoder and its pooled tables, its block buffers twice
//	               (5.5 MB), and the history zstdPlan finds for the frames the
//	               decoder can reach, up to a fourth history
//
// Each adds stageOverhead. For an input Decode refuses from its header before
// reserving, a brotli body that is empty, carries the large-window marker or
// declares a window over the bound, Workspace is 0.
func Workspace(c Coding, input []byte, bound int) int64 {
	workspace, _ := plan(c, input, bound)
	return workspace
}

// plan is Workspace, and how many bytes of the input it read.
func plan(c Coding, input []byte, bound int) (workspace int64, read int) {
	bound = clampBound(bound)
	switch c {
	case Gzip, Deflate:
		return flateFixed + flateLinks + stageOverhead, 0
	case Brotli:
		if len(input) == 0 {
			return 0, 0
		}
		bits, large := brotliWindowBits(input[0])
		if large || 1<<bits-16 > max(bound, brotliSmallestWindow) {
			return 0, 1
		}
		return brotliFixed + 2*brotliTrees + brotliMaps + brotliRingHeld(brotliRing(bits)) + stageOverhead, 1
	case Zstd:
		history, read := zstdPlan(input, zstdWindow(bound))
		return zstdFixed + history + 2*zstdBlockBuffers + stageOverhead, read
	}
	return 0, 0
}

// WorkspaceCeiling is the most Workspace returns for the coding under bound,
// whatever the input: for br the largest ring the bound admits, and for zstd
// twice the largest history any window the bound admits takes.
func WorkspaceCeiling(c Coding, bound int) int64 {
	bound = clampBound(bound)
	switch c {
	case Gzip, Deflate:
		return flateFixed + flateLinks + stageOverhead
	case Brotli:
		return brotliFixed + 2*brotliTrees + brotliMaps + brotliRingHeld(brotliLargestRing(bound)) + stageOverhead
	case Zstd:
		return zstdFixed + 2*allocated(zstdHistoryEnvelope(zstdWindow(bound))) + 2*zstdBlockBuffers + stageOverhead
	}
	return 0
}

// Allocation is what one stage allocates in total, garbage included, mechanism
// by mechanism. A term that does not apply to a coding is zero.
type Allocation struct {
	// Decoder is the decoder's state, tables and buffers at their first sizes,
	// and stageOverhead.
	Decoder int64
	// Output is the stage's output buffers, every capacity up to bound + 1.
	Output int64
	// LinkTables is flate's Huffman link tables, regrown as its codes lengthen.
	LinkTables int64
	// Ring is brotli's ring buffer, doubled up to the largest window admitted.
	Ring int64
	// Trees is brotli's tree groups: one growth the stream may never pay for,
	// and every other, which reads its trees from the input.
	Trees int64
	// ContextMaps is brotli's context maps and modes, made once for the
	// Reader at their largest.
	ContextMaps int64
	// History is zstd's history, made at most zstdHistoryAllocations times,
	// each at most the largest any admitted window takes.
	History int64
	// Blocks is zstd's block buffers regrown: the decoded-block buffer for
	// windows below a block, the literals, sequences and run-length buffers as
	// the output pays, and the compressed data as the input pays.
	Blocks int64
	// PoolMisses is zstd's tables and skip buffers taken again from pools a
	// garbage collection emptied.
	PoolMisses int64
}

// Total is the sum of the terms.
func (a Allocation) Total() int64 {
	return a.Decoder + a.Output + a.LinkTables + a.Ring + a.Trees + a.ContextMaps + a.History + a.Blocks + a.PoolMisses
}

// StageAllocation bounds what one stage of the coding allocates in total over
// an input of inputLen bytes under bound B, by mechanism:
//
//	gzip, deflate  the decoder, and every link-table growth: about 4.6 MB,
//	               whatever B and L
//	br             the decoder; every ring size up to the largest admitted
//	               window; the tree groups, 2.7 MB unpaid and 3125 bytes per
//	               input byte, never more than every growth they can make; the
//	               context maps, 22 KB once
//	zstd           the decoder and its block buffers once; the history at most
//	               three times, each at most what a window of W = max(B, 1024)
//	               takes, about 27 MiB at an 8 MiB bound; the block buffers'
//	               regrowth, about 14(B+1) and 10 bytes per input byte; the
//	               pool misses, 5600 bytes per input byte
//
// Each has its output's growth, about 2.5(B+1).
func StageAllocation(c Coding, bound, inputLen int) Allocation {
	bound = clampBound(bound)
	b := int64(bound)
	l := int64(max(inputLen, 0))
	a := Allocation{Output: outputGrowth(b)}
	switch c {
	case Gzip, Deflate:
		a.Decoder = flateFixed + stageOverhead
		a.LinkTables = flateLinkGrowth
	case Brotli:
		a.Decoder = brotliFixed + stageOverhead
		a.Ring = brotliRingGrowth(brotliLargestRing(bound))
		a.Trees = brotliTrees + min(brotliTreeGrowth, brotliTreeBytesPerInputByte*l)
		a.ContextMaps = brotliMaps
	case Zstd:
		window := zstdWindow(bound)
		// Paid for by output: each buffer grows only, each growth by output at
		// least its size before the next, so there are at most sqrt(2(B+1)) + 1
		// of each, every one a size class at most 40 bytes over. The literals
		// (1.25), the sequences, 24 bytes for at least 3 bytes of output (10),
		// the run-length block (1.25) and a single-segment frame's
		// decoded-block buffer (1.25) make 13.75.
		growths := isqrt(2*(b+1)) + 1
		a.Decoder = zstdFixed + zstdBlockBuffers + stageOverhead
		a.History = zstdHistoryAllocations * allocated(zstdHistoryEnvelope(window))
		a.Blocks = zstdWindowGrowth(window) + 14*(b+1) + 4*40*growths + zstdBlockDataBytesPerInputByte*l
		a.PoolMisses = zstdPoolBytesPerInputByte * l
	default:
		return Allocation{}
	}
	return a
}

// Cumulative is A(coding, B): what one Decode of the coding allocates in
// total, garbage included, under bound B, over an encoded body of at most B
// bytes, which the capture's own body bound ensures. It is StageAllocation at
// the worst admissible input length, B, and DecodeOverhead. StageAllocation at
// the body's actual length is a tighter bound for a given body.
func Cumulative(c Coding, bound int) int64 {
	a := StageAllocation(c, bound, clampBound(bound))
	if a == (Allocation{}) {
		return 0
	}
	return decodeOverhead + a.Total()
}

// Charges is the ceiling on what the Reserver holds for one Decode of the
// coding at once, with n = bound + 1: the output while it grows, the new
// buffer, at most n, and the one it replaces, at most ceil(n/2); and the
// workspace, at most WorkspaceCeiling. A decode's actual charges use the
// Workspace it planned, which is at most that.
func Charges(c Coding, bound int) int64 {
	workspace := WorkspaceCeiling(c, bound)
	if workspace == 0 {
		return 0
	}
	n := int64(clampBound(bound)) + 1
	return n + (n+1)/2 + workspace
}

// Peak is the ceiling on the simultaneous owned peak of one Decode, with
// n = bound + 1: L + n + ceil(n/2) + the workspace, the encoded input of L
// bytes being charged by the caller and the rest by Charges.
func Peak(c Coding, bound, encodedLen int) int64 {
	return int64(max(encodedLen, 0)) + Charges(c, bound)
}
