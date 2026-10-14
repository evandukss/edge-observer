package contentcoding

// The brotli work budget. Brotli costs work its output does not bound: a stream
// can make the decoder read context maps and build prefix-code tables for every
// few bytes it carries while it produces almost nothing. So a brotli stage
// counts its work W, and before each operation of cost q it requires
//
//	W + q <= BrotliWorkBase + BrotliWorkPerByte * D, and W + q <= the ceiling
//
// where D is the bytes the decoder has produced so far, and the ceiling is a
// fixed limit that no credit raises. The ceiling bounds the work counted, not
// the time a decode takes, and no time is promised.
//
//   - The credit comes only from bytes produced: never from a length a
//     metablock declares, and never from how the caller reads the output, so
//     the same stream ends the same way whatever its reads' sizes.
//   - Work is charged once, whichever read it falls in, and counted from zero
//     for each Decode.
//   - The check comes before the work it guards, and a sum that would overflow
//     fails it. An operation that would exceed the budget is not done, and the
//     stage ends DecodingTooCostly with nothing returned.
//   - What the stage established before the check stays established: the output
//     stop at bound + 1 bytes, and every size and integrity result.
//
// W counts entries written or read, each step at the most it can take: a
// prefix code's table at the largest size its alphabet allows, with the
// code-length code's table and a length per symbol for a code sent as code
// lengths; each context-map and context-mode entry, cleared and then written;
// a map's entries again to undo its move-to-front coding, with each place the
// list moves, and the literal map's to find trivial block types; the tree
// groups' tables when a metablock lays them out; and the entries cleared at
// each metablock's start and end. This is the supported limit for brotli: a
// stream that needs more work than the budget allows is not decoded, whatever
// a decoder without one would make of it.
const (
	// BrotliWorkBase is C, the work any brotli stream may do before it has
	// produced anything.
	BrotliWorkBase = 1 << 22
	// BrotliWorkPerByte is k, the work each byte produced allows.
	BrotliWorkPerByte = 1024
)

// brotliWorkCeiling is the most work a brotli stage may do, whatever its output
// has earned.
const brotliWorkCeiling = 1 << 30

// workBudget is the budget a brotli stage runs within: base and perByte are
// BrotliWorkBase and BrotliWorkPerByte, most the ceiling.
type workBudget struct{ base, perByte, most uint64 }
