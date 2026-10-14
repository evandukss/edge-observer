package contentcoding

import (
	"encoding/binary"
	"hash/adler32"
	"hash/crc32"
	"io"

	"github.com/klauspost/compress/flate"
)

// The gzip member header (RFC 1952 section 2.3).
const (
	gzipID1, gzipID2, gzipDeflate = 0x1f, 0x8b, 8

	gzipHeaderCRC, gzipExtra, gzipName, gzipComment = 1 << 1, 1 << 2, 1 << 3, 1 << 4
	gzipReserved                                    = 0xe0
)

// gzipStage undoes gzip: one member after another until the input ends. The
// members are framed here rather than by a gzip package, so a header's extra
// field, name and comment are skipped where they lie and never copied, and the
// deflate decoder, its window and its tables are made once for every member.
// The decoder reads feed, which is in or reads it, and is closed when the
// members end unless its library faulted.
func gzipStage(in *input, feed io.Reader, out *output, lib *library) Outcome {
	var inflater io.ReadCloser
	outcome := gzipMembers(in, feed, out, lib, &inflater)
	if inflater != nil {
		lib.close(func() { _ = inflater.Close() })
	}
	return outcome
}

// gzipMembers decodes the members, making the decoder in *inflater for the
// first and resetting it for each after.
func gzipMembers(in *input, feed io.Reader, out *output, lib *library, inflater *io.ReadCloser) Outcome {
	for members := 0; ; members++ {
		if in.remaining() == 0 {
			if members == 0 {
				return DecodingFailed
			}
			return Decoded
		}
		if !gzipHeader(in) {
			return DecodingFailed
		}
		var err error
		if *inflater == nil {
			if !lib.call(operationMake, func() { *inflater = flate.NewReader(feed) }) {
				return DecodingFailed
			}
		} else if resetter := (*inflater).(flate.Resetter); !lib.call(operationReset, func() { err = resetter.Reset(feed, nil) }) || err != nil {
			return DecodingFailed
		}
		start := len(out.buf)
		if outcome, _ := out.fill(guarded{lib, *inflater}); outcome != Decoded {
			return outcome
		}
		trailer, ok := in.next(8)
		if !ok {
			return DecodingFailed
		}
		content := out.buf[start:]
		if binary.LittleEndian.Uint32(trailer[:4]) != crc32.ChecksumIEEE(content) ||
			binary.LittleEndian.Uint32(trailer[4:]) != uint32(len(content)) {
			return DecodingFailed
		}
	}
}

// gzipHeader reads one member header, and reports whether it is one.
func gzipHeader(in *input) bool {
	start := in.pos
	fixed, ok := in.next(10)
	if !ok || fixed[0] != gzipID1 || fixed[1] != gzipID2 || fixed[2] != gzipDeflate || fixed[3]&gzipReserved != 0 {
		return false
	}
	flags := fixed[3]
	if flags&gzipExtra != 0 {
		size, ok := in.next(2)
		if !ok {
			return false
		}
		if _, ok := in.next(int(binary.LittleEndian.Uint16(size))); !ok {
			return false
		}
	}
	for _, field := range [...]byte{gzipName, gzipComment} {
		if flags&field == 0 {
			continue
		}
		for {
			c, err := in.ReadByte()
			if err != nil {
				return false
			}
			if c == 0 {
				break
			}
		}
	}
	if flags&gzipHeaderCRC != 0 {
		sum := crc32.ChecksumIEEE(in.b[start:in.pos])
		stored, ok := in.next(2)
		if !ok || binary.LittleEndian.Uint16(stored) != uint16(sum) {
			return false
		}
	}
	return true
}

// zlibHeader reports whether two bytes are a zlib header (RFC 1950 section
// 2.2): CM 8, CINFO at most 7, and CMF*256 + FLG divisible by 31.
func zlibHeader(cmf, flg byte) bool {
	return cmf&0x0f == 8 && cmf>>4 <= 7 && (uint16(cmf)<<8|uint16(flg))%31 == 0
}

// zlibPresetDictionary is FLG's FDICT bit.
const zlibPresetDictionary = 0x20

// deflateStage undoes deflate: zlib when the header check holds, raw deflate
// otherwise, and in either case nothing may follow the stream. The decoder
// reads feed, which is in or reads it, and is closed once the stream ends
// unless its library faulted.
func deflateStage(in *input, feed io.Reader, out *output, lib *library) Outcome {
	b := in.b
	wrapped := len(b) >= 2 && zlibHeader(b[0], b[1])
	if wrapped {
		if b[1]&zlibPresetDictionary != 0 {
			return DecodingFailed
		}
		in.pos = 2
	}
	var inflater io.ReadCloser
	if !lib.call(operationMake, func() { inflater = flate.NewReader(feed) }) {
		return DecodingFailed
	}
	outcome, _ := out.fill(guarded{lib, inflater})
	lib.close(func() { _ = inflater.Close() })
	if outcome != Decoded {
		return outcome
	}
	if wrapped {
		trailer, ok := in.next(4)
		if !ok || binary.BigEndian.Uint32(trailer) != adler32.Checksum(out.buf) {
			return DecodingFailed
		}
	}
	if in.remaining() != 0 {
		return DecodingFailed
	}
	return Decoded
}
