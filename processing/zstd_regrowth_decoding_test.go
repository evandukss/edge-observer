package processing_test

import "fmt"

// The shared zstd fixture builders for the repeated-message comparisons. The
// sequential comparison that first used them (its pre-limit records, comment
// 4006) is superseded on T12's final tip by the concurrent comparison in
// zstd_concurrent_decoding_test.go, which runs capture alongside the workers;
// only these builders remain, which that comparison uses (decision 586).

// zrFrame is one raw-literal zstd frame: magic, a frame-header descriptor of 0
// (a window descriptor follows, no content size, no checksum), the window
// descriptor byte, and a single last raw block of one byte 'a'. It decodes to
// "a". The window the descriptor names is 1<<(10+exp) + (1<<(10+exp))/8*mant,
// exp = descriptor>>3, mant = descriptor&7.
func zrFrame(descriptor byte) []byte {
	return []byte{0x28, 0xb5, 0x2f, 0xfd, 0, descriptor, 9, 0, 0, 'a'}
}

// zrBody is frames raw-literal frames concatenated. rising gives frame i the
// descriptor min(i, 104), so the windows climb to the 8 MiB the bound admits
// and the history regrows; a flat body gives every frame descriptor 0, the
// 1024-byte floor, so nothing regrows. Both decode to frames bytes of 'a'.
func zrBody(frames int, rising bool) []byte {
	var b []byte
	for i := 0; i < frames; i++ {
		d := byte(0)
		if rising {
			d = byte(min(i, 104))
		}
		b = append(b, zrFrame(d)...)
	}
	return b
}

// zrResponse is an HTTP/1.1 response with body as its Content-Length-framed
// body, under coding if coding is not empty.
func zrResponse(coding string, body []byte) []byte {
	h := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
	if coding != "" {
		h += "Content-Encoding: " + coding + "\r\n"
	}
	h += fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
	return append([]byte(h), body...)
}
