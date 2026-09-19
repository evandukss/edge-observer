package reconstruct_test

import (
	"testing"

	"github.com/evandukss/edge-observer/reconstruct"
)

func pipelineSeeds(f *testing.F) {
	f.Helper()

	f.Add([]byte(response), []byte(request), uint8(0))
	f.Add([]byte(request), []byte(response), uint8(1))
	f.Add([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{}\n\r\n0\r\n\r\n"), []byte(request), uint8(3))
	f.Add([]byte{}, []byte{}, uint8(0))
	f.Add([]byte("\x00\x01"), []byte("\xff\xfe"), uint8(7))
}

// FuzzRunReadsOneConnectionTheSameWhereverTheCallsFell: one pair of byte
// streams split at different call boundaries reconstructs identically, and
// never crashes, hangs or exceeds its bounds.
func FuzzRunReadsOneConnectionTheSameWhereverTheCallsFell(f *testing.F) {
	pipelineSeeds(f)

	f.Fuzz(func(t *testing.T, sent, received []byte, size uint8) {
		// One record per byte at the smallest size: keep inputs small so the
		// fuzzer measures the pipeline, not this harness.
		if len(sent)+len(received) > 2048 {
			return
		}

		whole := reconstruct.Run(exchange(1, 0, string(sent), string(received)), reconstruct.DefaultLimits())
		split := reconstruct.Run(exchange(1, int(size), string(sent), string(received)), reconstruct.DefaultLimits())

		if whole.String() != split.String() {
			t.Fatalf("fragments of %d bytes reconstructed differently:\n%s\nagainst\n%s",
				size, split.String(), whole.String())
		}
		if again := reconstruct.Run(exchange(1, 0, string(sent), string(received)), reconstruct.DefaultLimits()); again.String() != whole.String() {
			t.Fatal("two reconstructions of one capture differ")
		}

		// One connection in, at most one out; one with no exchanges says so.
		if len(whole.Connections) > 1 {
			t.Fatalf("%d connections from one", len(whole.Connections))
		}
		for _, connection := range whole.Connections {
			if connection.Role == reconstruct.RoleUnknown && len(connection.Exchanges) != 0 {
				t.Fatalf("a connection of unknown side holds %d exchanges", len(connection.Exchanges))
			}
			for i, e := range connection.Exchanges {
				if e.Complete && (e.Request == nil || e.Response == nil) {
					t.Fatalf("exchange %d is complete with a side missing", i)
				}
				if e.Request == nil && e.Response == nil {
					t.Fatalf("exchange %d has neither side", i)
				}
			}
		}
	})
}
