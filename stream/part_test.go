package stream_test

import (
	"errors"
	"math"
	"testing"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/stream"
)

func TestAPartThatBreaksAnyOfItsRulesIsRefused(t *testing.T) {
	cases := map[string]stream.Part{
		"no offsets":                {Offset: 4, Length: 0, Bytes: []byte{}},
		"a gap with no name":        {Offset: 4, Length: 2, Gap: stream.GapTruncated + 1},
		"fewer bytes than offsets":  {Offset: 4, Length: 3, Bytes: []byte("ab")},
		"more bytes than offsets":   {Offset: 4, Length: 1, Bytes: []byte("ab")},
		"a hole carrying bytes":     {Offset: 4, Length: 2, Gap: stream.GapMissing, Bytes: []byte("ab")},
		"past the last offset":      {Offset: math.MaxUint64 - 1, Length: 2, Bytes: []byte("ab")},
		"a truncation with payload": {Offset: 4, Length: 1, Gap: stream.GapTruncated, Bytes: []byte("a")},
	}
	for name, part := range cases {
		t.Run(name, func(t *testing.T) {
			if err := part.Validate(); !errors.Is(err, stream.ErrInvalidPart) {
				t.Fatalf("Validate = %v, want an error wrapping %v", err, stream.ErrInvalidPart)
			}
		})
	}
}

// The control for the case above: what Assemble produces, bytes and both kinds
// of hole, and the last offset a part can reach, all pass.
func TestEveryPartAssembleProducesPassesItsRules(t *testing.T) {
	s := single(t,
		record(fragment.Sent, 0, 0, "GET /one"),
		truncated(fragment.Sent, 1, 8, " HT", 9),
		record(fragment.Sent, 2, 30, "\r\n"),
	)
	gaps := map[stream.GapReason]int{}
	for _, part := range s.Parts {
		gaps[part.Gap]++
		if err := part.Validate(); err != nil {
			t.Errorf("part at %d (%s, %d offsets): %v", part.Offset, part.Gap, part.Length, err)
		}
	}
	if gaps[stream.GapNone] == 0 || gaps[stream.GapTruncated] == 0 || gaps[stream.GapMissing] == 0 {
		t.Fatalf("wiring, not the property: the stream holds %v, and the case needs bytes and both kinds of hole", gaps)
	}

	last := stream.Part{Offset: math.MaxUint64 - 2, Length: 2, Bytes: []byte("ab")}
	if err := last.Validate(); err != nil {
		t.Errorf("a part ending on the last offset: %v", err)
	}
}
