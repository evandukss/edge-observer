package http1_test

import (
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/stream"
)

type parserDeliveryReserve struct{}

func (parserDeliveryReserve) Reserve(http1.Charge) bool { return true }
func (parserDeliveryReserve) Release(http1.Charge)      {}

func parserDeliveryNew(t *testing.T, kind http1.Kind) *http1.Parser {
	t.Helper()
	p, err := http1.NewParser(kind, http1.Limits{}, parserDeliveryReserve{})
	if err != nil || p == nil {
		t.Fatalf("wiring, not the property: parser construction: %v", err)
	}
	return p
}

func parserDeliveryFeed(t *testing.T, p *http1.Parser, text string) http1.Progress {
	t.Helper()
	offset, _ := p.Next()
	got, err := p.Feed(stream.Part{Offset: offset, Length: uint64(len(text)), Bytes: []byte(text)})
	if err != nil {
		t.Fatalf("wiring, not the property: valid bytes refused: %v", err)
	}
	return got
}

func TestParserDeliveryResumesNeedInput(t *testing.T) {
	p := parserDeliveryNew(t, http1.Request)
	first := parserDeliveryFeed(t, p, "POST /resume HTTP/1.1\r\nContent-Len")
	if first.Result != http1.NeedInput || first.Message != nil {
		t.Fatalf("partial header returned %+v", first)
	}
	head := parserDeliveryFeed(t, p, "gth: 3\r\n\r\n")
	if head.Result != http1.Head || head.Message == nil || head.Message.Target != "/resume" {
		t.Fatalf("resumed header did not hand over its head: %+v", head)
	}
	if partial := parserDeliveryFeed(t, p, "ab"); partial.Result != http1.NeedInput || partial.Message != nil {
		t.Fatalf("partial body returned %+v", partial)
	}
	end := parserDeliveryFeed(t, p, "c")
	if end.Result != http1.Framed || end.Message == nil || string(end.Message.Body) != "abc" || !end.Message.Complete {
		t.Fatalf("body did not resume to a complete message: %+v", end)
	}
}

func TestParserDeliveryPartialConsumptionAndIdleAnswer(t *testing.T) {
	p := parserDeliveryNew(t, http1.Response)
	head := "HTTP/1.1 200 OK\r\nContent-Length: 900\r\n\r\n"
	tail := "HTTP/1.1 204 No Content\r\n\r\n"
	first := parserDeliveryFeed(t, p, head+tail)
	if first.Result != http1.Head || first.Consumed != uint64(len(head)) {
		t.Fatalf("response head consumed %d, result %s; want %d and head", first.Consumed, first.Result, len(head))
	}
	answer, err := p.Answer("HEAD")
	if err != nil || answer.Result != http1.Framed || answer.Message == nil || len(answer.Message.Body) != 0 {
		t.Fatalf("HEAD answer stranded a complete response until new input: %+v, %v", answer, err)
	}
	second := parserDeliveryFeed(t, p, tail)
	if second.Result != http1.Head || second.Consumed != uint64(len(tail)) {
		t.Fatalf("next status line lost after partial consumption: %+v", second)
	}
	answer, err = p.Answer("GET")
	if err != nil || answer.Result != http1.Framed || answer.Message == nil || answer.Message.Status != 204 {
		t.Fatalf("bodyless final response stranded at idle: %+v, %v", answer, err)
	}
}

func TestParserDeliveryMalformedCutAndEndAreDistinct(t *testing.T) {
	t.Run("malformed", func(t *testing.T) {
		p := parserDeliveryNew(t, http1.Request)
		got := parserDeliveryFeed(t, p, "GET / HTTP/1.1\r\nnot-a-field\r\n\r\n")
		if got.Result != http1.Malformed {
			t.Fatalf("malformed header returned %s", got.Result)
		}
	})
	t.Run("cut", func(t *testing.T) {
		p := parserDeliveryNew(t, http1.Request)
		parserDeliveryFeed(t, p, "GET / HTTP/1.1\r\nX-Field: ")
		offset, _ := p.Next()
		got, err := p.Feed(stream.Part{Offset: offset, Length: 3, Gap: stream.GapMissing})
		if err != nil {
			t.Fatalf("wiring, not the property: hole refused: %v", err)
		}
		if got.Result != http1.Cut {
			t.Fatalf("structural hole returned %s", got.Result)
		}
		later := parserDeliveryFeed(t, p, "GET /must-not-scan HTTP/1.1\r\n\r\n")
		if later.Result != http1.Cut || later.Message != nil || p.Unplaced() == 0 {
			t.Fatalf("parser scanned beyond a hole: %+v, unplaced %d", later, p.Unplaced())
		}
	})
	t.Run("end", func(t *testing.T) {
		p := parserDeliveryNew(t, http1.Request)
		parserDeliveryFeed(t, p, "GET /unfinished HTTP/1.1\r\nX-Field: ")
		got := p.End()
		if got.Result != http1.End || got.Message == nil || got.Message.Complete || got.Message.Defect != http1.DefectStreamEnded {
			t.Fatalf("end did not hand over the unfinished message: %+v", got)
		}
	})
}

func TestParserDeliveryWorkDoesNotRescanGrowingPrefix(t *testing.T) {
	p := parserDeliveryNew(t, http1.Request)
	parserDeliveryFeed(t, p, "GET /linear HTTP/1.1\r\nX-Long: ")
	start := http1.Examined(p)
	for range 256 {
		got := parserDeliveryFeed(t, p, strings.Repeat("x", 16))
		if got.Result != http1.NeedInput {
			t.Fatalf("growing header stopped: %s", got.Result)
		}
	}
	work := http1.Examined(p) - start
	if work == 0 || work > 4*4096 {
		t.Errorf("4096 new header bytes cost %d examined bytes; want positive linear work <= %d", work, 4*4096)
	}
	got := parserDeliveryFeed(t, p, "\r\n\r\n")
	if got.Result != http1.Framed || got.Message == nil || got.Message.Target != "/linear" {
		t.Fatalf("growing header did not finish: %+v", got)
	}
}
