package processing

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/sink"
)

type mirroredLines struct {
	mutex sync.Mutex
	bytes.Buffer
}

func (m *mirroredLines) Write(_ context.Context, p []byte) (int, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.Buffer.Write(p)
}
func (*mirroredLines) Close(context.Context) error  { return nil }
func (*mirroredLines) Reopen(context.Context) error { return nil }

func TestWriterMirrorsReleasedLinesWithSeparateAccounting(t *testing.T) {
	file, stdout := &mirroredLines{}, &mirroredLines{}
	w, err := OpenWriter(WriterOptions{Directory: t.TempDir(), OpenSink: func(string) sink.Sink { return file }, Stdout: stdout})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	defer func() { _ = w.Shutdown(ctx) }()
	for _, line := range []string{"{\"record\":\"exchange\"}\n", "{\"record\":\"connection\"}\n"} {
		if err := w.WriteApproved(ctx, Approved{line: []byte(line)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if a, b := w.DeliveryStats(), w.StdoutDeliveryStats(); b == nil || a.Written != 2 || b.Written != 2 || a.Authorized != b.Authorized {
		t.Fatalf("mirror accounting: file %+v stdout %+v", a, b)
	}
	file.mutex.Lock()
	stdout.mutex.Lock()
	if file.String() != stdout.String() {
		t.Error("mirror bytes differ from approved file")
	}
	stdout.mutex.Unlock()
	file.mutex.Unlock()
	w.Freeze()
	before := *w.StdoutDeliveryStats()
	if err := w.WriteApproved(ctx, Approved{line: []byte("{}\n")}); err == nil {
		t.Error("frozen writer accepted output")
	}
	if *w.StdoutDeliveryStats() != before {
		t.Error("frozen mirror accounting changed")
	}
}
