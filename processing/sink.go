package processing

import (
	"context"
	"github.com/evandukss/edge-observer/sink"
	"io/fs"
)

const DefaultQueueBytes int64 = 8 << 20

// WriterOptions configures stable paths and a bound on retained encoded bytes,
// never on total output. OpenSink defaults to sink.NewFile.
type WriterOptions struct {
	Directory  string
	QueueBytes int64
	OpenSink   sink.Factory
}

func OpenWriter(options WriterOptions) (*Writer, error) { return nil, ErrNotImplemented }
func (w *Writer) DeliveryStats() sink.Stats             { return sink.Stats{} }
func (w *Writer) DerivedStats(name string) sink.Stats   { return sink.Stats{} }
func (w *Writer) Reopen(ctx context.Context) error      { return ErrNotImplemented }
func (w *Writer) Drain(ctx context.Context) error       { return ErrNotImplemented }
func (w *Writer) Shutdown(ctx context.Context) error    { return ErrNotImplemented }

// ReadArtifactFiles reads the explicitly named files, in order, selecting only
// the named session (empty means all). It makes no continuity claim between files.
// Malformed records fail even when their session cannot be established.
func ReadArtifactFiles(files fs.FS, names []string, session string, visit func(Artifact) error) error {
	return ErrNotImplemented
}
