package processing

import (
	"context"
	"errors"
	"github.com/evandukss/edge-observer/sink"
	"io/fs"
	"path/filepath"
)

const DefaultQueueBytes int64 = 8 << 20

// WriterOptions configures stable paths and a bound on retained encoded bytes,
// never on total output. OpenSink defaults to sink.NewFile.
type WriterOptions struct {
	Directory  string
	QueueBytes int64
	OpenSink   sink.Factory
}

func OpenWriter(options WriterOptions) (*Writer, error) {
	if options.Directory == "" || options.QueueBytes < 0 {
		return nil, ErrOptions
	}
	if options.QueueBytes == 0 {
		options.QueueBytes = DefaultQueueBytes
	}
	if options.OpenSink == nil {
		options.OpenSink = sink.NewFile
	}
	q, err := sink.NewQueue(options.QueueBytes)
	if err != nil {
		return nil, err
	}
	w := &Writer{directory: options.Directory, queue: q, factory: options.OpenSink}
	if err = q.Register(ArtifactName, w.factory(filepath.Join(w.directory, ArtifactName))); err != nil {
		_ = q.Shutdown(context.Background())
		return nil, err
	}
	return w, nil
}
func (w *Writer) DeliveryStats() sink.Stats {
	if w == nil || w.queue == nil {
		return sink.Stats{}
	}
	return w.queue.DestinationStats(ArtifactName)
}
func (w *Writer) DerivedStats(name string) sink.Stats {
	if w == nil || w.queue == nil {
		return sink.Stats{}
	}
	return w.queue.DestinationStats(DerivedName(name))
}
func (w *Writer) Reopen(ctx context.Context) error { return w.queue.Reopen(ctx) }
func (w *Writer) Drain(ctx context.Context) error  { return w.queue.Drain(ctx) }
func (w *Writer) Shutdown(ctx context.Context) error {
	if w == nil {
		return nil
	}
	w.mutex.Lock()
	w.closed = true
	w.mutex.Unlock()
	return w.queue.Shutdown(ctx)
}

// ReadArtifactFiles reads the explicitly named files, in order, selecting only
// the named session (empty means all). It makes no continuity claim between files.
// Malformed records fail even when their session cannot be established.
func ReadArtifactFiles(files fs.FS, names []string, session string, visit func(Artifact) error) error {
	if files == nil || visit == nil || len(names) == 0 {
		return errors.New("approved reader requires files and visitor")
	}
	count := 0
	for _, name := range names {
		n, err := readArtifactFile(files, name, session, visit)
		count += n
		if err != nil {
			return err
		}
	}
	if count == 0 {
		return ErrNoArtifacts
	}
	return nil
}
