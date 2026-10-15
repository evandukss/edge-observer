package sink

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// NewStream wraps a borrowed writer without closing it. For an os.File it owns
// a close-on-exec duplicate above descriptors 0, 1 and 2: a closed pipe then
// reports EPIPE rather than triggering Go's special SIGPIPE exit for stdout.
// Queue provides bounded admission and a caller deadline around blocked I/O.
func NewStream(out io.Writer) (Sink, error) {
	if out == nil {
		return nil, errors.New("stream destination is nil")
	}
	s := &streamSink{out: out, boundary: make(chan struct{}, 1)}
	if file, ok := out.(*os.File); ok {
		if file == nil {
			return nil, errors.New("stream file is nil")
		}
		fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			return nil, err
		}
		s.owned = os.NewFile(uintptr(fd), file.Name())
		s.out = s.owned
	}
	return s, nil
}

type streamSink struct {
	out      io.Writer
	owned    *os.File
	boundary chan struct{}
}

func (s *streamSink) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.boundary <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-s.boundary
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *streamSink) Write(ctx context.Context, p []byte) (int, error) {
	if err := s.lock(ctx); err != nil {
		return 0, err
	}
	defer func() { <-s.boundary }()
	if s.out == nil {
		return 0, ErrClosed
	}
	return s.out.Write(p)
}

// A borrowed stream has no pathname to reopen.
func (*streamSink) Reopen(ctx context.Context) error { return ctx.Err() }

func (s *streamSink) Close(ctx context.Context) error {
	if err := s.lock(ctx); err != nil {
		return err
	}
	defer func() { <-s.boundary }()
	s.out = nil
	if s.owned == nil {
		return nil
	}
	file := s.owned
	s.owned = nil
	return file.Close()
}
