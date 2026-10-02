package sink

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type fileSink struct {
	path     string
	file     *os.File
	boundary chan struct{}
	dirty    bool
}

func newFile(path string) Sink {
	f := &fileSink{path: path, boundary: make(chan struct{}, 1)}
	// Initial open also belongs to the I/O side. Writes wait at this boundary;
	// a filesystem stalled in open cannot hold activation or admission.
	f.boundary <- struct{}{}
	go func() { defer func() { <-f.boundary }(); _ = f.replace() }()
	return f
}
func (f *fileSink) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case f.boundary <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (f *fileSink) Write(ctx context.Context, line []byte) (int, error) {
	if err := f.lock(ctx); err != nil {
		return 0, err
	}
	defer func() { <-f.boundary }()
	if f.file == nil {
		return 0, errors.New("sink unavailable")
	}
	if f.dirty {
		n, err := f.file.Write([]byte{'\n'})
		if err != nil {
			return 0, err
		}
		if n != 1 {
			return 0, io.ErrShortWrite
		}
		f.dirty = false
	}
	n, err := f.file.Write(line)
	if err != nil || n != len(line) {
		if err == nil {
			err = io.ErrShortWrite
		}
	}
	return n, err
}
func (f *fileSink) Reopen(ctx context.Context) error {
	if err := f.lock(ctx); err != nil {
		return err
	}
	defer func() { <-f.boundary }()
	return f.replace()
}
func (f *fileSink) replace() error {
	if err := os.MkdirAll(filepath.Dir(f.path), 0700); err != nil {
		return err
	}
	next, err := os.OpenFile(f.path, os.O_CREATE|os.O_RDWR|os.O_APPEND|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	info, err := next.Stat()
	if err != nil {
		_ = next.Close()
		return err
	}
	dirty := false
	if info.Mode().IsRegular() && info.Size() > 0 {
		var last [1]byte
		if _, err := next.ReadAt(last[:], info.Size()-1); err != nil {
			_ = next.Close()
			return err
		}
		dirty = last[0] != '\n'
	}
	old := f.file
	f.file = next
	f.dirty = dirty
	if old != nil {
		return old.Close()
	}
	return nil
}
func (f *fileSink) Close(ctx context.Context) error {
	if err := f.lock(ctx); err != nil {
		return err
	}
	defer func() { <-f.boundary }()
	if f.file == nil {
		return nil
	}
	old := f.file
	f.file = nil
	return old.Close()
}
