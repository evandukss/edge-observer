package sink

import (
	"bytes"
	"context"
	"errors"
	"io"
)

// WriteFinal attempts one terminal line per destination after Freeze and before
// Shutdown closes resources. It never changes delivery statistics or reopens
// admission. Its line is bounded by the queue's byte limit independently of
// ordinary pending bytes. Retained includes it while I/O holds it. A blocked
// write may outlive ctx, but a canceled wait cannot start a later write.
func (q *Queue) WriteFinal(ctx context.Context, name string, line []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if q == nil || q.state == nil {
		return ErrClosed
	}
	st := q.state
	st.mutex.Lock()
	d := st.destinations[name]
	if d == nil || st.frozen == nil || st.closing || d.final {
		st.mutex.Unlock()
		return ErrClosed
	}
	if len(line) == 0 || line[len(line)-1] != '\n' {
		st.mutex.Unlock()
		return errors.New("sink requires a complete line")
	}
	if int64(len(line)) > st.stats.LimitBytes {
		st.mutex.Unlock()
		return ErrQueueFull
	}
	d.final = true
	st.mutex.Unlock()
	select {
	case d.boundary <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	st.mutex.Lock()
	if st.closing || ctx.Err() != nil {
		st.mutex.Unlock()
		<-d.boundary
		if err := ctx.Err(); err != nil {
			return err
		}
		return ErrClosed
	}
	owned := bytes.Clone(line)
	d.finalLine = owned
	st.mutex.Unlock()
	done := make(chan error, 1)
	go func() {
		defer func() {
			st.mutex.Lock()
			d.finalLine = nil
			st.mutex.Unlock()
			<-d.boundary
		}()
		_, err := d.writeLine(ctx, owned)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// writeLine runs only while the caller owns the destination boundary.
func (d *destination) writeLine(ctx context.Context, line []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if d.dirty {
		n, err := d.sink.Write(ctx, []byte{'\n'})
		if err == nil && n != 1 {
			err = io.ErrShortWrite
		}
		if err != nil {
			return 0, err
		}
		d.dirty = false
	}
	// Repair can itself block, so cancellation is checked again before the line.
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n, err := d.sink.Write(ctx, line)
	if n < 0 || n > len(line) {
		n, err = 0, io.ErrShortWrite
	}
	if n != len(line) && err == nil {
		err = io.ErrShortWrite
	}
	if n > 0 {
		d.dirty = line[n-1] != '\n'
	}
	return n, err
}
