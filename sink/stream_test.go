package sink

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestStreamCloseKeepsBorrowedFileOpen(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	s, err := NewStream(w)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(context.Background(), []byte("mirror\n")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("borrowed\n")); err != nil {
		t.Fatalf("borrowed descriptor was closed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "mirror\nborrowed\n" {
		t.Fatalf("stream bytes %q: %v", got, err)
	}
}

func TestStreamClosedStdoutIsDeliveryError(t *testing.T) {
	if os.Getenv("OBSERVER_STREAM_TEST_CHILD") == "1" {
		s, err := NewStream(os.Stdout)
		if err != nil {
			os.Exit(41)
		}
		_, err = s.Write(context.Background(), []byte("{}\n"))
		if !errors.Is(err, syscall.EPIPE) {
			os.Exit(42)
		}
		if err := s.Close(context.Background()); err != nil {
			os.Exit(43)
		}
		os.Exit(0)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestStreamClosedStdoutIsDeliveryError$")
	command.Env = append(os.Environ(), "OBSERVER_STREAM_TEST_CHILD=1")
	command.Stdout = w
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			t.Fatalf("subprocess watchdog expired before delivery outcome: %v", ctx.Err())
		}
		t.Fatalf("closed fd1 ended process instead of reporting EPIPE: %v, %s", err, diagnostic.Bytes())
	}
}
