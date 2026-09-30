package processing_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/evandukss/edge-observer/processing"
)

func TestWriterSharesEncodedAllowanceAcrossRecordTypes(t *testing.T) {
	plan := rulesPlan(t, `"remove": {"headers": ["authorization"]}`)
	b := batch(t, 1, "GET / HTTP/1.1\r\nAuthorization: protected-value\r\nX-Public: original\r\n\r\n", goodResponse)
	var reference outputLog
	w, store := worker(t, plan, &reference)
	enqueue(t, store, b)
	if o := drain(t, w); o.Written != 2 || len(reference.lines) != 2 {
		t.Fatalf("both record types must reach output: %+v", o)
	}
	all := append(append([]byte{}, reference.lines[0]...), reference.lines[1]...)
	if bytes.Contains(all, []byte("protected-value")) || !bytes.Contains(all, []byte("original")) {
		t.Fatal("reference is not sanitized useful output")
	}
	for _, delta := range []int64{0, -1} {
		t.Run(map[int64]string{0: "exact", -1: "one-byte-short"}[delta], func(t *testing.T) {
			dir := t.TempDir()
			limit := int64(len(all)) + delta
			writer, err := processing.Open(dir, limit)
			if err != nil || writer == nil {
				t.Fatalf("writer construction: %v", err)
			}
			t.Cleanup(func() { _ = writer.Close() })
			w, store := worker(t, plan, writer)
			enqueue(t, store, b)
			o, err := w.Drain(context.Background())
			want := all
			if delta == 0 {
				if err != nil || o.Written != 2 {
					t.Fatalf("exact bound control: %+v %v", o, err)
				}
			} else {
				want = reference.lines[0]
				if !errors.Is(err, processing.ErrOutputLimit) || o.Written != 1 || o.OutputFailures != 1 {
					t.Fatalf("aggregate fault not reached: %+v %v", o, err)
				}
				select {
				case <-writer.Exhausted():
				default:
					t.Fatal("limit did not signal")
				}
				_, _ = w.Drain(context.Background())
			}
			stored, err := os.ReadFile(filepath.Join(dir, processing.ArtifactName))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stored, want) {
				t.Fatalf("whole-record allowance: stored %d bytes want %d", len(stored), len(want))
			}
			st := writer.Stats()
			if st.Bytes != int64(len(want)) || st.Bytes > limit || st.LimitBytes != limit || st.Exhausted != (delta < 0) {
				t.Fatalf("storage accounting: %+v", st)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 || entries[0].Name() != processing.ArtifactName {
				t.Fatalf("unexpected output files: %v %v", entries, err)
			}
		})
	}
}

func TestWriterRequiresFreshFileAndRefusesUnapprovedValue(t *testing.T) {
	dir := t.TempDir()
	w, err := processing.Open(dir, 1<<20)
	if err != nil || w == nil {
		t.Fatalf("fresh file control: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	if again, err := processing.Open(dir, 1<<20); err == nil || again != nil {
		t.Fatal("existing artifact reopened")
	}
	if err := w.WriteApproved(context.Background(), processing.Approved{}); !errors.Is(err, processing.ErrUnapproved) {
		t.Fatalf("forged zero approval: %v", err)
	}
	st := w.Stats()
	if st.Bytes != 0 || st.Written != 0 {
		t.Fatalf("unapproved value reached disk: %+v", st)
	}
	info, err := os.Stat(filepath.Join(dir, processing.ArtifactName))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("artifact permissions: %v %v", info, err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestApprovedBytesCannotChangeAuthorizedLine(t *testing.T) {
	dir := t.TempDir()
	writer, err := processing.Open(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	var expected []byte
	output := outputFunc(func(ctx context.Context, a processing.Approved) error {
		// Every approved line, in the order written: the exchange, then the
		// connection's record.
		expected = append(expected, a.Bytes()...)
		copy := a.Bytes()
		if len(copy) == 0 {
			t.Fatal("approved line missing")
		}
		copy[0] = '!'
		return writer.WriteApproved(ctx, a)
	})
	w, store := worker(t, rulesPlan(t, ""), output)
	enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
	if o := drain(t, w); o.Written != 2 {
		t.Fatalf("write control, the exchange and the connection's record: %+v", o)
	}
	stored, err := os.ReadFile(filepath.Join(dir, processing.ArtifactName))
	if err != nil || len(expected) == 0 || !bytes.Equal(stored, expected) {
		t.Fatalf("caller mutated approved output: %v", err)
	}
}
