package processing_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/evandukss/edge-observer/processing"
)

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
	if err := writer.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(dir, processing.ArtifactName))
	if err != nil || len(expected) == 0 || !bytes.Equal(stored, expected) {
		t.Fatalf("caller mutated approved output: %v", err)
	}
}
