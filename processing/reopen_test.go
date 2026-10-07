package processing

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWriterReopensApprovedAndDerivedFilesAfterRename(t *testing.T) {
	root := t.TempDir()
	w, err := OpenWriter(WriterOptions{Directory: root})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	derived, err := w.openDerived("inventory")
	if err != nil {
		t.Fatal(err)
	}
	// These sentinels measure byte routing, not artifact or extension validation.
	for _, session := range []string{"before", "after"} {
		line := []byte("{\"session\":\"" + session + "\"}\n")
		if err := w.WriteApproved(context.Background(), Approved{line: line}); err != nil {
			t.Fatal(err)
		}
		if reason := w.writeDerived(derived, line); reason != "" {
			t.Fatalf("derived enqueue: %s", reason)
		}
		if err := w.Drain(context.Background()); err != nil {
			t.Fatal(err)
		}
		if session == "before" {
			for _, name := range []string{ArtifactName, DerivedName("inventory")} {
				if err := os.Rename(filepath.Join(root, name), filepath.Join(root, name+".1")); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Reopen(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, name := range []string{ArtifactName, DerivedName("inventory")} {
		old, err := os.ReadFile(filepath.Join(root, name+".1"))
		if err != nil {
			t.Fatal(err)
		}
		current, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(old) != "{\"session\":\"before\"}\n" || string(current) != "{\"session\":\"after\"}\n" {
			t.Fatalf("%s: old %q current %q", name, old, current)
		}
	}
	if a, d := w.DeliveryStats(), w.DerivedStats("inventory"); a.Written != 2 || d.Written != 2 || a.Pending != 0 || d.Pending != 0 {
		t.Fatalf("delivery approved %+v derived %+v", a, d)
	}
}

func TestDerivedWriterAppendsAcrossSessions(t *testing.T) {
	root := t.TempDir()
	for _, session := range []string{"one", "two"} {
		w, err := OpenWriter(WriterOptions{Directory: root})
		if err != nil {
			t.Fatal(err)
		}
		d, err := w.openDerived("inventory")
		if err != nil {
			t.Fatal(err)
		}
		line := []byte("{\"session\":\"" + session + "\"}\n")
		if reason := w.writeDerived(d, line); reason != "" {
			t.Fatalf("derived refusal: %s", reason)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if st := w.DerivedStats("inventory"); st.Written != 1 || st.Failed != 0 {
			t.Fatalf("derived outcomes: %+v", st)
		}
	}
	data, err := os.ReadFile(filepath.Join(root, DerivedName("inventory")))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{\"session\":\"one\"}\n{\"session\":\"two\"}\n" {
		t.Fatalf("derived append: %s", data)
	}
}
func TestUnavailableDerivedFileRecoversWithoutStoppingApprovedOutput(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, DerivedName("inventory"))
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	w, err := OpenWriter(WriterOptions{Directory: root})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	d, err := w.openDerived("inventory")
	if err != nil {
		t.Fatalf("unavailable derived file prevented start: %v", err)
	}
	if reason := w.writeDerived(d, []byte("{}\n")); reason != "" {
		t.Fatalf("enqueue: %s", reason)
	}
	if err := w.WriteApproved(context.Background(), Approved{line: []byte("{}\n")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a, d := w.DeliveryStats(), w.DerivedStats("inventory"); a.Written != 1 || d.Failed != 1 {
		t.Fatalf("separate outcomes: approved %+v derived %+v", a, d)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := w.Reopen(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reason := w.writeDerived(d, []byte("{}\n")); reason != "" {
		t.Fatalf("recovered enqueue: %s", reason)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if d := w.DerivedStats("inventory"); d.Written != 1 || d.Failed != 1 || d.Pending != 0 {
		t.Fatalf("derived recovery: %+v", d)
	}
}
