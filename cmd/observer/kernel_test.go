package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The release a session records is the one its host publishes, read whole; a
// release that cannot be read is recorded with why, never as an empty release
// that would read as an account written before sessions recorded one.
func TestTheSessionsKernelIsReadFromItsHostAndAnUnreadableOneSaysWhy(t *testing.T) {
	host := func(content *string) string {
		root := t.TempDir()
		if content != nil {
			path := filepath.Join(root, "sys", "kernel", "osrelease")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(*content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return root
	}
	published, empty := "6.8.0-41-generic\n", "\n"

	switch got := kernelOf(host(&published)); {
	case got == nil:
		t.Error("a published release is not recorded at all")
	case got.Release != "6.8.0-41-generic" || got.Why != "":
		t.Errorf("a host publishing 6.8.0-41-generic is recorded as %+v", *got)
	}
	for name, root := range map[string]string{"absent": host(nil), "empty": host(&empty)} {
		switch got := kernelOf(root); {
		case got == nil:
			t.Errorf("%s: an unreadable release is not recorded at all, which reads as an account written "+
				"before sessions recorded one", name)
		case got.Release != "" || got.Why == "":
			t.Errorf("%s: an unreadable release is recorded as %+v, want no release and why", name, *got)
		case !strings.Contains(got.Why, "osrelease"):
			t.Errorf("%s: an unreadable release says %q, which does not name what was read", name, got.Why)
		}
	}
}
