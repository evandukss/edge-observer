//go:build attach

package attach_test

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
)

// Case 2 of P3-T25, criterion rows 1 and 13: a fatal diagnostic carries no
// protected plaintext - not on stderr, not on the collected stdout, not in any
// file written - with every write checked at the boundary as it is made.
//
//	the sealed account cannot be written
//	    the sessions directory is a tmpfs the test fills once a first connection
//	    is written; the next connection's approved write fails for want of space,
//	    the session ends, the account cannot be placed, and main prints the error
//	    and exits 1 - the one enumerated fatal site reachable once plaintext has
//	    been captured (TestT25EveryFatalSiteIsListedWithItsReason). The approved
//	    write that fails is also case 1's failure in the write itself
//	a runtime dump on SIGQUIT
//	    an exchange is held undecided on an open connection when the observer is
//	    sent SIGQUIT, and the Go runtime prints every goroutine to stderr and exits
//
// The control is the first case's run on an ample filesystem, stopped: it seals
// and exits 0, and the permitted marker is written.
func TestT25AFatalDiagnosticCarriesNoProtectedPlaintext(t *testing.T) {
	binary := built(t)
	for _, how := range []string{"the sealed account cannot be written", "a runtime dump on SIGQUIT", "stopped on ample space"} {
		t.Run(how, func(t *testing.T) {
			port := t18Serving(t)
			decided, faulting := speaking(t, port), speaking(t, port)
			c := configuring(t, target("clients", decided.process))
			t18Edit(t, c, t18Removing)
			var fill func() int64
			if how != "a runtime dump on SIGQUIT" {
				fill = t25Filled(t, c.sessions(), 256<<10)
			}
			w := t25Watched(t, binary, c, nil)
			t25Decided(t, binary, c, decided)

			switch how {
			case "the sealed account cannot be written":
				t.Logf("filled the sessions filesystem with %d bytes", fill())
				t18Ask(t, faulting, "/?asked=t25-after-the-fill",
					"X-Public: "+t18BoundaryPermitted, "Authorization: Bearer "+t18BoundaryProtected)
				t18Hangup(faulting)
				w.ended(t, 30*time.Second)
				stopped := w.records("stopped")
				if len(stopped) != 1 {
					t.Fatalf("wiring, not the property: the session printed %d stopped records:\n%s", len(stopped), w.stderrText())
				}
				processingBlock, _ := stopped[0]["processing"].(map[string]any)
				failures, _ := processingBlock["output_failures"].(float64)
				recorded, _ := stopped[0]["error"].(string)
				// The guards: the approved write really failed, and the fatal site
				// really ran, with exit status 1.
				if failures < 1 || !strings.Contains(recorded, "no space left on device") {
					t.Fatalf("wiring, not the property: the write did not fail for want of space: %v", stopped[0])
				}
				if w.state == nil || w.state.ExitCode() != 1 || !strings.Contains(w.stderrText(), "observer: write the sealed account") {
					t.Fatalf("wiring, not the property: main's fatal exit did not run: %v\n%s", w.state, w.stderrText())
				}
				t.Logf("stopped record %v; stderr %q", stopped[0], w.stderrText())
			case "a runtime dump on SIGQUIT":
				before := inspected(t, binary, c).Seen.Records
				t18Ask(t, faulting, "/?asked=t25-held-at-the-dump",
					"X-Public: "+t18BoundaryPermitted, "Authorization: Bearer "+t18BoundaryProtected)
				t18Until(t, binary, c, 10*time.Second, "wiring, not the property: the held exchange was never captured",
					func(a account.Account) bool { return a.Seen != nil && a.Seen.Records >= before+2 })
				w.signal(t, syscall.SIGQUIT)
				dump := w.stderrText()
				if w.state == nil || w.state.ExitCode() != 2 || !strings.Contains(dump, "SIGQUIT: quit") || !strings.Contains(dump, "goroutine ") {
					t.Fatalf("wiring, not the property: the runtime did not dump and exit: %v, %d bytes of stderr", w.state, len(dump))
				}
				t.Logf("the dump is %d bytes over %d goroutines", len(dump), strings.Count(dump, "\ngoroutine "))
			default:
				t18Ask(t, faulting, "/?asked=t25-control",
					"X-Public: "+t18BoundaryPermitted, "Authorization: Bearer "+t18BoundaryProtected)
				t18Hangup(faulting)
				t25Settled(t, binary, c, w, 4, 10*time.Second)
				w.signal(t, syscall.SIGTERM)
				if w.state == nil || w.state.ExitCode() != 0 {
					t.Fatalf("wiring, not the property: the control did not exit 0: %v\n%s", w.state, w.stderrText())
				}
				sealed := t18Sealed(t, w.directory(c), w.session)
				if !slices.Contains(t18Targets(t18Approved(t, w.directory(c))), "/?asked=t25-control") || sealed.Processing.OutputFailures != 0 {
					t.Fatalf("wiring, not the property: the control did not write its exchange: %+v", sealed.Processing)
				}
			}
			t25Clean(t, w)
		})
	}
}

// t25FatalSites is every site in the observer module's non-test source that
// ends the process or prints a recovered panic, with why it is covered or why
// it cannot run while plaintext is held. The Go runtime's own dump on SIGQUIT
// is no site in this source and is provoked by the SIGQUIT case above.
var t25FatalSites = map[string]string{
	"internal/cmd/broken-extension/main.go: os.Exit(": "a separate fault-injection peer: crash mode exits while " +
		"sanitized exchanges are pending; every mode exits on an invalid invocation or a closed output pipe. " +
		"It can hold only the sanitized input the observer sent, never removed values",
	"internal/cmd/broken-extension/main.go: panic(": "a separate fault-injection peer: descendant mode reports " +
		"failure to start its child; every mode with recording reports audit open/write failures, and every " +
		"mode reports invalid protocol input. These peer failures may occur while sanitized input is held",

	"cmd/observer/main.go: os.Exit(": "run's error printed to stderr, then exit 1. Reached after capture when the " +
		"sealed account cannot be written: TestT25AFatalDiagnosticCarriesNoProtectedPlaintext",
	"cmd/observer/control.go: panic(": "newIdentity finding no system random source. Its two callers run before " +
		"anything is captured: start, before begin attaches, and the requesting side of ask, a separate " +
		"process. Unreachable while plaintext is held",
	"bpf/cmd/verify/main.go: os.Exit(": "the build's BPF verifier, a separate program that is not the observer",
}

// Every fatal site is listed with its reason, and every listed site exists. A
// new site fails here until somebody says whether it can run while plaintext is
// held, so the enumeration cannot go stale in silence.
func TestT25EveryFatalSiteIsListedWithItsReason(t *testing.T) {
	// The module root is the nearest directory above the package holding go.mod.
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("wiring, not the property: no go.mod above the test's directory")
		}
		root = parent
	}
	patterns := []string{"log.Fatal", "panic(", "os.Exit(", "recover()"}
	found := map[string]int{}
	files := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == ".jj" || entry.Name() == ".git" || entry.Name() == ".workspaces") {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		files++
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		content, err := io.ReadAll(file)
		_ = file.Close()
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(root, path)
		for _, pattern := range patterns {
			if n := strings.Count(string(content), pattern); n > 0 {
				found[relative+": "+pattern] += n
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if files < 100 || found["cmd/observer/main.go: os.Exit("] == 0 {
		t.Fatalf("wiring, not the property: the walk read %d source files and found %v", files, found)
	}
	for site, count := range found {
		if _, listed := t25FatalSites[site]; !listed {
			t.Errorf("fatal site %s (%d occurrences) has no stated reason", site, count)
		}
	}
	for site := range t25FatalSites {
		if found[site] == 0 {
			t.Errorf("listed fatal site %s is no longer in the source", site)
		}
	}
	t.Logf("%d source files, sites %v", files, found)
}
