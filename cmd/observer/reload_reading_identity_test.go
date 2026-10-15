package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// Constructed procfs isolates the final command-reading boundary. Stat and
// argv come from the running test process; only the named identity field is
// changed. This does not stage kernel PID reuse or library discovery.
func TestReloadReadingRejectsChangedOrUnknownIdentity(t *testing.T) {
	for _, change := range []string{"unchanged", "birth", "namespace", "numbering", "unread_birth", "unknown_namespace", "unknown_argv", "unknown_original_birth"} {
		t.Run(change, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "101")
			if err := os.MkdirAll(filepath.Join(directory, "ns"), 0o700); err != nil {
				t.Fatal(err)
			}
			write := func(name string, body []byte) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(directory, name), body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			remove := func(name string) {
				t.Helper()
				if err := os.Remove(filepath.Join(directory, name)); err != nil {
					t.Fatal(err)
				}
			}
			stat, err := os.ReadFile("/proc/self/stat")
			if err != nil {
				t.Fatal(err)
			}
			_, rest, found := strings.Cut(string(stat), " ")
			if !found {
				t.Fatal("wiring: captured stat has no PID")
			}
			stat = []byte("101 " + rest)
			argv, err := os.ReadFile("/proc/self/cmdline")
			if err != nil || len(argv) == 0 {
				t.Fatalf("wiring: argv=%q error=%v", argv, err)
			}
			exe, err := os.Readlink("/proc/self/exe")
			if err != nil {
				t.Fatal(err)
			}
			write("stat", stat)
			write("cmdline", argv)
			write("status", []byte("NSpid:\t101\n"))
			if err := os.Symlink(exe, filepath.Join(directory, "exe")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/proc/self/ns/pid", filepath.Join(directory, "ns/pid")); err != nil {
				t.Fatal(err)
			}
			p, err := process.Identify(root, 101)
			if err != nil || p.StartTime == 0 || p.Namespace.Inode == 0 || p.NamespacePID != 101 {
				t.Fatalf("wiring: original identity=%+v error=%v", p, err)
			}
			exec, err := process.ReadExec(root, 101)
			if err != nil {
				t.Fatal(err)
			}
			reading := probe.Reading{Exec: exec}
			if why, same := reloadIdentityUnchanged(root, p, reading); !same {
				t.Fatalf("wiring: unchanged control refused: %s", why)
			}
			switch change {
			case "birth":
				end := strings.LastIndexByte(string(stat), ')')
				fields := strings.Fields(string(stat[end+2:]))
				if len(fields) <= 19 {
					t.Fatal("wiring: captured stat has no birth")
				}
				fields[19] = strconv.FormatUint(p.StartTime+1, 10)
				write("stat", []byte(string(stat[:end+2])+strings.Join(fields, " ")))
			case "namespace":
				remove("ns/pid")
				write("ns/pid", []byte("a distinct namespace identity"))
			case "numbering":
				write("status", []byte("NSpid:\t101\t7\n"))
			case "unread_birth":
				remove("stat")
			case "unknown_namespace":
				remove("ns/pid")
			case "unknown_argv":
				remove("cmdline")
			case "unknown_original_birth":
				p.StartTime = 0
			}
			why, same := reloadIdentityUnchanged(root, p, reading)
			if change == "unchanged" {
				if !same {
					t.Fatalf("stable reading refused: %s", why)
				}
			} else if same || why == "" {
				t.Fatalf("property: %s reading accepted or unnamed: same=%t reason=%q", change, same, why)
			}
		})
	}
}
