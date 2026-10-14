package preflight

import (
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

type readinessAdapter struct {
	name   string
	pid    int32
	unread bool
}

func (a readinessAdapter) Name() string { return a.name }
func (a readinessAdapter) Inspect(p process.Process) probe.Support {
	if a.unread {
		return probe.Support{Reason: "unread runtime", Error: "permission refused"}
	}
	return probe.Support{Supported: p.PID == a.pid, Reason: a.name + " verdict"}
}
func TestReadinessUsesTheSelectedRuntimeWithoutAnOpenSSLLibrary(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		a := readinessAdapter{name: "a", pid: 1}
		b := readinessAdapter{name: "b", pid: 2}
		adapters := []probe.Inspector{a, b}
		if reverse {
			adapters = []probe.Inspector{b, a}
		}
		c, err := probe.NewCatalog(adapters...)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []process.Process{{PID: 1}, {PID: 2}, {PID: 3}} {
			r := tlsLibrary(Host{ProcFS: t.TempDir()}, p, c)
			if p.PID == 3 {
				if r.Status != Missing || !strings.Contains(r.Found, "unsupported") {
					t.Fatalf("unsupported: %+v", r)
				}
			} else {
				if r.Status != Met || !strings.Contains(r.Found, c.Inspect(p).Adapter+" verdict") {
					t.Fatalf("selected runtime: %+v", r)
				}
			}
		}
	}
	c, err := probe.NewCatalog(readinessAdapter{name: "uncertain", unread: true})
	if err != nil {
		t.Fatal(err)
	}
	if r := tlsLibrary(Host{}, process.Process{PID: 1}, c); r.Status != Indeterminate {
		t.Fatalf("uncertainty downgraded: %+v", r)
	}
}
