package probe_test

import (
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

type identifyingAdapter struct {
	adapter
	file uint64
}

func (a identifyingAdapter) Identify(process.Process, probe.Report) (probe.FileID, probe.FileID, error) {
	return probe.FileID{Inode: a.file}, probe.FileID{Inode: a.file + 100}, nil
}
func TestReloadEvidenceAndRequestGroupsFollowTheSelectedAdapter(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		a := identifyingAdapter{adapter: supports("a"), file: 1}
		b := identifyingAdapter{adapter: supports("b"), file: 2}
		inspectors := []probe.Inspector{a, b}
		if reverse {
			inspectors = []probe.Inspector{b, a}
		}
		c := catalog(t, inspectors...)
		request := probe.Request{Processes: []process.Process{{PID: 1}, {PID: 2}, {PID: 3}},
			Admit: []admission.Selection{{ObserverPID: 1}, {ObserverPID: 2}, {ObserverPID: 3}},
			Read:  map[int32]probe.Reading{1: {Report: probe.Report{Supported: true, Adapter: "a"}}, 2: {Report: probe.Report{Supported: true, Adapter: "b"}}, 3: {Report: probe.Report{Supported: true, Adapter: "a"}}},
			Deny:  []admission.Denial{{ObserverPID: 99}}}
		routes, err := c.Routes(request, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(routes) != 2 {
			t.Fatalf("%d routes, want 2", len(routes))
		}
		for _, route := range routes {
			want := 1
			if route.Adapter.Name() == "a" {
				want = 2
			}
			if len(route.Request.Processes) != want || len(route.Request.Admit) != want || len(route.Request.Read) != want || len(route.Request.Deny) != 1 {
				t.Fatalf("partition lost or duplicated members: %+v", route.Request)
			}
			for _, p := range route.Request.Processes {
				r := route.Request.Read[p.PID].Report
				if r.Adapter != route.Adapter.Name() {
					t.Fatalf("pid %d routed to %s, selected %s", p.PID, route.Adapter.Name(), r.Adapter)
				}
				lib, libc, err := c.Identify(p, r)
				want := uint64(1)
				if r.Adapter == "b" {
					want = 2
				}
				if err != nil || lib.Inode != want || libc.Inode != want+100 {
					t.Fatalf("selected identification: %v %v %v", lib, libc, err)
				}
			}
		}
		request.Read[2] = probe.Reading{Report: probe.Report{Support: []probe.Support{{Adapter: "b", Reason: "unsupported fixture"}}}}
		if _, err := c.Routes(request, nil); err == nil || !strings.Contains(err.Error(), "unsupported fixture") {
			t.Fatalf("unsupported refusal %v", err)
		}
	}
}
