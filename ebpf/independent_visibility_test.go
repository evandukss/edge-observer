//go:build attach

package ebpf_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/preflight"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl"
	"github.com/evandukss/edge-observer/process"
)

func TestIndependentNotLiveVisibilitySurvivesAttachmentOrder(t *testing.T) {
	full := proofFixture(t, nil)
	partial := proofConfigured(t, nil, func(o *ebpf.Options) {
		for i := range o.Points {
			if o.Points[i].Symbol == "SSL_write" {
				o.Points[i].Path = "/independent-proof-missing-write"
			}
		}
	})
	if len(full.session.Unprobed()) != 0 || len(partial.session.Unprobed()) != 1 {
		t.Fatalf("UNPROVED: full=%v partial=%v", full.session.Unprobed(), partial.session.Unprobed())
	}
	built := probe.Capability{Backend: probe.BPF, Payload: true, Filtered: true, Lifecycle: true, Descendants: true, SocketEvidence: true}
	a := full.session.Coverage().Narrow(built)
	b := partial.session.Coverage().Narrow(built)
	if !slices.Contains(b.Unprobed, "SSL_write") || !strings.Contains(account.Describe(b), "capture is not live") || !strings.Contains(account.Describe(b), "whole attachment") {
		t.Errorf("COUNTEREXAMPLE: direct partial coverage/description hides not-live: %+v / %s", b, account.Describe(b))
	}
	if len(a.Unprobed) != 0 || strings.Contains(account.Describe(a), "capture is not live") {
		t.Errorf("COUNTEREXAMPLE: full placement described not-live: %+v", a)
	}
	for _, order := range []struct {
		name string
		caps []probe.Capability
	}{{"full_then_partial", []probe.Capability{a, b}}, {"partial_then_full", []probe.Capability{b, a}}} {
		t.Run(order.name, func(t *testing.T) {
			combined := probe.Weakest(order.caps...)
			encoded, err := json.Marshal(combined)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(combined.Unprobed, "SSL_write") || !strings.Contains(account.Describe(combined), "capture is not live") || !strings.Contains(string(encoded), `"unprobed"`) {
				t.Errorf("COUNTEREXAMPLE: attachment order lost not-live: capability=%s describe=%s", encoded, account.Describe(combined))
			}
		})
	}
	catalog, err := probe.NewCatalog(openssl.New())
	if err != nil {
		t.Fatal(err)
	}
	report := preflight.Assess(preflight.Running(), []process.Process{partial.who}, catalog)
	found := 0
	for _, r := range report.Requirements {
		if r.Name == preflight.TLSLibrary {
			found++
			if !strings.Contains(r.Declared, "capture is not live") || !strings.Contains(r.Declared, "lifecycle") || !strings.Contains(r.Declared, "byte-moving") {
				t.Errorf("COUNTEREXAMPLE: preflight omits consequence: %s", r.Declared)
			}
		}
	}
	if found != 1 {
		t.Fatalf("UNPROVED: preflight library requirements=%d", found)
	}
	t.Logf("PRECONDITIONS full_attachments=1 actual_partial_attachments=1 failed_present_write=1 orderings=2 preflight_requirements=%d", found)
}
