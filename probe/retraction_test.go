package probe_test

import (
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/probe"
)

func TestRetractionReceiptValidatesSubsetAndIsReentrantOnce(t *testing.T) {
	a := admission.Selection{ObserverPID: 1, Instance: admission.Instance{PID: 1, Generation: 7, Start: admission.Determinate(100)}, Provenance: admission.Provenance{Target: "original"}}
	b := a
	b.ObserverPID = 2
	b.Instance.PID = 2
	original := []admission.Selection{a, b}
	var calls []admission.Selection
	var receipt func([]admission.Selection)
	receipt = probe.BindRetraction(original, func(take []admission.Selection) {
		calls = append(calls, take...)
		if take[0].ObserverPID == 1 {
			receipt([]admission.Selection{b})
		}
	})
	original[0].ObserverPID = 99
	wrong := a
	wrong.Instance.Start = admission.Determinate(101)
	receipt([]admission.Selection{wrong})
	if len(calls) != 0 {
		t.Fatal("receipt accepted another birth")
	}
	changed := a
	changed.Provenance.Target = "replacement"
	done := make(chan struct{})
	go func() { receipt([]admission.Selection{changed, changed}); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("receipt held its lock across owner callback")
	}
	receipt([]admission.Selection{a, b})
	if len(calls) != 2 || calls[0].ObserverPID != 1 || calls[1].ObserverPID != 2 || calls[0].Provenance.Target != "original" {
		t.Fatalf("receipt repeated or changed original grants: %+v", calls)
	}
}

func TestAdmissionBatchRejectsUnrepresentableOrUnscopedOwnership(t *testing.T) {
	a := admission.Selection{ObserverPID: 1, Instance: admission.Instance{PID: 1, Generation: 7}}
	b := a
	b.ObserverPID = 2
	b.Instance.PID = 2
	scopeA, scopeB := probe.NewAdmissionScope(), probe.NewAdmissionScope()
	if scopeA == scopeB {
		t.Fatal("separate allocators share a scope")
	}
	valid := probe.Added{Selections: []admission.Selection{a, b}, Scopes: map[admission.Key]*probe.AdmissionScope{a.Instance.Key(): scopeA, b.Instance.Key(): scopeB}, Retract: func([]admission.Selection) {}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("wiring: distinct returned keys refused: %v", err)
	}
	for _, which := range []string{"duplicate_key", "duplicate_pid", "missing_scope", "unmatched_scope", "missing_receipt"} {
		one := valid
		one.Selections = append([]admission.Selection(nil), valid.Selections...)
		one.Scopes = map[admission.Key]*probe.AdmissionScope{a.Instance.Key(): scopeA, b.Instance.Key(): scopeB}
		switch which {
		case "duplicate_key":
			one.Selections[1].Instance = a.Instance
			delete(one.Scopes, b.Instance.Key())
		case "duplicate_pid":
			one.Selections[1].ObserverPID = a.ObserverPID
		case "missing_scope":
			delete(one.Scopes, a.Instance.Key())
		case "unmatched_scope":
			one.Scopes[admission.Key{PID: 3, Generation: 7}] = scopeA
		case "missing_receipt":
			one.Retract = nil
		}
		if err := one.Validate(); err == nil {
			t.Errorf("%s was accepted", which)
		}
	}
}
