package intake_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
)

func TestAccountingBoundsOwnersShareOneLedger(t *testing.T) {
	s, err := intake.New(8192)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.Write(fragment.Record{Payload: []byte("source")}); err != nil {
		t.Fatal(err)
	}
	e := s.Take()
	if e == nil || s.Stats().Leased != 1 {
		t.Fatal("wiring, not the property: source was not leased")
	}
	source := s.Stats().Bytes
	if !s.Reserve(intake.Parsing, 1000) || !s.Reserve(intake.Policy, 2000) {
		t.Fatal("wiring, not the property: small charges were refused")
	}
	if a := s.Stats(); a.Bytes != source || a.Parsing != 1000 || a.Policy != 2000 {
		t.Errorf("coexisting owners not charged: %+v", a)
	}
	// Fill the remainder from the fixture's reservations and the intake's
	// separately measured source charge, not from reported work balances.
	rest := int64(8192) - source - 3000
	if rest <= 0 || !s.Reserve(intake.Parsing, rest) {
		t.Fatal("wiring, not the property: fixture does not fit its allowance")
	}
	for _, owner := range []intake.Owner{intake.Parsing, intake.Policy} {
		if s.Reserve(owner, 1) {
			t.Errorf("owner %v exceeded the shared allowance", owner)
		}
	}
	if err := s.Write(fragment.Record{Payload: []byte("next")}); !errors.Is(err, intake.ErrLimit) {
		t.Errorf("intake ignored work charges: %v", err)
	}
	if a := s.Stats(); a.ParsingRefused != 1 || a.PolicyRefused != 1 || a.Parsing != 1000+rest || a.Policy != 2000 {
		t.Errorf("refusal changed balances or lost its cause: %+v", a)
	}
	e.Release()
	if a := s.Stats(); a.Bytes != 0 || a.Parsing != 1000+rest || a.Policy != 2000 {
		t.Errorf("source release refunded a coexisting copy: %+v", a)
	}
	s.Return(intake.Parsing, 1000+rest)
	s.Return(intake.Policy, 2000)
	if a := s.Stats(); a.Bytes != 0 || a.Parsing != 0 || a.Policy != 0 {
		t.Errorf("settlement retained charges: %+v", a)
	}
}

func TestAccountingBoundsConcurrentOwnersCannotMultiplyAllowance(t *testing.T) {
	s, err := intake.New(4096)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	start := make(chan struct{})
	var done sync.WaitGroup
	var granted atomic.Int64
	for i := 0; i < 16; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			<-start
			owner := intake.Parsing
			if i%2 == 1 {
				owner = intake.Policy
			}
			if s.Reserve(owner, 512) {
				granted.Add(1)
			}
		}(i)
	}
	close(start)
	done.Wait()
	if granted.Load() == 0 {
		t.Fatal("wiring, not the property: no holder reached reservation")
	}
	a := s.Stats()
	if granted.Load() != 8 || a.Parsing+a.Policy != 4096 || a.ParsingRefused+a.PolicyRefused != 8 {
		t.Errorf("concurrent holders multiplied allowance: granted=%d stats=%+v", granted.Load(), a)
	}
	s.Return(intake.Parsing, a.Parsing)
	s.Return(intake.Policy, a.Policy)
	if a = s.Stats(); a.Parsing != 0 || a.Policy != 0 {
		t.Errorf("holders did not return charges: %+v", a)
	}
}

func TestAccountingBoundsClosedInputKeepsWorkAndOverReturnVisible(t *testing.T) {
	s, err := intake.New(4096)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Reserve(intake.Parsing, 100) {
		t.Fatal("wiring, not the property: initialized store refused work")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if !s.Stats().Closed {
		t.Fatal("wiring, not the property: store did not close")
	}
	if !s.Reserve(intake.Policy, 200) {
		t.Error("closed input refused valid retained work")
	}
	if a := s.Stats(); a.Parsing != 100 || a.Policy != 200 {
		t.Errorf("close erased work: %+v", a)
	}
	s.Return(intake.Parsing, 101)
	s.Return(intake.Policy, 200)
	if a := s.Stats(); a.Parsing != -1 || a.Policy != 0 {
		t.Errorf("over-return hidden: %+v", a)
	}
}
