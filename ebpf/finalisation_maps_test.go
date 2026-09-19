//go:build attach

package ebpf

import (
	"errors"
	"fmt"
	cilium "github.com/cilium/ebpf"
	"github.com/evandukss/edge-observer/admission"
)

// IndependentFailRingReader closes the actual reader while the session is
// still live. It does not close Session.done or replace the reading loop; that
// loop must distinguish this failure from an orderly session shutdown.
func IndependentFailRingReader(session *Session) error {
	if session.reader == nil {
		return fmt.Errorf("fixture has no live ring reader")
	}
	if err := session.reader.Close(); err != nil {
		return err
	}
	<-session.stopped
	return nil
}

// IndependentKernelGrantPresent observes the actual map without the
// reconciliation now performed by Session.Admissions changing its contents.
func IndependentKernelGrantPresent(session *Session, instance admission.Instance) (bool, error) {
	var value admissionValue
	err := session.collection.Maps["allowed_processes"].Lookup(keyOf(instance), &value)
	if errors.Is(err, cilium.ErrKeyNotExist) {
		return false, nil
	}
	return err == nil, err
}
