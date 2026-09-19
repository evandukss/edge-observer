package probe_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// The catalog is the subject, so adapters are stood in for; real runtimes are
// tested in the adapters' own tests.
type adapter struct {
	name    string
	answer  probe.Support
	asked   *int
	attach  probe.Attachment
	failure error
}

func (a adapter) Name() string { return a.name }

func (a adapter) Inspect(process.Process) probe.Support {
	if a.asked != nil {
		*a.asked++
	}
	return a.answer
}

func (a adapter) Attach(probe.Request, probe.Sink) (probe.Attachment, error) {
	return a.attach, a.failure
}

func supports(name string) adapter {
	return adapter{name: name, answer: probe.Support{Supported: true, Reason: "found " + name, Runtime: name}}
}

func refuses(name, reason string) adapter {
	return adapter{name: name, answer: probe.Support{Reason: reason}}
}

var observed = process.Process{PID: 1731, StartTime: 90210, Executable: "/usr/bin/interpreter"}

func catalog(t *testing.T, adapters ...probe.Inspector) probe.Catalog {
	t.Helper()

	built, err := probe.NewCatalog(adapters...)
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	return built
}

// A runtime with no adapter is unsupported, never inferred from socket
// traffic.
func TestAProcessNoAdapterSupportsIsReportedUnsupported(t *testing.T) {
	report := catalog(t, refuses("openssl", "no OpenSSL library is mapped")).Inspect(observed)

	if report.Supported {
		t.Fatal("a process every adapter refused is reported supported")
	}
	if report.Adapter != "" {
		t.Fatalf("Adapter = %q, want no adapter", report.Adapter)
	}
	if !strings.Contains(report.Reason(), "no OpenSSL library is mapped") {
		t.Fatalf("the reason does not carry the adapter's own: %q", report.Reason())
	}
}

func TestAnEmptyCatalogSupportsNothingAndSaysSo(t *testing.T) {
	report := catalog(t).Inspect(observed)

	if report.Supported {
		t.Fatal("a catalog holding no adapter reports a process supported")
	}
	if !strings.Contains(report.Reason(), "no adapter") {
		t.Fatalf("Reason() = %q, which does not say the catalog is empty", report.Reason())
	}
}

func TestEveryAdapterIsAskedAndEveryAnswerIsKept(t *testing.T) {
	first, second := 0, 0
	refused := refuses("first", "not this one")
	refused.asked = &first
	found := supports("second")
	found.asked = &second

	report := catalog(t, refused, found).Inspect(observed)

	if first != 1 || second != 1 {
		t.Fatalf("adapters asked %d and %d times, want 1 each", first, second)
	}
	if len(report.Support) != 2 {
		t.Fatalf("%d answers kept, want 2", len(report.Support))
	}
	if report.Support[0].Adapter != "first" || report.Support[1].Adapter != "second" {
		t.Fatalf("answers are not attributed to the adapters that gave them: %+v", report.Support)
	}
	if report.Support[0].Supported {
		t.Error("the refusal is recorded as support")
	}
}

func TestTheFirstAdapterThatSupportsTheProcessIsTheOneChosen(t *testing.T) {
	report := catalog(t, supports("first"), supports("second")).Inspect(observed)

	if !report.Supported {
		t.Fatal("a process two adapters support is reported unsupported")
	}
	if report.Adapter != "first" {
		t.Fatalf("Adapter = %q, want the first that supports it", report.Adapter)
	}
	if len(report.Support) != 2 {
		t.Fatalf("%d answers kept, want 2; the later adapter's answer is dropped", len(report.Support))
	}
}

// Two adapters under one name are refused.
func TestACatalogRefusesTwoAdaptersOfOneName(t *testing.T) {
	if _, err := probe.NewCatalog(supports("openssl"), refuses("openssl", "no")); err == nil {
		t.Fatal("NewCatalog accepted two adapters named openssl")
	}
}

func TestACatalogRefusesAnAdapterWithoutOne(t *testing.T) {
	if _, err := probe.NewCatalog(supports("")); err == nil {
		t.Fatal("NewCatalog accepted an adapter with no name")
	}
	if _, err := probe.NewCatalog(nil); err == nil {
		t.Fatal("NewCatalog accepted a missing adapter")
	}
}

func TestTheReportNamesTheProcessItIsAbout(t *testing.T) {
	report := catalog(t, supports("openssl")).Inspect(observed)

	if report.Process != observed.Identity() {
		t.Fatalf("Process = %+v, want %+v", report.Process, observed.Identity())
	}
}

func TestErrUnsupportedIsWhatARefusalWraps(t *testing.T) {
	err := errors.New("wrapped nothing")
	if errors.Is(err, probe.ErrUnsupported) {
		t.Fatal("an unrelated error matches ErrUnsupported")
	}
}
