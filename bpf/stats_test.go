package bpf

import (
	_ "embed"
	"strconv"
	"strings"
	"testing"
)

//go:embed ssl.bpf.h
var source string

// The counter registry has two spellings, a define in the program's source and
// a constant here, and nothing else compares them. It reads the source because
// defines do not survive into the object. It catches a counter read at the
// wrong index, which returns a valid number under another meaning.
func TestEveryCounterIsTheSameIndexInBothSpellingsOfTheRegistry(t *testing.T) {
	defined := definitions(t, "OBS_STAT_", 5)

	for name, index := range Stats {
		held, found := defined[name]
		if !found {
			t.Errorf("this package reads %s at index %d and the program defines no such counter",
				name, index)
			continue
		}
		if held != index {
			t.Errorf("%s is index %d in the program and %d here, so every reader of it is filing "+
				"another counter's number under this one's meaning", name, held, index)
		}
	}

	// The other direction: a define nothing here names is written by the program
	// and unreachable by any reader.
	for name := range defined {
		if name == "OBS_STAT_MAX" {
			continue
		}
		if _, found := Stats[name]; !found {
			t.Errorf("the program defines %s at index %d and this package names no constant for it",
				name, defined[name])
		}
	}

	// And the bound, so a counter past the end of the array fails here.
	bound, found := defined["OBS_STAT_MAX"]
	if !found {
		t.Fatal("the program declares no counter bound")
	}
	for name, index := range Stats {
		if index >= bound {
			t.Errorf("%s is index %d and the counter array holds %d", name, index, bound)
		}
	}
}

// The function registry has the same two spellings: a moved code applies what
// the program was told about SSL_read to SSL_write, with valid numbers.
func TestEveryFunctionIsTheSameCodeInBothSpellingsOfTheRegistry(t *testing.T) {
	defined := definitions(t, "OBS_FUNC_", 7)

	for name, code := range Functions {
		held, found := defined[name]
		if !found {
			t.Errorf("this package names %s as code %d and the program defines no such function",
				name, code)
			continue
		}
		if held != code {
			t.Errorf("%s is code %d in the program and %d here, so anything filed against it is "+
				"filed against another function", name, held, code)
		}
	}

	for name := range defined {
		if name == "OBS_FUNC_MAX" {
			continue
		}
		if _, found := Functions[name]; !found {
			t.Errorf("the program defines %s at code %d and this package names no constant for it",
				name, defined[name])
		}
	}

	bound, found := defined["OBS_FUNC_MAX"]
	if !found {
		t.Fatal("the program declares no function-code bound")
	}
	if bound != FuncCodeBound {
		t.Errorf("the per-function arrays hold %d entries in the program and %d here", bound, FuncCodeBound)
	}
	for name, code := range Functions {
		if code >= bound {
			t.Errorf("%s is code %d and the per-function arrays hold %d", name, code, bound)
		}
	}
}

// The pairing an entry program is written with, read off the call site. Both
// maps can agree with the defines while this package pairs obs_read_entry with
// obs_write_entry's code.
func TestEveryEntryProgramIsPairedWithTheCodeItPassesTheProgram(t *testing.T) {
	written := callSites(t)

	for name, code := range EntryPrograms {
		passed, found := written[name]
		if !found {
			t.Errorf("this package pairs %s with code %d and the program has no such entry program",
				name, code)
			continue
		}
		if Functions[passed] != code {
			t.Errorf("%s passes %s to the program and this package pairs it with code %d, which is %s",
				name, passed, code, nameOf(code))
		}
	}

	for name, passed := range written {
		if _, found := EntryPrograms[name]; !found {
			t.Errorf("the program has an entry program %s passing %s and this package pairs it with nothing",
				name, passed)
		}
	}
}

// The programs that record a descriptor, read off their call sites. A stale
// list makes a session's binding capability narrower or, worse, wider than the
// truth.
func TestEveryProgramThatRecordsADescriptorIsNamedAsOne(t *testing.T) {
	recording := recordingPrograms(t)

	for name := range BindingPrograms {
		if !recording[name] {
			t.Errorf("this package names %s as a program that records a descriptor and the "+
				"program has no such call site, so a session that holds it is credited with a "+
				"binding source it does not have", name)
		}
	}
	for name := range recording {
		if !BindingPrograms[name] {
			t.Errorf("%s records a descriptor against the call in flight and this package does "+
				"not name it, so a session holding it alone reports that it establishes no binding",
				name)
		}
	}
}

// recordingPrograms is every program in the source whose body calls
// obs_saw_socket.
func recordingPrograms(t *testing.T) map[string]bool {
	t.Helper()

	found := make(map[string]bool)
	for line := range strings.Lines(source) {
		if !strings.Contains(line, "obs_saw_socket(") || !strings.Contains(line, "int obs_") {
			continue
		}
		name, _, cut := strings.Cut(line[strings.Index(line, "int ")+len("int "):], "(")
		if !cut {
			continue
		}
		found[strings.TrimSpace(name)] = true
	}

	if len(found) < 8 {
		t.Fatalf("read %d programs recording a descriptor out of the program's source, which "+
			"cannot be right", len(found))
	}
	return found
}

// nameOf is the define a code belongs to, for a failure that says which two
// functions were swapped rather than printing two numbers.
func nameOf(code uint32) string {
	for name, held := range Functions {
		if held == code {
			return name
		}
	}
	return "no function this package names"
}

// callSites is every entry program in the source against the OBS_FUNC_ define
// it passes obs_entry.
func callSites(t *testing.T) map[string]string {
	t.Helper()

	written := make(map[string]string)
	for line := range strings.Lines(source) {
		if !strings.Contains(line, "obs_entry(ctx, OBS_FUNC_") {
			continue
		}
		name, _, found := strings.Cut(strings.TrimPrefix(line[strings.Index(line, "int ")+len("int "):], " "), "(")
		if !found {
			continue
		}
		rest := line[strings.Index(line, "obs_entry(ctx, ")+len("obs_entry(ctx, "):]
		define, _, found := strings.Cut(rest, ",")
		if !found {
			continue
		}
		written[strings.TrimSpace(name)] = strings.TrimSpace(define)
	}

	if len(written) < 7 {
		t.Fatalf("read %d entry-program call sites out of the program's source, which cannot be right",
			len(written))
	}
	return written
}

// definitions is every define in the program's source with this prefix, by
// name. least is the fewest a reading may return: an empty reading and a
// program with no such defines look alike.
func definitions(t *testing.T, prefix string, least int) map[string]uint32 {
	t.Helper()

	held := make(map[string]uint32)
	for line := range strings.Lines(source) {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "#define" || !strings.HasPrefix(fields[1], prefix) {
			continue
		}
		index, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		held[fields[1]] = uint32(index)
	}

	if len(held) < least {
		t.Fatalf("read %d %s definitions out of the program's source, which cannot be right",
			len(held), prefix)
	}
	return held
}

// Every way out of the socket observation is counted, so "no binding was
// observed" says why. It reads the source: the returns are the fact. Every way
// out is an unmet precondition rather than an insertion failure, so without
// these a run whose probes fired and left at a precondition looks like a run
// whose probes never fired. The return that records a descriptor is counted as
// itself: beside it, four failure counters at zero mean something.
func TestEveryReturnOutOfTheSocketObservationIsCounted(t *testing.T) {
	body := bodyOf(t, "obs_saw_socket")

	counters := make(map[string]bool)
	counted, recording, silent := 0, 0, 0
	previous, before := "", ""
	for line := range strings.Lines(body) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "return;" {
			if !strings.Contains(previous, "obs_count(OBS_STAT_") {
				silent++
				t.Errorf("a return out of the socket observation after %q is counted by nothing, so a "+
					"run that left there reports no binding and no reason", previous)
			} else {
				counted++
				counters[counterIn(previous)] = true
				if strings.Contains(before, "c->fds = 1;") {
					recording++
				}
			}
		}
		if trimmed != "" {
			before, previous = previous, trimmed
		}
	}

	if silent != 0 {
		t.Errorf("%d of the returns out of the socket observation are silent", silent)
	}
	if counted != 5 {
		t.Errorf("%d returns out of the socket observation are counted and there are five: a negative "+
			"descriptor, no live call on the thread, a socket key that could not be built, a "+
			"descriptor with no lifetime in the occupancy table, and the one that records a "+
			"descriptor against the call", counted)
	}
	if recording != 1 {
		t.Errorf("%d counted returns out of the socket observation record a descriptor against the "+
			"call, and exactly one does: without it nothing is ever associated, and the four "+
			"failure counters would be measuring a function that cannot succeed", recording)
	}
	if len(counters) != counted {
		t.Errorf("%d counted returns share %d counters between them, so at least two of them are "+
			"indistinguishable at the observer's surface and no reading can say which fired",
			counted, len(counters))
	}
	for name := range counters {
		if _, named := Stats[name]; !named {
			t.Errorf("the socket observation counts %s and this package names no constant for it, so "+
				"nothing reads it", name)
		}
	}
}

// counterIn is the OBS_STAT_ define an obs_count call names.
func counterIn(line string) string {
	rest := line[strings.Index(line, "obs_count(")+len("obs_count("):]
	name, _, found := strings.Cut(rest, ")")
	if !found {
		return ""
	}
	return strings.TrimSpace(name)
}

// bodyOf is one function's body out of the program's source: from its definition
// to the closing brace in the first column.
func bodyOf(t *testing.T, name string) string {
	t.Helper()

	var body strings.Builder
	inside := false
	for line := range strings.Lines(source) {
		if !inside {
			inside = strings.HasPrefix(line, "static") && strings.Contains(line, " "+name+"(")
			continue
		}
		if strings.HasPrefix(line, "}") {
			if body.Len() == 0 {
				t.Fatalf("read an empty body for %s out of the program's source", name)
			}
			return body.String()
		}
		body.WriteString(line)
	}

	t.Fatalf("the program's source holds no function %s", name)
	return ""
}
