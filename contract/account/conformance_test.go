package account

import (
	"bufio"
	"bytes"

	"io/fs"

	"strings"
	"testing"
	"testing/fstest"
)

// An unreadable record member is a finding. Validation reads records first, so
// no tree reaches this today; the helper is asked directly so a change in what
// validation guarantees cannot make the read a silent absence.
func TestAnUnreadableRecordMemberIsAFinding(t *testing.T) {
	a := &agreement{result: Agreement{Outcome: Disagree, Checked: []string{}, Findings: []Finding{}}}
	visited := 0
	a.each(fstest.MapFS{}, Paths[RoleConnections], func([]byte) { visited++ })
	if visited != 0 {
		t.Fatalf("wiring, not the property: an empty tree yielded %d lines", visited)
	}
	if len(a.result.Findings) != 1 {
		t.Fatalf("an unreadable record member produced %d findings, where one against it is expected: %+v",
			len(a.result.Findings), a.result.Findings)
	}
	finding := a.result.Findings[0]
	if finding.Reason != RecordReferenceUnresolved || finding.Member != ConformanceBundle+"/"+Paths[RoleConnections] ||
		!strings.Contains(finding.Detail, fs.ErrNotExist.Error()) {
		t.Fatalf("the finding is %+v, where record_reference_unresolved against %s carrying %q is expected", finding,
			ConformanceBundle+"/"+Paths[RoleConnections], fs.ErrNotExist.Error())
	}
}

// A member unreadable to its end is a finding too: one line a byte longer than
// the reader's 64 MiB limit.
func TestARecordMemberWithALineTooLongIsAFinding(t *testing.T) {
	const size = 64*1024*1024 + 1
	a := &agreement{result: Agreement{Outcome: Disagree, Checked: []string{}, Findings: []Finding{}}}
	visited := 0
	tree := fstest.MapFS{Paths[RoleConnections]: &fstest.MapFile{Data: bytes.Repeat([]byte("x"), size)}}
	a.each(tree, Paths[RoleConnections], func([]byte) { visited++ })
	if visited != 0 {
		t.Fatalf("wiring, not the property: a %d-byte line was visited %d times, so the reader did not stop on it", size, visited)
	}
	if len(a.result.Findings) != 1 {
		t.Fatalf("a record member with a %d-byte line produced %d findings, where one against it is expected: %+v", size,
			len(a.result.Findings), a.result.Findings)
	}
	finding := a.result.Findings[0]
	if finding.Reason != RecordReferenceUnresolved || finding.Member != ConformanceBundle+"/"+Paths[RoleConnections] ||
		!strings.Contains(finding.Detail, bufio.ErrTooLong.Error()) {
		t.Fatalf("the finding is reason %s against %s, where record_reference_unresolved against %s carrying %q is expected",
			finding.Reason, finding.Member, ConformanceBundle+"/"+Paths[RoleConnections], bufio.ErrTooLong.Error())
	}
}
