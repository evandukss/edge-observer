package process

import (
	"strings"
	"testing"
)

// approved is a policy naming one build of one library and two entry points.
func approved() Approval {
	return Approval{Libraries: []LibraryApproval{{
		BuildID: "77b686c8727edee8124fcc6d0e4d4539c545cbcf",
		Symbols: map[string]uint64{"SSL_read": 0x3fee0, "SSL_write": 0x40700},
	}}}
}

// The control: a library matching the policy exactly is within it.
func TestAnApprovedLibraryAndOffsetsPass(t *testing.T) {
	err := approved().ApproveLibrary("77b686c8727edee8124fcc6d0e4d4539c545cbcf",
		map[string]uint64{"SSL_read": 0x3fee0, "SSL_write": 0x40700})
	if err != nil {
		t.Fatalf("an approved library was refused: %v", err)
	}
}

// An unapproved build id is refused, whatever its offsets.
func TestALibraryWithAnUnapprovedBuildIDIsRefused(t *testing.T) {
	err := approved().ApproveLibrary("0000000000000000000000000000000000000000",
		map[string]uint64{"SSL_read": 0x3fee0, "SSL_write": 0x40700})
	if err == nil {
		t.Fatal("a library with an unapproved build id was not refused")
	}
	if !strings.Contains(err.Error(), "build id") {
		t.Errorf("the refusal does not name the build id: %v", err)
	}
}

// An offset the policy does not approve is refused: a probe about to be
// placed on the wrong instruction.
func TestASymbolAtAnUnapprovedOffsetIsRefused(t *testing.T) {
	err := approved().ApproveLibrary("77b686c8727edee8124fcc6d0e4d4539c545cbcf",
		map[string]uint64{"SSL_read": 0x3fee0, "SSL_write": 0x99999})
	if err == nil {
		t.Fatal("a symbol at an unapproved offset was not refused")
	}
	if !strings.Contains(err.Error(), "SSL_write") {
		t.Errorf("the refusal does not name the offending symbol: %v", err)
	}
}

// A symbol the policy does not name is refused, so a newly grown entry point is
// not attached on the strength of the others.
func TestASymbolThePolicyDoesNotNameIsRefused(t *testing.T) {
	err := approved().ApproveLibrary("77b686c8727edee8124fcc6d0e4d4539c545cbcf",
		map[string]uint64{"SSL_read": 0x3fee0, "SSL_read_ex": 0x3ffa0})
	if err == nil {
		t.Fatal("a symbol the policy does not name was not refused")
	}
	if !strings.Contains(err.Error(), "SSL_read_ex") {
		t.Errorf("the refusal does not name the unapproved symbol: %v", err)
	}
}

// An empty policy approves any library.
func TestAnEmptyPolicyApprovesAnyLibrary(t *testing.T) {
	err := Approval{}.ApproveLibrary("anything", map[string]uint64{"SSL_read": 0x1234})
	if err != nil {
		t.Fatalf("an empty policy refused a library: %v", err)
	}
}
