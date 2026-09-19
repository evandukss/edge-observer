package bpf

import (
	"regexp"
	"testing"
)

// Every followed syscall that can only operate on a socket is marked as one,
// and the two lists in the program's source agree. On the messaging path the
// syscall's own nature is the only answer (the classifier reads the inode mode
// only for the scalar and vector family), so a messaging syscall missing from
// the socket-only split reports an unresolved operation instead of a stated
// limit, silently. It reads the source because the two lists are maintained by
// hand.
func TestEveryMessagingSyscallTheProgramFollowsIsMarkedSocketOnly(t *testing.T) {
	followed := casesIn(t, "obs_supported")
	only := casesIn(t, "obs_socket_only")

	if len(followed) < 8 {
		t.Fatalf("read %d syscalls out of obs_supported, which cannot be right", len(followed))
	}
	if len(only) == 0 {
		t.Fatal("read no syscalls out of obs_socket_only, so this compared nothing")
	}

	for name := range only {
		if !followed[name] {
			t.Errorf("%s is marked socket-only and is not one the program follows, so the mark "+
				"reaches no operation", name)
		}
	}
	for name := range SocketOnlySyscalls {
		if !only[name] {
			t.Errorf("%s is socket-only in this package and the program does not mark it, so an "+
				"operation through it reports no evidence where the truth is an unfollowed route",
				name)
		}
	}
	for name := range only {
		if !SocketOnlySyscalls[name] {
			t.Errorf("the program marks %s socket-only and this package names no such syscall",
				name)
		}
	}
}

// casesIn is every OBS_SYS_ constant named in one function of the program.
func casesIn(t *testing.T, function string) map[string]bool {
	t.Helper()

	body := regexp.MustCompile(`(?s)\b` + regexp.QuoteMeta(function) + `\(__u32 number\)\s*\{.*?\n\}`)
	found := body.FindString(source)
	if found == "" {
		t.Fatalf("the program declares no %s, so this measured nothing", function)
	}

	named := make(map[string]bool)
	for _, match := range regexp.MustCompile(`OBS_SYS_[A-Z0-9_]+`).FindAllString(found, -1) {
		named[match] = true
	}
	return named
}
