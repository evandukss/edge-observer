package bpf

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The calls counted as socket I/O are the ones the program follows as a TLS
// call's socket work, read from the program's own source.
func TestTheSocketCallsAreTheOnesTheProgramFollows(t *testing.T) {
	body := regexp.MustCompile(`(?s)static __always_inline int obs_supported\(__u32 number\)\s*\{(.*?)\n\}`).
		FindStringSubmatch(source)
	if body == nil {
		t.Fatal("wiring, not the property: the source defines no obs_supported, so nothing below compares anything")
	}
	var followed []string
	for _, name := range regexp.MustCompile(`case OBS_SYS_(\w+):`).FindAllStringSubmatch(body[1], -1) {
		followed = append(followed, strings.ToLower(name[1]))
	}
	if len(followed) < 10 {
		t.Fatalf("wiring, not the property: obs_supported names %d calls: %v", len(followed), followed)
	}
	counted := make([]string, 0, len(SocketCalls))
	for _, name := range SocketCalls {
		counted = append(counted, name)
	}
	slices.Sort(followed)
	slices.Sort(counted)
	if !slices.Equal(followed, counted) {
		t.Errorf("the program follows %v as socket I/O and SocketCalls names %v", followed, counted)
	}
}
