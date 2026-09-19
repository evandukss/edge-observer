package process_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/process"
)

// The start identity a grant binds is read here and established in the
// kernel, equal only while this reader's time namespace moves nothing. So the
// offset is asserted, and zero is kept apart from an offset nobody could
// establish (which a session refuses). The zero content below is a real
// no-namespace host's /proc/self/timens_offsets, padding included.

func offsets(t *testing.T, content string) string {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "self")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatalf("make %s: %v", directory, err)
	}
	if content == "" {
		return root
	}
	if err := os.WriteFile(filepath.Join(directory, "timens_offsets"), []byte(content), 0o644); err != nil {
		t.Fatalf("write timens_offsets: %v", err)
	}
	return root
}

func TestAReaderInNoTimeNamespaceReadsTheKernelsOwnStartTimes(t *testing.T) {
	offset, err := process.StartTimesAreOffset(offsets(t,
		"monotonic           0         0\nboottime            0         0\n"))
	if err != nil {
		t.Fatalf("read the offsets a host with no time namespace publishes: %v", err)
	}
	if offset != 0 {
		t.Errorf("a boottime offset of zero read as %s, so a session would refuse to attach on a host "+
			"whose start times are the kernel's", offset)
	}
}

func TestAKernelThatPublishesNoOffsetsHasNoneRatherThanAnUnknownOne(t *testing.T) {
	offset, err := process.StartTimesAreOffset(offsets(t, ""))
	if err != nil {
		t.Fatalf("read a procfs with no timens_offsets: %v", err)
	}
	if offset != 0 {
		t.Errorf("a kernel with no time namespaces reported an offset of %s", offset)
	}
}

func TestAShiftedBootTimeIsReportedWithItsNanoseconds(t *testing.T) {
	offset, err := process.StartTimesAreOffset(offsets(t,
		"monotonic       12345         0\nboottime        86400       500\n"))
	if err != nil {
		t.Fatalf("read a shifted boot time: %v", err)
	}
	want := 86400*time.Second + 500*time.Nanosecond
	if offset != want {
		t.Errorf("a boottime offset of 86400 seconds and 500 nanoseconds read as %s, want %s", offset, want)
	}
}

func TestOffsetsThatNameNoBootTimeAreIndeterminateRatherThanZero(t *testing.T) {
	offset, err := process.StartTimesAreOffset(offsets(t, "monotonic           0         0\n"))
	if err == nil {
		t.Fatalf("offsets naming no boot time reported an offset of %s, so a session would bind every "+
			"grant to a start time it never established was the kernel's", offset)
	}
}

func TestAnUnreadableOffsetIsNotAnOffsetOfZero(t *testing.T) {
	offset, err := process.StartTimesAreOffset(offsets(t, "boottime not-a-number 0\n"))
	if err == nil {
		t.Fatalf("an offset that is not a number read as %s", offset)
	}
}
