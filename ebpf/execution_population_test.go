//go:build attach

package ebpf

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	cilium "github.com/cilium/ebpf"
	"github.com/evandukss/edge-observer/admission"
)

// The expected population is declared here before Withdrawn runs. Neither
// Inventory, Admissions nor the focused reader supplies the test denominator.
func executionPopulationActor(t *testing.T, generation admission.Generation) (*exec.Cmd, admission.Selection) {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	pid := cmd.Process.Pid
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	end := strings.LastIndex(string(stat), ")")
	if end < 0 {
		t.Fatal("fixture: malformed real stat")
	}
	fields := strings.Fields(string(stat)[end+1:])
	if len(fields) < 20 {
		t.Fatal("fixture: short real stat")
	}
	birth, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		t.Fatal(err)
	}
	ns := info.Sys().(*syscall.Stat_t)
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	var inside int64
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "NStgid:") {
			parts := strings.Fields(line)
			inside, err = strconv.ParseInt(parts[len(parts)-1], 10, 32)
		}
	}
	if err != nil || inside <= 0 {
		t.Fatalf("fixture: group namespace numbering unavailable: %v", err)
	}
	one := admission.Selection{ObserverPID: int32(pid), Instance: admission.Instance{Namespace: admission.Namespace{Device: uint64(ns.Dev), Inode: ns.Ino}, PID: int32(inside), Start: admission.Determinate(admission.BootTicks(birth)), Generation: generation}, Mode: admission.ModeFollow}
	return cmd, one
}

func executionPopulationSession(t *testing.T, recorded, granted []admission.Selection) (*Session, *cilium.Map) {
	t.Helper()
	m, err := cilium.NewMap(&cilium.MapSpec{Name: "t11_population", Type: cilium.Hash, KeySize: uint32(binary.Size(instanceKey{})), ValueSize: uint32(binary.Size(admissionValue{})), MaxEntries: 16})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	for _, one := range granted {
		key := instanceKey{NamespaceDevice: one.Instance.Namespace.Device, NamespaceInode: one.Instance.Namespace.Inode, PID: uint32(one.Instance.PID)}
		value := admissionValue{Generation: uint64(one.Instance.Generation), Birth: uint64(one.Instance.Start.Ticks), Kind: uint8(one.Kind), Mode: uint8(one.Mode), Threads: 1}
		if err := m.Update(key, value, cilium.UpdateNoExist); err != nil {
			t.Fatal(err)
		}
	}
	// Read the fixture map directly, independent of the production grant reader.
	var key instanceKey
	var value admissionValue
	actual := make(map[admission.Key]int)
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		actual[admission.Key{Namespace: admission.Namespace{Device: key.NamespaceDevice, Inode: key.NamespaceInode}, PID: int32(key.PID), Generation: admission.Generation(value.Generation)}]++
	}
	if err := iter.Err(); err != nil {
		t.Fatal(err)
	}
	want := make(map[admission.Key]int)
	for _, one := range granted {
		want[one.Instance.Key()]++
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("fixture: kernel grant set differs from declaration: %v != %v", actual, want)
	}
	s := &Session{collection: &cilium.Collection{Maps: map[string]*cilium.Map{"allowed_processes": m}}, inventory: append([]admission.Selection(nil), recorded...), seen: make(map[instanceKey]admission.Start)}
	return s, m
}

func TestExecutionWithdrawalPopulationIsTheDeclaredSet(t *testing.T) {
	_, running := executionPopulationActor(t, 701)
	endedCmd, ended := executionPopulationActor(t, 702)
	_, unreadable := executionPopulationActor(t, 703)
	_, granted := executionPopulationActor(t, 704)
	if err := endedCmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = endedCmd.Wait()
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", ended.ObserverPID)); !os.IsNotExist(err) {
		t.Fatalf("fixture: exited and reaped process still present: %v", err)
	}
	// No observer-side number can be established for this retained admission.
	// Its identity is still known and its grant independently absent.
	unreadable.ObserverPID = 0
	recorded := []admission.Selection{running, ended, unreadable, granted}
	want := map[admission.Key]Ended{running.Instance.Key(): GrantEndedWhileRunning, ended.Instance.Key(): ExecutionEnded, unreadable.Instance.Key(): ExecutionIndeterminate}
	s, _ := executionPopulationSession(t, recorded, []admission.Selection{granted})
	got, err := s.Withdrawn()
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[admission.Key]int)
	for _, one := range got {
		key := one.Selection.Instance.Key()
		counts[key]++
		state, exists := want[key]
		if !exists {
			t.Errorf("extra withdrawal outside declared known-ungranted set: %+v", one)
			continue
		}
		if one.State != state {
			t.Errorf("declared admission %v: got %q want %q", key, one.State, state)
		}
		for _, original := range recorded {
			if original.Instance.Key() == key && !reflect.DeepEqual(one.Selection, original) {
				t.Errorf("identity-matching result changed admission: %+v", one.Selection)
			}
		}
	}
	expectedCounts := make(map[admission.Key]int)
	for key := range want {
		expectedCounts[key] = 1
	}
	if !reflect.DeepEqual(counts, expectedCounts) {
		t.Errorf("withdrawal identity multiset: got %v want %v", counts, expectedCounts)
	}
}

func TestExecutionUnknownBirthAndBaselineIsIndeterminate(t *testing.T) {
	for _, which := range []string{"neither-known", "baseline-known", "recorded-known", "recorded-over-baseline"} {
		t.Run(which, func(t *testing.T) {
			_, one := executionPopulationActor(t, 711)
			original := one.Instance.Start
			if which == "neither-known" || which == "baseline-known" {
				one.Instance.Start = admission.Start{}
			}
			s, _ := executionPopulationSession(t, []admission.Selection{one}, nil)
			key := instanceKey{NamespaceDevice: one.Instance.Namespace.Device, NamespaceInode: one.Instance.Namespace.Inode, PID: uint32(one.Instance.PID)}
			if which == "baseline-known" {
				s.seen[key] = original
			}
			if which == "recorded-over-baseline" {
				s.seen[key] = admission.Determinate(original.Ticks + 100)
			}
			got, err := s.Withdrawn()
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("unknown-birth retained admission has %d results, want one", len(got))
			}
			want := GrantEndedWhileRunning
			if which == "neither-known" {
				want = ExecutionIndeterminate
			}
			if got[0].State != want {
				t.Errorf("original birth/baseline: got %q want %q", got[0].State, want)
			}
			if !reflect.DeepEqual(got[0].Selection, one) {
				t.Errorf("baseline overwrote the recorded admission: %+v", got[0].Selection)
			}
		})
	}
}

func TestExecutionFailedGrantReadIsNotAnAbsentGrantSet(t *testing.T) {
	_, one := executionPopulationActor(t, 721)
	s, m := executionPopulationSession(t, []admission.Selection{one}, []admission.Selection{one})
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := s.Withdrawn()
	if err == nil {
		t.Errorf("failed allowlist read became a successful withdrawal set: %+v", got)
	}
	if len(got) != 0 {
		t.Errorf("failed allowlist read invented absent grants: %+v", got)
	}
}
