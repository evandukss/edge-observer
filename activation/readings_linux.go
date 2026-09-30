package activation

import (
	"os"

	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// Readings are the kernel readings verification makes of the payload holder
// and its participants: a process's identity and cgroup, the /proc/self link,
// the cgroup's directory, files and numbers, and dumpability. KernelReadings is
// what Verify and VerifyActive read. VerifyActiveReading verifies with readings
// a caller supplies, so that what one reading returns - a participant gone
// while it is read, a read refused - is the caller's to decide and everything
// after the readings is verification's own.
type Readings struct {
	State     func(pid int) (ParticipantState, error)
	Link      func(path string) (string, error)
	Directory func(cgroup string) (string, error)
	File      func(path string) ([]byte, error)
	Number    func(directory, name string, required bool) (uint64, error)
	Dumpable  func() (int, error)
}

// KernelReadings reads the kernel, as start and reload do.
func KernelReadings() Readings {
	return Readings{State: processState, Link: os.Readlink, Directory: cgroupDirectory, File: os.ReadFile,
		Number: cgroupNumber, Dumpable: readDumpability}
}

func (r Readings) reads() postureReads {
	return postureReads{state: r.State, link: r.Link, directory: r.Directory, file: r.File, number: r.Number,
		dumpable: r.Dumpable}
}

// VerifyActiveReading is VerifyActive with readings in place of the kernel's.
func VerifyActiveReading(gate *probe.DeliveryGate, participants []process.Process, readings Readings) (Posture, error) {
	return verifyReading(gate, participants, false, readings.reads())
}
