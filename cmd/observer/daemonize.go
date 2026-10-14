package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
)

// reportName names the descriptor a detached observer reports activation or
// failure on. Only daemonize sets it, for its child.
const reportName = "OBSERVER_ACTIVATION_REPORT"

// configurationName names the descriptor a detached observer reads the
// configuration it runs from: the bytes its parent checked. Only launch sets
// it, for its child.
const configurationName = "OBSERVER_CHECKED_CONFIGURATION"

// checked is a configuration read once and put through every check a detached
// session makes before anything starts or stops: the bytes read, what they
// compile to, and this program, which the session is started from.
//
// A detached session runs exactly these bytes. Its parent hands them over on
// descriptor 4, named by OBSERVER_CHECKED_CONFIGURATION=4 beside the activation
// report on descriptor 3, and the session never reads the file itself, so a
// change to the file after the check reaches no session until the next start,
// restart or reload reads it.
type checked struct {
	// path is the configuration's absolute path. An extension's relative command
	// is resolved against its directory, and a reload reads the file again.
	path string
	// content is the bytes that were read and checked.
	content []byte
	// read is what content compiles to.
	read policy.Policy
	// executable is this program, found before anything is stopped.
	executable string
}

// checkDetached reads the configuration once and makes every check a detached
// start makes before it starts or stops anything, so that a configuration a
// detached session would refuse is refused while a running session still runs:
//
//   - the configuration is read and compiled, processing and every extension's
//     command included, as loadProcessing does;
//   - the log is not stdout, since a detached session has no standard output;
//   - this program is found, to start the session from.
//
// What is left to the session is what only starting it can discover:
// attaching, the runtime and resources.
func checkDetached(path string) (checked, error) {
	content, err := readConfiguration(path)
	if err != nil {
		return checked{}, err
	}
	read, err := policy.CompileProcessing(content, filepath.Dir(path))
	if err != nil {
		return checked{}, err
	}
	if read.Settings.Log == policy.Stdout {
		return checked{}, errors.New("the log is configured as stdout, and a detached observer has no standard output: " +
			"configure a file, or run it in the foreground")
	}
	executable, err := os.Executable()
	if err != nil {
		return checked{}, fmt.Errorf("find this program to start it detached: %w", err)
	}
	return checked{path: path, content: content, read: read, executable: executable}, nil
}

// daemonize starts the observer detached and returns once it has activated,
// or with its error. A Go program cannot fork after its runtime starts, so the
// parent starts the child first, in its own session; the child resolves,
// attaches, drops capabilities and activates, then reports on a pipe. The
// parent exits zero only on "activated"; otherwise the child has failed and
// exited, so no detached process outlives a failed attach.
//
// A detached observer has no standard output, so a stdout log is refused
// before anything starts. Restart-on-failure is a supervisor's job; under one,
// run start in the foreground.
func daemonize(path string, stdout io.Writer) error {
	c, err := checkDetached(path)
	if err != nil {
		return err
	}
	return launch(c, stdout)
}

// launch starts a detached session from what was checked and returns once it
// has activated, or with its error. The child is this program run as
// "start <path>", handed the checked bytes and nothing else to compile.
func launch(c checked, stdout io.Writer) error {
	reading, writing, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("make the activation report: %w", err)
	}
	taking, handing, err := os.Pipe()
	if err != nil {
		_ = reading.Close()
		_ = writing.Close()
		return fmt.Errorf("make the configuration's hand-over: %w", err)
	}
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		for _, end := range []*os.File{reading, writing, taking, handing} {
			_ = end.Close()
		}
		return fmt.Errorf("open %s: %w", os.DevNull, err)
	}

	child := exec.Command(c.executable, "start", c.path)
	child.Env = append(os.Environ(), reportName+"=3", configurationName+"=4")
	child.ExtraFiles = []*os.File{writing, taking}
	child.Stdin, child.Stdout, child.Stderr = null, null, null
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err = child.Start()
	_ = writing.Close()
	_ = taking.Close()
	_ = null.Close()
	if err != nil {
		_ = reading.Close()
		_ = handing.Close()
		return fmt.Errorf("start the detached observer: %w", err)
	}

	// The bytes are written while the report is awaited, since a pipe holds less
	// than a configuration may be. A child that ends, or reports, without reading
	// them all ends the hand-over: closing it below returns the write.
	go func() {
		_, _ = handing.Write(c.content)
		_ = handing.Close()
	}()
	// The child closes its end once it has reported, or ends without a word.
	said, _ := io.ReadAll(io.LimitReader(reading, 1<<16))
	_ = reading.Close()
	_ = handing.Close()
	line := strings.TrimSpace(string(said))
	switch {
	case strings.HasPrefix(line, "activated "):
		_, _ = fmt.Fprintf(stdout, "started    session %s, pid %d, detached; its log is %s\n",
			strings.TrimPrefix(line, "activated "), child.Process.Pid, c.read.Settings.Log)
		return child.Process.Release()
	case strings.HasPrefix(line, "failed "):
		_ = child.Wait()
		return errors.New(strings.TrimPrefix(line, "failed "))
	default:
		err := child.Wait()
		return fmt.Errorf("the detached observer ended before it said whether it activated: %v", err)
	}
}

// detachedReport is the pipe a detached observer reports on; nil in the
// foreground.
func detachedReport() *os.File {
	if os.Getenv(reportName) != "3" {
		return nil
	}
	_ = os.Unsetenv(reportName)
	return os.NewFile(3, "activation report")
}

// report says once whether this detached observer activated, and closes the
// pipe. It does nothing in the foreground.
func report(to *os.File, format string, arguments ...any) {
	if to == nil {
		return
	}
	line := strings.ReplaceAll(fmt.Sprintf(format, arguments...), "\n", " ")
	_, _ = fmt.Fprintln(to, line)
	_ = to.Close()
}

// handedOver is the descriptor a detached observer reads its configuration
// from; nil in the foreground.
func handedOver() *os.File {
	if os.Getenv(configurationName) != "4" {
		return nil
	}
	_ = os.Unsetenv(configurationName)
	return os.NewFile(4, "checked configuration")
}

// configurationFor is the configuration a session runs. In the foreground it
// is the file at path, read and compiled. Detached, it is the bytes its parent
// checked, read from the descriptor it was handed and compiled the same way,
// against path's directory, and the file is not read: what the parent checked
// is what runs. At most one byte past the configuration bound is read, so an
// oversized hand-over is refused as the file would be.
func configurationFor(path string, from *os.File) (policy.Policy, error) {
	if from == nil {
		return loadProcessing(path)
	}
	content, err := io.ReadAll(io.LimitReader(from, config.MaxProcessingBytes+1))
	_ = from.Close()
	if err != nil {
		return policy.Policy{}, fmt.Errorf("read the configuration handed to this detached observer: %w", err)
	}
	return policy.CompileProcessing(content, filepath.Dir(path))
}

// restartRefused is a restart refused before it stopped anything: whatever
// session runs over the configuration runs on, its process, its identity and
// its output untouched. It says why, and the command exits non-zero.
type restartRefused struct{ reason error }

func (r *restartRefused) Error() string {
	return "restart refused, and nothing was stopped: " + r.reason.Error()
}

func (r *restartRefused) Unwrap() error { return r.reason }

// restarter is the steps a restart takes, in this order:
//
//  1. check makes every check a detached start makes (checkDetached). A
//     failure is a restartRefused.
//  2. holder names the session running over the checked configuration's
//     directory. Any answer but a session or errNotRunning is a
//     restartRefused.
//  3. stop ends that session, found by the checked configuration and never by
//     reading the file again. It returns once the session has released its pid
//     file and last-sealed.json names it, so the two sessions never overlap.
//  4. launch starts the replacement detached, from the checked bytes.
//
// Nothing before step 3 stops anything, and nothing after it refuses for the
// configuration: the configuration step 1 passed is the one steps 3 and 4 act
// on, whatever the file holds by then. A failure only starting the
// replacement can discover - attaching, the runtime, resources - is reported
// after the stop, and nothing rolls it back.
//
// restarting holds the real steps. A test copies it and replaces any step to
// observe what a restart did, in what order, and with what.
type restarter struct {
	check  func(path string) (checked, error)
	holder func(directory string) (pid int, session string, err error)
	stop   func(c checked, stdout io.Writer) error
	launch func(c checked, stdout io.Writer) error
}

var restarting = restarter{check: checkDetached, holder: holder, stop: stopChecked, launch: launch}

// restart ends the running session, sealing it, and starts a new one detached,
// whose activation record names the session it follows and the gap. Under a
// supervisor, restart through it: the gap is recorded either way.
func restart(path string, stdout io.Writer) error {
	return restarting.restart(path, stdout)
}

func (r restarter) restart(path string, stdout io.Writer) error {
	c, err := r.check(path)
	if err != nil {
		return &restartRefused{reason: err}
	}
	switch _, _, err := r.holder(c.read.Settings.Directory); {
	case err == nil:
		if err := r.stop(c, stdout); err != nil {
			return err
		}
	case !errors.Is(err, errNotRunning):
		return &restartRefused{reason: err}
	}
	return r.launch(c, stdout)
}

// stopChecked ends the session running over the checked configuration's
// directory and waits for it to seal.
func stopChecked(c checked, stdout io.Writer) error {
	return stopIn(c.read.Settings.Directory, stdout)
}
