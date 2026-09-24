package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/evandukss/edge-observer/policy"
)

// reportName names the descriptor a detached observer reports activation or
// failure on. Only daemonize sets it, for its child.
const reportName = "OBSERVER_ACTIVATION_REPORT"

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
	read, err := policy.Load(path)
	if err != nil {
		return err
	}
	if read.Settings.Log == policy.Stdout {
		return errors.New("the log is configured as stdout, and a detached observer has no standard output: " +
			"configure a file, or run it in the foreground")
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find this program to start it detached: %w", err)
	}
	reading, writing, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("make the activation report: %w", err)
	}
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		_ = reading.Close()
		_ = writing.Close()
		return fmt.Errorf("open %s: %w", os.DevNull, err)
	}

	child := exec.Command(executable, "start", path)
	child.Env = append(os.Environ(), reportName+"=3")
	child.ExtraFiles = []*os.File{writing}
	child.Stdin, child.Stdout, child.Stderr = null, null, null
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err = child.Start()
	_ = writing.Close()
	_ = null.Close()
	if err != nil {
		_ = reading.Close()
		return fmt.Errorf("start the detached observer: %w", err)
	}

	// The child closes its end once it has reported, or ends without a word.
	said, _ := io.ReadAll(io.LimitReader(reading, 1<<16))
	_ = reading.Close()
	line := strings.TrimSpace(string(said))
	switch {
	case strings.HasPrefix(line, "activated "):
		_, _ = fmt.Fprintf(stdout, "started    session %s, pid %d, detached; its log is %s\n",
			strings.TrimPrefix(line, "activated "), child.Process.Pid, read.Settings.Log)
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

// restart ends the running session, sealing it, and starts a new one detached,
// whose activation record names the session it follows and the gap. Under a
// supervisor, restart through it: the gap is recorded either way.
func restart(path string, stdout io.Writer) error {
	read, err := policy.Load(path)
	if err != nil {
		return err
	}
	switch _, _, err := holder(read.Settings.Directory); {
	case err == nil:
		if err := stop(path, stdout); err != nil {
			return err
		}
	case !errors.Is(err, errNotRunning):
		return err
	}
	return daemonize(path, stdout)
}
