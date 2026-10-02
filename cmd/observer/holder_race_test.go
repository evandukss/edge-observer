package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAControlProbeCannotRefuseAConcurrentStart(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, pidName), nil, 0600); err != nil {
		t.Fatal(err)
	}
	probed, resume, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_, _, err := holderUsing(dir, func(file *os.File) (bool, error) {
			held, err := probeHolder(file)
			close(probed)
			<-resume
			return held, err
		})
		done <- err
	}()
	<-probed
	lock, err := acquire(dir)
	close(resume)
	probeErr := <-done
	if !errors.Is(probeErr, errNotRunning) {
		t.Fatalf("wiring: probe did not observe the initially idle file: %v", probeErr)
	}
	if err != nil {
		t.Fatalf("a control probe prevented a start: %v", err)
	}
	defer lock.release()
	if err := lock.record(os.Getpid(), "active-session"); err != nil {
		t.Fatal(err)
	}
	pid, session, err := holder(dir)
	if err != nil || pid != os.Getpid() || session != "active-session" {
		t.Fatalf("live holder = %d %q %v", pid, session, err)
	}
}
