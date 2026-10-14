package main

import (
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/processing"
)

// commandDependencies replaces host attachment and signal sources per invocation.
// Parsing, policy compilation, routing, activation logging and the controller
// remain on the command path. The default begin opens the selected real writer.
type commandDependencies struct {
	stderr   io.Writer
	begin    func(policy.Policy, string, processing.WriterOptions) (*daemon, error)
	stopping <-chan os.Signal
	asking   <-chan os.Signal
}

// signals selects channels before begin runs. The shutdown owner must watch the
// same stopping channel here and in serveUntilStop, including during activation.
func (d commandDependencies) signals() (<-chan os.Signal, <-chan os.Signal, func()) {
	if d.stopping != nil {
		return d.stopping, d.asking, func() {}
	}
	stopping, asking := make(chan os.Signal, 1), make(chan os.Signal, 1)
	signal.Notify(stopping, os.Interrupt, syscall.SIGTERM)
	signal.Notify(asking, syscall.SIGUSR1)
	return stopping, asking, func() { signal.Stop(stopping); signal.Stop(asking) }
}
