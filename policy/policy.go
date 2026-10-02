// Package policy reads the observer's configuration file: where it writes,
// what it watches, what it never watches, which library builds a probe may be
// placed on, and the rules applied before anything is written.
//
// The file is the contract's configuration (contract/config, observer.config/1),
// read and compiled by the contract's own code (CompileProcessing).
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/process"
)

// Stdout is the log value that sends the log to standard output alone.
const Stdout = "stdout"

// Settings is where the observer writes, its limits, how often it restates its
// state and how many workers process.
type Settings struct {
	// Log is the configured log file, or Stdout.
	Log string

	// Directory holds the pid file and one subdirectory per session.
	Directory string

	// AdmittedEventLimit bounds decoded-event admission for this session.
	// It is independent of approved output and is not a process-memory bound.
	AdmittedEventLimit int64

	// StateEvery is how often the log restates the observer's state after
	// activation.
	StateEvery time.Duration

	// Workers is the number of processing workers, limits.workers.
	Workers int
}

// Policy is one configuration file as the observer reads it.
type Policy struct {
	// Processing is present only on a successfully compiled processing configuration.
	Processing *config.ProcessingPlan
	// ProcessingRevision binds the processing and retention declarations and
	// the extensions, excluding observation scope and observer settings.
	// CompileProcessing supplies it alongside Processing. Reload requires the
	// same nonempty value and retains the active plan; restart changes it.
	// A legacy policy has no processing revision and cannot replace a compiled one.
	ProcessingRevision string
	Settings           Settings
	Approval           process.Approval

	// Revision names the file's content, so an account can say which policy
	// was in force.
	Revision string
}

// assemble is the observation approval and the settings a compiled
// configuration asks for. A watch or ignore entry the process selector
// refuses, or a library approval it cannot use, is refused naming its key.
func assemble(content []byte, file config.File, resolved config.ResolvedObserver) (Policy, []config.Finding) {
	var findings []config.Finding
	refuse := func(subject string, err error) {
		findings = append(findings, config.Finding{Document: "configuration", Subject: subject,
			Reason: config.InvalidValue, Detail: err.Error()})
	}
	approval := process.Approval{}
	for i, w := range file.Watch {
		rule, err := ruleOf(w.Match)
		if err != nil {
			refuse(fmt.Sprintf("watch[%d]", i), err)
			continue
		}
		rule.Name, rule.Mode = w.Name, childrenMode(w.Children)
		approval.Rules = append(approval.Rules, rule)
	}
	for i, m := range file.Ignore {
		rule, err := ruleOf(m)
		if err != nil {
			refuse(fmt.Sprintf("ignore[%d]", i), err)
			continue
		}
		approval.Exclusions = append(approval.Exclusions, rule)
	}
	for i, l := range file.Libraries {
		library := process.LibraryApproval{BuildID: l.BuildID, Symbols: l.Symbols}
		if err := library.Validate(); err != nil {
			refuse(fmt.Sprintf("libraries[%d]", i), err)
			continue
		}
		approval.Libraries = append(approval.Libraries, library)
	}
	if len(findings) > 0 {
		return Policy{}, findings
	}
	settings := Settings{
		Log:                resolved.Log,
		Directory:          resolved.Directory,
		AdmittedEventLimit: resolved.AdmittedEventLimit,
		StateEvery:         time.Duration(resolved.StateEverySeconds) * time.Second,
		Workers:            int(resolved.Workers),
	}
	sum := sha256.Sum256(content)
	return Policy{Settings: settings, Approval: approval, Revision: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// childrenMode is the admission mode a watch entry's children answer names:
// all is existing and future descendants, existing the ones running when the
// watch is resolved, none no descendant. The reader admits no other value.
func childrenMode(children string) admission.Mode {
	switch children {
	case config.ChildrenAll:
		return admission.ModeFollow
	case config.ChildrenExisting:
		return admission.ModeExisting
	case config.ChildrenNone:
		return admission.ModeNone
	}
	return admission.ModeUnset
}

func ruleOf(m config.Match) (process.Rule, error) {
	rule := process.Rule{Executable: m.Exe, Cgroup: m.Cgroup, Interface: m.Interface}
	if m.Args != nil {
		rule.Arguments = append([]string{}, *m.Args...)
	}
	if m.PID != nil {
		rule.PID = &process.PIDGuard{PID: m.PID.PID, Start: m.PID.Start, Boot: m.PID.Boot}
	}
	if m.Port != nil {
		rule.Port = uint16(*m.Port)
	}
	if err := rule.Validate(); err != nil {
		return process.Rule{}, err
	}
	return rule, nil
}
