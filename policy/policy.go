// Package policy reads the observer's configuration file: where it writes,
// what it attaches to, what it never attaches to, and which library builds a
// probe may be placed on.
//
// The file is the contract's operator configuration (contract/config), checked
// by the contract's own code against what this program has (Inventory). Every
// section the contract accepts and this program does not implement is refused
// by name (Unimplemented), never read and ignored.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/process"
)

// Stdout is the log value that sends the log to standard output alone.
const Stdout = "stdout"

// Settings is where the observer writes and how often it restates its state.
type Settings struct {
	// Log is the configured log file, or Stdout.
	Log string

	// Directory holds the pid file and one subdirectory per session.
	Directory string

	// BoundMiB bounds one session's spool.
	BoundMiB int64

	// StateEvery is how often the log restates the observer's state after
	// activation.
	StateEvery time.Duration
}

// Policy is one configuration file as the observer reads it.
type Policy struct {
	Settings Settings
	Approval process.Approval

	// Revision names the file's content, so an account can say which policy
	// was in force.
	Revision string
}

// Load reads the configuration file at path.
func Load(path string) (Policy, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read the configuration: %w", err)
	}
	read, err := parse(content)
	if err != nil {
		return Policy{}, fmt.Errorf("read the configuration %s: %w", path, err)
	}
	return read, nil
}

func parse(content []byte) (Policy, error) {
	return against(content, Inventory())
}

// against reads a configuration against an inventory. The program uses only
// its own; tests use this to hold the none-versus-some rule against an
// inventory that has some of a kind.
func against(content []byte, has config.Available) (Policy, error) {
	written, structural := config.ReadConfiguration(content)
	if len(structural) > 0 {
		return Policy{}, &Refused{Outcome: config.StructurallyRefused, Findings: structural}
	}
	if sections := unimplemented(written, has); len(sections) > 0 {
		return Policy{}, &Unimplemented{Sections: sections}
	}
	result := config.Check(config.Input{Configuration: content, Available: has})
	if result.Outcome != config.Accepted {
		return Policy{}, &Refused{Outcome: result.Outcome, Findings: append(result.Structural, result.Composition...)}
	}

	approval := process.Approval{}
	for i, t := range written.ObservationScope.Targets {
		mode, answerable := modeOf(t.Descendants)
		if !answerable {
			return Policy{}, &Unanswerable{Target: t.Name, Existing: *t.Descendants.Existing, Future: *t.Descendants.Future}
		}
		rule, err := ruleOf(t.Match)
		if err != nil {
			return Policy{}, fmt.Errorf("observation_scope.targets[%d]: %w", i, err)
		}
		rule.Name, rule.Mode = t.Name, mode
		approval.Rules = append(approval.Rules, rule)
	}
	for i, m := range written.ObservationScope.Exclude {
		rule, err := ruleOf(m)
		if err != nil {
			return Policy{}, fmt.Errorf("observation_scope.exclude[%d]: %w", i, err)
		}
		approval.Exclusions = append(approval.Exclusions, rule)
	}
	for i, l := range written.ObservationScope.Libraries {
		library := process.LibraryApproval{BuildID: l.BuildID, Symbols: l.Symbols}
		if err := library.Validate(); err != nil {
			return Policy{}, fmt.Errorf("observation_scope.libraries[%d]: %w", i, err)
		}
		approval.Libraries = append(approval.Libraries, library)
	}

	resolved := result.Resolved.Observer
	settings := Settings{
		Log:        resolved.Log,
		Directory:  resolved.Directory,
		BoundMiB:   resolved.SpoolBoundMiB,
		StateEvery: time.Duration(resolved.StateEverySeconds) * time.Second,
	}
	sum := sha256.Sum256(content)
	return Policy{Settings: settings, Approval: approval, Revision: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// modeOf is the admission mode giving a target's two descendant answers. One
// pair - future descendants without existing ones - has no mode.
func modeOf(d config.Descendants) (admission.Mode, bool) {
	switch existing, future := *d.Existing, *d.Future; {
	case !existing && !future:
		return admission.ModeNone, true
	case existing && !future:
		return admission.ModeExisting, true
	case existing && future:
		return admission.ModeFollow, true
	default:
		return admission.ModeUnset, false
	}
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

// unimplemented is every section of a well-formed configuration that asks for
// something this program does not do. The program captures every connection
// of an approved instance and keeps all of it, plaintext included, in the
// session's spool and sealed account on this host.
//
// Where the inventory holds a kind, the count decides: NONE of it means the
// kind is unimplemented; SOME of it without the one named is left to the
// composition check. So an inventory that gains processors turns an unknown
// slot back into "cannot be resolved" with no change here. Packs, traffic
// scopes, policy documents and routing have nothing to count and are refused
// whenever asked for.
func unimplemented(c config.Configuration, has config.Available) []Section {
	processing := []Capability{Processing}
	var sections []Section
	add := func(path string, needs []Capability, detail string, arguments ...any) {
		sections = append(sections, Section{Path: path, Needs: needs, Detail: fmt.Sprintf(detail, arguments...)})
	}
	builtins := func(role string) bool {
		return slices.ContainsFunc(has.Builtins, func(b config.Component) bool { return b.Role == role })
	}
	kinds := func(is func(config.SinkKind) bool) bool { return slices.ContainsFunc(has.SinkKinds, is) }

	for i, rule := range c.TrafficScope.Rules {
		if len(rule.Targets) > 0 || rule.Direction != config.DirectionAny || len(rule.LocalPorts) > 0 || len(rule.RemotePorts) > 0 {
			add(fmt.Sprintf("traffic_scope.rules[%d]", i), processing,
				"it narrows the connections captured, and every connection of an approved instance is captured")
		}
	}
	if retain := c.RetentionExport.RetainPlaintext; retain != nil && !*retain &&
		!kinds(func(k config.SinkKind) bool { return !k.RetainsPlaintext }) {
		add("retention_and_export.retain_plaintext", processing,
			"it is false, and every output this program has keeps the plaintext it captures")
	}
	if len(c.RetentionExport.ExportSinks) > 0 && !kinds(func(k config.SinkKind) bool { return k.LeavesHost }) {
		add("retention_and_export.export_sinks", nil, "it names %v, and nothing this program has leaves the host; "+
			"an output that does is added to the program as a contribution, not configured into it",
			c.RetentionExport.ExportSinks)
	}
	if len(c.Packs) > 0 {
		add("packs", []Capability{Processing, Plugins}, "it enables %v, and this program loads no pack", c.Packs)
	}
	otherKinds := kinds(func(k config.SinkKind) bool { return k.Name != LocalAccount })
	local := map[string]bool{}
	for i, sink := range c.Sinks {
		if sink.Kind == LocalAccount {
			local[sink.Name] = true
		} else if !otherKinds {
			add(fmt.Sprintf("sinks[%d].kind", i), nil, "sink %q is of kind %q, and this program's one output "+
				"is the %s; another kind is added to the program as a contribution, not configured into it",
				sink.Name, sink.Kind, LocalAccount)
		}
	}
	routed := map[string]bool{}
	processors := builtins(config.RoleProcessor)
	for i, pipeline := range c.Pipelines {
		if len(pipeline.Slots) > 0 && !processors {
			add(fmt.Sprintf("pipelines[%d].slots", i), processing,
				"pipeline %q fills %d slots, and this program has no processing component", pipeline.Name, len(pipeline.Slots))
		}
		if slices.ContainsFunc(pipeline.Sinks, func(name string) bool { return local[name] }) {
			routed[pipeline.Input] = true
		}
	}
	if !routed[Reconstruction] || !routed[Connection] {
		add("pipelines", processing, "every %s and every %s is kept in the local account, so a configuration "+
			"routing either to none is filtering them", Reconstruction, Connection)
	}
	if len(c.Subscribers) > 0 && !builtins(config.RoleSubscriber) {
		add("subscribers", processing, "it names %d subscribers, and this program has none", len(c.Subscribers))
	}
	if len(c.Policy) > 0 {
		add("policy", processing, "it carries %d policy documents, and this program enforces none", len(c.Policy))
	}
	return sections
}
