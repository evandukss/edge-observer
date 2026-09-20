// Package config is the authored view of an observer deployment: the operator
// configuration, the pack manifest, and the typed processing-component
// interface both select implementations through. The specification is
// CONFIG.md in this directory.
//
// What is written here is resolved against what a runtime has - its record
// types, built-in components, sink kinds and admission's descendant answers -
// and the resolved view is contract/policy's Inventory. This package checks
// documents statically; it executes no component, evaluates no policy and
// enforces nothing.
package config

import "encoding/json"

// Versions this draft reads. No machine-readable schema is published;
// example JSON files show the shapes, and the Go validators enforce the contracts.
const (
	ConfigurationVersion = "observer.config/draft"
	ManifestVersion      = "observer.pack/draft"
	ComponentVersion     = "observer.component/draft"
)

// The observer settings an operator may omit, as values: the observer's own
// defaults, which a test holds equal.
const (
	DefaultSpoolBoundMiB     int64 = 64
	DefaultStateEverySeconds int64 = 30
)

// Configuration is the operator's document. Its three scopes are separate
// members because they are separate controls: which instances may be inspected,
// which of their connections, and what may be kept or leave the host. None of
// them is expressed through another.
type Configuration struct {
	Version string `json:"version"`

	Observer Observer `json:"observer"`

	ObservationScope ObservationScope `json:"observation_scope"`
	TrafficScope     TrafficScope     `json:"traffic_scope"`
	RetentionExport  RetentionExport  `json:"retention_and_export"`

	// Packs are the packs this configuration enables, by manifest name.
	Packs []string `json:"packs"`

	Sinks       []Sink       `json:"sinks"`
	Pipelines   []Pipeline   `json:"pipelines"`
	Subscribers []Subscriber `json:"subscribers"`

	// Policy is the operator's policy documents, in contract/policy's
	// vocabulary, decoded and checked there.
	Policy []json.RawMessage `json:"policy"`
}

// Observer is where the observer writes, the spool bound per session, and how
// often the log restates state. Log and Directory are required;
// SpoolBoundMiB and StateEverySeconds default to DefaultSpoolBoundMiB and
// DefaultStateEverySeconds and are refused below 1. Log is "stdout" or an
// absolute path; Directory is absolute, since a relative path would depend on
// how the process was started.
type Observer struct {
	Log               string `json:"log"`
	Directory         string `json:"directory"`
	SpoolBoundMiB     *int64 `json:"spool_bound_mib"`
	StateEverySeconds *int64 `json:"state_every_seconds"`
}

// ObservationScope is which instances may be inspected. Approval against it is
// checked before plaintext is copied, and nothing later in the configuration
// widens it.
type ObservationScope struct {
	Targets []Target `json:"targets"`
	Exclude []Match  `json:"exclude"`

	// Libraries are the library builds a probe may be placed on, by build id with
	// approved entry-point offsets. Empty approves any library.
	Libraries []Library `json:"libraries"`
}

// Library is one approved library build.
type Library struct {
	BuildID string            `json:"build_id"`
	Symbols map[string]uint64 `json:"symbols"`
}

// Target is one selection rule and what it says about descendants.
type Target struct {
	Name        string      `json:"name"`
	Match       Match       `json:"match"`
	Descendants Descendants `json:"descendants"`
}

// Match names instances by the conditions the observer's admission reads. At
// least one is present.
type Match struct {
	Exe       string    `json:"exe,omitempty"`
	Args      *[]string `json:"args,omitempty"`
	Cgroup    string    `json:"cgroup,omitempty"`
	PID       *PIDGuard `json:"pid,omitempty"`
	Port      *int      `json:"port,omitempty"`
	Interface string    `json:"interface,omitempty"`
}

// PIDGuard names one process instance, not a pid number.
type PIDGuard struct {
	PID   int32  `json:"pid"`
	Start uint64 `json:"start"`
	Boot  string `json:"boot"`
}

// Descendants is the five answers a descendant rule owes. Two are the
// operator's; three are fixed by admission and written out, so stating
// anything else is refused. Every member is required.
type Descendants struct {
	Existing *bool `json:"existing"`
	Future   *bool `json:"future"`

	// Boundary, RootExit and Replacement are the fixed answers, written so a
	// reader sees them.
	Boundary    string `json:"boundary"`
	RootExit    string `json:"root_exit"`
	Replacement string `json:"replacement"`
}

// TrafficScope is which connections of the selected instances are captured,
// decided per connection before plaintext is copied. A condition needing a
// reconstructed message is a post-capture suppression in the policy
// vocabulary, never evidence that an instance was not inspected.
type TrafficScope struct {
	Rules []TrafficRule `json:"rules"`
}

// TrafficRule admits connections of the named targets matching every
// condition. Targets empty means every target.
type TrafficRule struct {
	Targets     []string `json:"targets"`
	Direction   string   `json:"direction"`
	LocalPorts  []int    `json:"local_ports"`
	RemotePorts []int    `json:"remote_ports"`
}

// Directions a traffic rule can name.
const (
	DirectionInbound  = "inbound"
	DirectionOutbound = "outbound"
	DirectionAny      = "any"
)

// RetentionExport is what may be kept on the host and what may leave it.
type RetentionExport struct {
	// RetainPlaintext is whether plaintext may be kept on the host beyond the
	// pipeline that processes it, in a sink that does not leave the host.
	RetainPlaintext *bool `json:"retain_plaintext"`

	// ExportSinks are the sinks permitted to send anything off the host. A
	// pipeline dispatching to a sink whose kind leaves the host, and which is
	// not named here, is refused.
	ExportSinks []string `json:"export_sinks"`
}

// Sink is one configured destination.
type Sink struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// Pipeline is an explicit composition: records of Input enter, pass through the
// slots in order, and are dispatched to Sinks. A pipeline with no slots is the
// no-extension path, and it is the same route through the core as any other.
type Pipeline struct {
	Name   string   `json:"name"`
	Input  string   `json:"input"`
	Slots  []Slot   `json:"slots"`
	Sinks  []string `json:"sinks"`
	Queues []Queue  `json:"queues"`
}

// Slot is one position in a pipeline and the implementation that fills it. A
// replacement is a different implementation in the same slot, never a second
// component racing the first.
type Slot struct {
	Name           string          `json:"name"`
	Implementation string          `json:"implementation"`
	Configuration  json.RawMessage `json:"configuration,omitempty"`
	OnFailure      string          `json:"on_failure"`
}

// Failure actions a slot can take when its implementation returns a record
// error. A fatal error always stops the pipeline.
const (
	OnFailureDropAndAccount = "drop_and_account"
	OnFailureStopPipeline   = "stop_pipeline"
)

// Queue is a core-managed queue in a pipeline.
type Queue struct {
	Name string `json:"name"`
}

// Subscriber consumes one pipeline's output and emits linked findings that
// reference observation ids, never rewriting a delivered record. Reserved:
// nothing runs a subscriber yet.
type Subscriber struct {
	Name           string `json:"name"`
	Stream         string `json:"stream"`
	Implementation string `json:"implementation"`
}
