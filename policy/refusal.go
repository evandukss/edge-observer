package policy

import (
	"fmt"
	"strings"

	"github.com/evandukss/edge-observer/contract/config"
)

// Load refuses in one of three ways, each an error errors.As finds:
//
//	*Refused        the contract's own check refused it: structurally, or in
//	                composition against Inventory. A member name differing from
//	                the contract's only in case is malformed, never read as the
//	                member it resembles
//	*Unimplemented  it is well formed and asks for what this program does not do
//	*Unanswerable   a target's two descendant answers name no admission mode
//
// The order is structural, then unimplemented, then composition. Unimplemented
// comes before composition because composition against this program's empty
// inventory would answer a different question: a pack "cannot be resolved"
// where the operator needs to hear that no pack is loaded.

// Capability is what this program would need in order to implement a section
// it refuses. Its value is the text an operator reads.
type Capability string

const (
	// Processing: pipeline slots, configuration-only packs, subscribers,
	// policy documents, filtering, and anything that changes what is kept.
	Processing Capability = "configurable processing"

	// Plugins: executable plugins, which a pack may supply.
	Plugins Capability = "executable plugins"
)

// needs says what a section needs. None means no configuration enables it: it
// is added to the program as code.
func needs(capabilities []Capability) string {
	if len(capabilities) == 0 {
		return "no configuration enables it"
	}
	names := make([]string, len(capabilities))
	for i, capability := range capabilities {
		names[i] = string(capability)
	}
	if len(names) == 1 {
		return "it needs " + names[0]
	}
	return "it needs " + strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// Section is one member of a configuration the contract accepts and this
// program does not implement. Path names the member as the contract does, with
// an index for a list member: "packs", "pipelines[0].slots", "sinks[1].kind".
// Needs is what would implement it, empty where no configuration can.
type Section struct {
	Path   string
	Needs  []Capability
	Detail string
}

// Unimplemented refuses a configuration that asks for something this program
// does not do. Every such section is named, not just the first, and none is
// ever read and ignored: a redaction request silently dropped would leave the
// operator believing their plaintext was handled.
//
// This program implements what the contract's no-extension example needs. It
// refuses:
//
//	pipelines[i].slots          any slot, while Inventory holds no
//	                            processor                           processing
//	packs                       any pack                            processing, plugins
//	subscribers                 any subscriber, while Inventory
//	                            holds no subscriber                 processing
//	policy                      any policy document                 processing
//	retention_and_export.retain_plaintext
//	                            false, while every sink kind keeps
//	                            plaintext                           processing
//	pipelines                   no pipeline carrying reconstruction,
//	                            or none carrying connection, to a
//	                            local_account sink: the spool keeps
//	                            both, so routing neither is
//	                            filtering                           processing
//	sinks[i].kind               any kind but local_account, while
//	                            Inventory holds no other kind       none
//	retention_and_export.export_sinks
//	                            any export sink, while no sink kind
//	                            leaves the host                     none
//	traffic_scope.rules[i]      a rule naming targets, a direction
//	                            other than any, or any port: every
//	                            connection of an approved instance
//	                            is captured                         processing
//
// NONE of a kind in Inventory is unimplemented. SOME of a kind without the one
// named is the operator's error and stays a composition refusal (*Refused).
// Rows with nothing in the inventory to count are refused whenever asked for.
type Unimplemented struct {
	Sections []Section
}

func (u *Unimplemented) Error() string {
	lines := make([]string, 0, len(u.Sections))
	for _, section := range u.Sections {
		lines = append(lines, fmt.Sprintf("%s: %s; this program does not implement it, and %s",
			section.Path, section.Detail, needs(section.Needs)))
	}
	return "it asks for what this program does not do: " + strings.Join(lines, "; ")
}

// Refused is a configuration the contract's own check refused, with the
// check's findings unchanged.
type Refused struct {
	Outcome  config.Outcome
	Findings []config.Finding
}

func (r *Refused) Error() string {
	lines := make([]string, 0, len(r.Findings))
	for _, finding := range r.Findings {
		subject := finding.Subject
		if subject == "" {
			subject = finding.Document
		}
		lines = append(lines, fmt.Sprintf("%s: %s: %s", subject, finding.Reason, finding.Detail))
	}
	return fmt.Sprintf("%s: %s", r.Outcome, strings.Join(lines, "; "))
}

// Unanswerable refuses a target whose two descendant answers name no admission
// mode. The contract treats the answers as independent; admission has three
// modes, and following future descendants without the existing ones is not one.
type Unanswerable struct {
	Target   string
	Existing bool
	Future   bool
}

func (u *Unanswerable) Error() string {
	return fmt.Sprintf("target %q answers existing %t and future %t, and admission has no mode giving that "+
		"pair: none is false and false, existing is true and false, follow is true and true",
		u.Target, u.Existing, u.Future)
}
