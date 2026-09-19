package config

import "encoding/json"

// Manifest is a pack's document. It declares; it does not establish: accepting
// it means it is well formed and composes, never that the pack behaves as
// declared.
type Manifest struct {
	Version     string `json:"version"`
	Name        string `json:"name"`
	PackVersion string `json:"pack_version"`

	// Components are the external implementations this pack supplies. A
	// configuration-only pack supplies none and selects built-ins.
	Components []Component `json:"components"`

	// Pipelines are pipelines the pack adds, composed exactly as an operator's.
	Pipelines []Pipeline `json:"pipelines"`

	// Replacements select a different implementation for a slot of a pipeline
	// the operator configured or another enabled pack added.
	Replacements []Replacement `json:"replacements"`

	// Policy is the pack's policy documents, in contract/policy's vocabulary,
	// loaded with the pack as their source.
	Policy []json.RawMessage `json:"policy"`
}

// Replacement selects an implementation for one slot. The implementation is
// resolved in the effective available component set: the runtime's built-ins
// and the components every enabled pack supplies. Supplying the implementation
// is not required, and selecting an available built-in is a replacement.
//
// A replacement inherits every ordering on the slot: those declared by the
// component it replaces, and those other components declare naming it. An
// ordering never disappears because the component it names was replaced, and a
// replacement that cannot satisfy an inherited ordering is refused as
// incompatible with its slot.
type Replacement struct {
	Pipeline       string          `json:"pipeline"`
	Slot           string          `json:"slot"`
	Implementation string          `json:"implementation"`
	Configuration  json.RawMessage `json:"configuration,omitempty"`
}
