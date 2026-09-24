package account

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/evandukss/edge-observer/contract/record"
)

// shape reads an account document against the Go types that encode the
// contract, member by member, so presence is decided before any value is read:
// a required block that is absent is a finding and never a zero.
type shape struct {
	member   string
	findings []Finding
	blocks   int
	// states is every block's state by its dotted path, for the moment rules.
	states map[string]BlockState
}

var (
	blockType   = reflect.TypeFor[Block]()
	rawType     = reflect.TypeFor[json.RawMessage]()
	instantType = reflect.TypeFor[record.Instant]()
	birthType   = reflect.TypeFor[record.Birth]()
	countType   = reflect.TypeFor[record.Count]()
	textType    = reflect.TypeFor[record.Text]()
	nsType      = reflect.TypeFor[record.Namespace]()
	decimal     = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
)

func (s *shape) find(at string, reason Reason, format string, args ...any) {
	s.findings = append(s.findings, Finding{Member: s.member, At: at, Reason: reason, Detail: fmt.Sprintf(format, args...)})
}

// object decodes one JSON object into its members, keeping null apart from
// absence only to treat them alike.
func object(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &members); err != nil {
		return nil, false
	}
	return members, true
}

func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// field is one member a struct type names.
type field struct {
	name     string
	index    int
	typ      reflect.Type
	optional bool
	count    bool
	identity bool
}

// fieldsOf is the members a struct names, with an embedded Block's own members
// left out: those are read before anything else.
func fieldsOf(typ reflect.Type) ([]field, bool) {
	if typ == blockType {
		return nil, true
	}
	var fields []field
	isBlock := false
	for i := range typ.NumField() {
		one := typ.Field(i)
		if one.Anonymous && one.Type == blockType {
			isBlock = true
			continue
		}
		if one.Anonymous && one.Type.Kind() == reflect.Struct {
			inner, _ := fieldsOf(one.Type)
			fields = append(fields, inner...)
			continue
		}
		name, _, _ := strings.Cut(one.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		tags := strings.Split(one.Tag.Get("account"), ",")
		fields = append(fields, field{name: name, index: i, typ: one.Type,
			optional: slices.Contains(tags, "optional"), count: slices.Contains(tags, "count"),
			identity: slices.Contains(tags, "identity")})
	}
	return fields, isBlock
}

func hasBlock(typ reflect.Type) bool {
	if typ.Kind() != reflect.Struct {
		return false
	}
	_, isBlock := fieldsOf(typ)
	return isBlock
}

// value reads one member's value against its type. at is its dotted path.
func (s *shape) value(raw json.RawMessage, typ reflect.Type, at string, count bool) {
	switch typ {
	case rawType:
		return
	case instantType, birthType, countType, textType, nsType:
		s.primitive(raw, typ, at)
		return
	}
	switch typ.Kind() {
	case reflect.Pointer:
		s.value(raw, typ.Elem(), at, count)
	case reflect.Struct:
		s.structure(raw, typ, at)
	case reflect.Slice:
		var elements []json.RawMessage
		if err := json.Unmarshal(raw, &elements); err != nil || isNull(raw) {
			s.find(at, ValueNotInContract, "a list is expected")
			return
		}
		for index, element := range elements {
			s.value(element, typ.Elem(), fmt.Sprintf("%s[%d]", at, index), false)
		}
	case reflect.Map:
		members, ok := object(raw)
		if !ok {
			s.find(at, ValueNotInContract, "an object is expected")
			return
		}
		for _, key := range slices.Sorted(mapsKeys(members)) {
			s.value(members[key], typ.Elem(), at+"."+key, typ.Elem().Kind() == reflect.String)
		}
	case reflect.String:
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			s.find(at, ValueNotInContract, "a string is expected")
			return
		}
		if count && !decimal.MatchString(text) {
			s.find(at, ValueNotInContract, "a count is a decimal string, and %q is not one", text)
		}
	case reflect.Bool:
		var truth bool
		if err := json.Unmarshal(raw, &truth); err != nil {
			s.find(at, ValueNotInContract, "a boolean is expected")
		}
	case reflect.Int, reflect.Int32, reflect.Int64:
		var number int64
		if err := json.Unmarshal(raw, &number); err != nil {
			s.find(at, ValueNotInContract, "an integer is expected")
		}
	}
}

func mapsKeys(m map[string]json.RawMessage) func(func(string) bool) {
	return func(yield func(string) bool) {
		for key := range m {
			if !yield(key) {
				return
			}
		}
	}
}

// primitive reads a record primitive: strictly, and with its value present
// exactly where its state says it is.
func (s *shape) primitive(raw json.RawMessage, typ reflect.Type, at string) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	target := reflect.New(typ)
	if err := decoder.Decode(target.Interface()); err != nil {
		s.find(at, ValueNotInContract, "not a record %s: %v", typ.Name(), err)
		return
	}
	state := record.State(target.Elem().FieldByName("State").String())
	if typ == countType {
		if unit := record.Unit(target.Elem().FieldByName("Unit").String()); !slices.Contains(countUnits, unit) {
			s.find(at, ValueNotInContract, "%q is not a unit a count is in: %v", unit, countUnits)
		}
	}
	value := ""
	if v := target.Elem().FieldByName("Value"); v.IsValid() {
		value = v.String()
	} else if v := target.Elem().FieldByName("Inode"); v.IsValid() {
		value = v.String()
	}
	switch state {
	case record.Determined:
		if value == "" && typ != textType {
			s.find(at, ValueNotInContract, "a determined %s carries its value", typ.Name())
		}
		if (typ == countType || typ == birthType || typ == instantType) && value != "" && !decimal.MatchString(value) {
			s.find(at, ValueNotInContract, "%q is not a decimal string", value)
		}
	case record.Undetermined, record.NotCarried:
		if value != "" {
			s.find(at, ValueNotInContract, "a %s %s carries no value", state, typ.Name())
		}
	default:
		s.find(at, ValueNotInContract, "%q is not a record state", state)
	}
}

// countUnits is every unit a record count is in.
var countUnits = []record.Unit{record.Bytes, record.Events, record.Fragments, record.Calls, record.Instances,
	record.Places, record.DescriptorLifetimes, record.Bindings}

// structure reads one object against a struct type.
func (s *shape) structure(raw json.RawMessage, typ reflect.Type, at string) {
	members, ok := object(raw)
	if !ok {
		s.find(at, AccountMalformed, "an object is expected")
		return
	}
	fields, isBlock := fieldsOf(typ)
	named, identity := map[string]bool{}, map[string]bool{}
	for _, one := range fields {
		named[one.name] = true
		identity[one.name] = one.identity
	}

	if isBlock {
		s.blocks++
		state, carried := s.blockState(members, at)
		if state != "" {
			s.states[at] = state
		}
		if !carried {
			// A block that is not carried holds no values, and nothing in it
			// is read as one.
			for _, key := range slices.Sorted(mapsKeys(members)) {
				if key == "state" || key == "why" {
					continue
				}
				if !named[key] {
					s.find(joinAt(at, key), MemberNotInContract, "the contract names no %q here", key)
					continue
				}
				if !identity[key] && !empty(members[key]) {
					s.find(joinAt(at, key), MemberNotInContract,
						"a %s block holds no values, and this one holds %s", state, strings.TrimSpace(string(members[key])))
				}
			}
			return
		}
	}

	for _, key := range slices.Sorted(mapsKeys(members)) {
		if !named[key] && (!isBlock || (key != "state" && key != "why")) {
			s.find(joinAt(at, key), MemberNotInContract, "the contract names no %q here", key)
		}
	}
	for _, one := range fields {
		child := joinAt(at, one.name)
		raw, present := members[one.name]
		if !present || isNull(raw) {
			switch {
			case one.optional:
			case hasBlock(one.typ):
				s.find(child, RequiredBlockAbsent, "the block %s is required and absent, and it is not read as zeros", child)
			default:
				s.find(child, RequiredMemberAbsent, "the member %s is required and absent", child)
			}
			continue
		}
		s.value(raw, one.typ, child, one.count)
	}
}

// blockState reads a block's state. It reports whether the block is carried.
func (s *shape) blockState(members map[string]json.RawMessage, at string) (BlockState, bool) {
	raw, present := members["state"]
	if !present {
		s.find(joinAt(at, "state"), RequiredMemberAbsent, "a block says whether it is carried")
		return "", false
	}
	var state BlockState
	if err := json.Unmarshal(raw, &state); err != nil {
		s.find(joinAt(at, "state"), UnknownBlockState, "a block state is a string")
		return "", false
	}
	switch state {
	case Carried, NotReached, NotCarried:
	case Unavailable:
		var why string
		if err := json.Unmarshal(members["why"], &why); err != nil || why == "" {
			s.find(joinAt(at, "why"), RequiredMemberAbsent, "an unavailable block says why")
		}
	default:
		s.find(joinAt(at, "state"), UnknownBlockState, "%q is not a block state", state)
		return "", false
	}
	return state, state == Carried
}

// empty is a value that holds nothing: "", false, 0, null, [], {}, or an object
// whose members are all empty.
func empty(raw json.RawMessage) bool {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return false
	}
	var holdsNothing func(any) bool
	holdsNothing = func(value any) bool {
		switch typed := value.(type) {
		case nil:
			return true
		case string:
			return typed == ""
		case bool:
			return !typed
		case json.Number:
			return typed.String() == "0"
		case []any:
			return len(typed) == 0
		case map[string]any:
			for _, member := range typed {
				if !holdsNothing(member) {
					return false
				}
			}
			return true
		}
		return false
	}
	return holdsNothing(value)
}

// permitted is which states each top-level block may have at each moment.
var permitted = map[string]map[Moment][]BlockState{
	"provenance": {Planned: {Carried}, Live: {Carried}, Sealed: {Carried}},
	"scope":      {Planned: {Carried}, Live: {Carried}, Sealed: {Carried}},
	"capture": {Planned: {NotReached}, Live: {Carried, Unavailable},
		Sealed: {Carried, Unavailable}},
	// reconstruction may be NotCarried where capture may not: it runs at read
	// time, so a producer sealing an account does not supply it.
	"reconstruction": {Planned: {NotReached}, Live: {Carried, Unavailable, NotCarried},
		Sealed: {Carried, Unavailable, NotCarried}},
	"processing": {Planned: {Carried, Unavailable, NotCarried}, Live: {Carried, Unavailable, NotCarried},
		Sealed: {Carried, Unavailable, NotCarried}},
	"requirements": {Planned: {Carried, Unavailable, NotCarried}, Live: {Carried, Unavailable, NotCarried},
		Sealed: {Carried, Unavailable, NotCarried}},
	"seal": {Planned: {NotReached}, Live: {NotReached}, Sealed: {Carried, Unavailable}},
}

// namespace is an extension namespace: lower-case dotted, at least two parts,
// so it can never be a core block's name.
var namespace = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// readAccount reads one account document: presence first, then the moment's
// rules, then values. It returns the decoded account only when nothing was
// found.
func readAccount(member string, content []byte) (Account, []Finding, int) {
	s := &shape{member: member, states: map[string]BlockState{}}
	members, ok := object(content)
	if !ok {
		s.find("", AccountMalformed, "an account is one JSON object")
		return Account{}, s.findings, 0
	}
	var version string
	if raw, present := members["account"]; !present || json.Unmarshal(raw, &version) != nil {
		s.find("account", RequiredMemberAbsent, "an account names its contract version")
		return Account{}, s.findings, 0
	}
	if version != Version {
		s.find("account", UnknownAccountVersion, "%q is not %s, and a version this does not know is not read", version, Version)
		return Account{}, s.findings, 0
	}

	s.structure(content, reflect.TypeFor[Account](), "")

	var moment Moment
	if raw, present := members["moment"]; present {
		_ = json.Unmarshal(raw, &moment)
	}
	switch moment {
	case Planned, Live, Sealed:
		for _, block := range slices.Sorted(func(yield func(string) bool) {
			for name := range permitted {
				if !yield(name) {
					return
				}
			}
		}) {
			state, found := s.states[block]
			if found && !slices.Contains(permitted[block][moment], state) {
				s.find(block, BlockStateNotPermitted, "a %s account's %s block may be %v, and this one is %s",
					moment, block, permitted[block][moment], state)
			}
		}
	default:
		if _, present := members["moment"]; present {
			s.find("moment", ValueNotInContract, "%q is not a moment", moment)
		}
	}

	if raw, present := members["extensions"]; present {
		if extensions, ok := object(raw); ok {
			for _, name := range slices.Sorted(mapsKeys(extensions)) {
				if !namespace.MatchString(name) {
					s.find("extensions."+name, ExtensionNamespaceInvalid,
						"a namespace is a lower-case dotted name of at least two parts, and %q is not", name)
				}
			}
		}
	}

	if len(s.findings) > 0 {
		return Account{}, s.findings, s.blocks
	}
	var account Account
	if err := json.Unmarshal(content, &account); err != nil {
		s.find("", AccountMalformed, "%v", err)
		return Account{}, s.findings, s.blocks
	}
	s.vocabulary(account)
	return account, s.findings, s.blocks
}

// vocabulary checks the values that have a closed vocabulary.
func (s *shape) vocabulary(a Account) {
	oneOf := func(at, value string, allowed ...string) {
		if !slices.Contains(allowed, value) {
			s.find(at, ValueNotInContract, "%q is not one of %v", value, allowed)
		}
	}
	if a.Scope.State == Carried {
		if a.Scope.Requested.State == Carried {
			seen := map[string]int{}
			for index, control := range a.Scope.Requested.Controls {
				at := fmt.Sprintf("scope.requested.controls[%d]", index)
				oneOf(at+".control", control.Control, ObservationScope, TrafficScope, RetentionAndExport)
				seen[control.Control]++
				if control.State == Carried && (control.Document == "" || control.Revision == "" || control.Member == "") {
					s.find(at, RequiredMemberAbsent, "a carried control names its document, revision and member")
				}
			}
			for _, control := range []string{ObservationScope, TrafficScope, RetentionAndExport} {
				if seen[control] != 1 {
					s.find("scope.requested.controls", ValueNotInContract,
						"each of the three controls appears once, and %s appears %d times", control, seen[control])
				}
			}
		}
		if a.Scope.Filters.State == Carried {
			for index, filter := range a.Scope.Filters.Filters {
				oneOf(fmt.Sprintf("scope.filters.filters[%d].stage", index), filter.Stage, PreCapture, PostCapture)
			}
		}
	}
	if a.Processing.State == Carried {
		for index, pipeline := range a.Processing.Pipelines {
			at := fmt.Sprintf("processing.pipelines[%d]", index)
			oneOf(at+".activation", pipeline.Activation, "active", "refused")
			for n, output := range pipeline.Outputs {
				oneOf(fmt.Sprintf("%s.outputs[%d].disposition", at, n), output.Disposition, "dispatched", "refused", "dropped")
			}
		}
	}
	if a.Requirements.State == Carried {
		for index, one := range a.Requirements.ExtensionDeclared {
			oneOf(fmt.Sprintf("requirements.extension_declared[%d].disposition", index), one.Disposition, "allow_trusted")
		}
		for index, one := range a.Requirements.Refused {
			oneOf(fmt.Sprintf("requirements.refused[%d].disposition", index), one.Disposition,
				"refuse_activation", "refuse_assurance")
		}
	}
	if a.Scope.State == Carried && a.Scope.Instances.State == Carried {
		for index, one := range a.Scope.Instances.Instances {
			at := fmt.Sprintf("scope.instances.instances[%d]", index)
			oneOf(at+".coverage", one.Coverage, Covered, PartiallyCovered, NotCovered, Excluded, CoverageUndetermined)
			if one.Why == "" && one.Coverage != Covered && one.Coverage != Excluded {
				s.find(at+".why", RequiredMemberAbsent, "a coverage of %s says why", one.Coverage)
			}
			if one.MultiplySelected != (len(one.SelectedBy) > 1) {
				s.find(at+".multiply_selected", ValueNotInContract,
					"multiply_selected is %v and %d targets selected the instance", one.MultiplySelected, len(one.SelectedBy))
			}
		}
	}
	if a.Seal.State == Carried {
		// Each seal count is in the unit of what it counts. A counter this
		// contract has no unit for is carried in whatever unit its producer
		// declares, among the units a count can be in.
		for what, unit := range map[string]record.Unit{"seal.interrupted": record.Calls,
			"seal.drain.delivered": record.Events, "seal.drain.outstanding": record.Events} {
			got := map[string]record.Unit{"seal.interrupted": a.Seal.Interrupted.Unit,
				"seal.drain.delivered": a.Seal.Drain.Delivered.Unit, "seal.drain.outstanding": a.Seal.Drain.Outstanding.Unit}[what]
			if got != unit {
				s.find(what+".unit", ValueNotInContract, "%s counts %s and is carried in %q", what, unit, got)
			}
		}
		for name, count := range a.Seal.Counters {
			if unit, known := counterUnits[name]; known && count.Unit != unit {
				s.find("seal.counters."+name+".unit", ValueNotInContract, "the counter %s counts %s and is carried in %q",
					name, unit, count.Unit)
			}
		}
		for index, identity := range a.Seal.Conserved {
			oneOf(fmt.Sprintf("seal.conserved[%d].holds", index), identity.Holds, "holds", "does_not_hold", "not_evaluated")
		}
	}
}
