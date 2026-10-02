package config

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// MaxCompiledSlots is the most slots the compiler emits for one route, sized
// from the reader's limits: seven removal operations, one per distinct masked
// header value, one per distinct JSON mask value in each message, one per
// distinct truncation length, and one for body_values. The internal layer is
// never what refuses a file the reader accepts.
const MaxCompiledSlots = 7 + MaxMaskedHeaders + 2*MaxRulePointers + MaxTruncatedHeaders + 1

// Compiled is a configuration, read and compiled.
type Compiled struct {
	File File

	Plan *ProcessingPlan

	// ProcessingRevision binds remove, mask, truncate, write_content and the
	// extensions with their resolved commands, and nothing else, so a file that
	// only adds a watch entry keeps it and one that changes any of these does
	// not.
	ProcessingRevision string
}

// Compile reads the configuration and compiles it directly into the plan, in
// the fixed published order: remove, then mask, then truncate, then
// body_values, then the extensions in the order written. directory is the
// absolute directory holding the configuration file: each extension's
// executable written relative is resolved against it once, here, and each must
// be an executable regular file when this runs.
//
// Removal wins over every other rule and is never a conflict. Two rules that
// would keep different values for one field are refused, naming both keys.
// Every refusal names what the user wrote; a refusal from the layer below is an
// internal defect.
func Compile(configuration []byte, directory string) (*Compiled, []Finding) {
	return compile(configuration, directory, true)
}

// CheckDocument is every refusal Compile makes that the configuration's bytes
// decide alone, for reading a configuration away from the host it runs on: an
// extension's command is neither resolved nor looked for.
func CheckDocument(configuration []byte) []Finding {
	_, findings := compile(configuration, "", false)
	return findings
}

func compile(configuration []byte, directory string, onThisHost bool) (*Compiled, []Finding) {
	if len(configuration) > MaxProcessingBytes {
		return nil, []Finding{{Document: "configuration", Reason: ConfigurationTooLarge,
			Detail: fmt.Sprintf("the configuration exceeds %d bytes", MaxProcessingBytes)}}
	}

	file, findings := ReadFile(configuration)
	if len(findings) > 0 {
		return nil, findings
	}
	compiled := &Compiled{File: file}
	documents := []document{{name: "configuration", rules: file.Rules}}

	m := merge(documents)
	if len(m.findings) > 0 {
		return nil, m.findings
	}
	plan, failures := generate(file, m)
	if len(failures) > 0 {
		return nil, failures
	}
	if failures := assertCoverage(documents, plan); len(failures) > 0 {
		return nil, failures
	}
	extensions := file.Extensions
	if onThisHost {
		if extensions, failures = resolveCommands(file.Extensions, directory); len(failures) > 0 {
			return nil, failures
		}
	}
	plan.extensions = extensions
	compiled.Plan = plan
	compiled.ProcessingRevision = revision(file, extensions)
	return compiled, nil
}

// document is one source of rules.
type document struct {
	name  string
	rules Rules
}

// origin is where a rule was written: its document and key.
type origin struct {
	document string
	key      string
}

func (o origin) String() string { return o.document + " " + o.key }

// entry is one distinct rule: the name or pointer it is about, the value or
// length it keeps where it keeps one, where it was first written, and every
// document that wrote it.
type entry struct {
	name      string
	value     string
	number    int
	origin    origin
	documents []string
}

// list is the distinct entries of one rule key, in the order first written.
type list struct {
	entries []entry
	index   map[string]int
}

func (l *list) add(name, value string, number int, at origin) (*entry, bool) {
	if l.index == nil {
		l.index = map[string]int{}
	}
	if i, seen := l.index[name]; seen {
		one := &l.entries[i]
		if !slices.Contains(one.documents, at.document) {
			one.documents = append(one.documents, at.document)
		}
		return one, false
	}
	l.index[name] = len(l.entries)
	l.entries = append(l.entries, entry{name: name, value: value, number: number, origin: at, documents: []string{at.document}})
	return &l.entries[len(l.entries)-1], true
}

// names is every distinct name or pointer, in the order first written.
func (l *list) names() []string {
	var out []string
	for _, one := range l.entries {
		out = append(out, one.name)
	}
	return out
}

func (l *list) documents() []string {
	var out []string
	for _, one := range l.entries {
		for _, d := range one.documents {
			if !slices.Contains(out, d) {
				out = append(out, d)
			}
		}
	}
	return out
}

// merged is every document's rules together, each distinct once.
type merged struct {
	removeHeaders, query, form list
	queryString                []origin
	removeJSON                 map[string]*list
	bodies, bodyValues         map[string][]origin
	maskHeaders                list
	maskJSON                   map[string]*list
	truncate                   list
	findings                   []Finding
}

func (m *merged) refuse(at origin, reason Reason, detail string, arguments ...any) {
	m.findings = append(m.findings, Finding{Document: at.document, Subject: at.key, Reason: reason,
		Detail: fmt.Sprintf(detail, arguments...)})
}

// limit refuses a distinct entry past the most one operation takes.
func (m *merged) limit(fresh bool, l *list, most int, at origin, what string) {
	if fresh && len(l.entries) == most+1 {
		m.refuse(at, LimitExceeded, "the configuration names more than %d distinct %s, "+
			"and one operation takes at most %d", most, what, most)
	}
}

func merge(documents []document) *merged {
	m := &merged{removeJSON: map[string]*list{MessageRequest: {}, MessageResponse: {}},
		maskJSON: map[string]*list{MessageRequest: {}, MessageResponse: {}},
		bodies:   map[string][]origin{}, bodyValues: map[string][]origin{}}
	for _, d := range documents {
		at := func(key string, i int) origin { return origin{document: d.name, key: fmt.Sprintf("%s[%d]", key, i)} }
		r := d.rules
		for i, name := range r.Remove.Headers {
			_, fresh := m.removeHeaders.add(strings.ToLower(name), strings.ToLower(name), 0, at("remove.headers", i))
			m.limit(fresh, &m.removeHeaders, MaxRemovedHeaders, at("remove.headers", i), "removed headers")
		}
		for i, name := range r.Remove.Query {
			_, fresh := m.query.add(name, name, 0, at("remove.query", i))
			m.limit(fresh, &m.query, MaxRuleNames, at("remove.query", i), "removed query parameters")
		}
		if r.Remove.QueryString {
			m.queryString = append(m.queryString, origin{document: d.name, key: "remove.query_string"})
		}
		for i, name := range r.Remove.Form {
			_, fresh := m.form.add(name, name, 0, at("remove.form", i))
			m.limit(fresh, &m.form, MaxRuleNames, at("remove.form", i), "removed form parameters")
		}
		for _, byMessage := range []struct {
			message  string
			pointers []string
		}{{MessageRequest, r.Remove.JSON.Request}, {MessageResponse, r.Remove.JSON.Response}} {
			message, pointers := byMessage.message, byMessage.pointers
			key := "remove.json." + message
			for i, pointer := range pointers {
				_, fresh := m.removeJSON[message].add(pointer, pointer, 0, at(key, i))
				m.limit(fresh, m.removeJSON[message], MaxRulePointers, at(key, i), "removed "+message+" JSON pointers")
			}
		}
		for i, message := range r.Remove.Bodies {
			m.bodies[message] = append(m.bodies[message], at("remove.bodies", i))
		}
		for i, message := range r.Remove.BodyValues {
			m.bodyValues[message] = append(m.bodyValues[message], at("remove.body_values", i))
		}
	}
	// Masks and truncations, once every removal is known: a rule on a field a
	// removal takes away is moot and never a conflict.
	removedHeader := func(name string) bool { _, removed := m.removeHeaders.index[name]; return removed }
	for _, d := range documents {
		r := d.rules
		for _, one := range r.Mask.Headers {
			name := strings.ToLower(one.Name)
			at := origin{document: d.name, key: "mask.headers." + one.Name}
			first, fresh := m.maskHeaders.add(name, one.Value, 0, at)
			m.limit(fresh, &m.maskHeaders, MaxMaskedHeaders, at, "masked headers")
			if !fresh && first.value != one.Value && !removedHeader(name) {
				m.refuse(at, RuleConflict, "masks %s as %q, and %s masks it as %q: two rules that would keep "+
					"different values for one field are refused", name, one.Value, first.origin, first.value)
			}
		}
		for _, one := range r.Truncate.Headers {
			name := strings.ToLower(one.Name)
			at := origin{document: d.name, key: "truncate.headers." + one.Name}
			first, fresh := m.truncate.add(name, name, one.Length, at)
			m.limit(fresh, &m.truncate, MaxTruncatedHeaders, at, "truncated headers")
			if !fresh && first.number != one.Length && !removedHeader(name) {
				m.refuse(at, RuleConflict, "truncates %s to %d bytes, and %s truncates it to %d: two rules that "+
					"would keep different values for one field are refused", name, one.Length, first.origin, first.number)
			}
		}
		for _, byMessage := range []struct {
			message string
			values  []NamedValue
		}{{MessageRequest, r.Mask.JSON.Request}, {MessageResponse, r.Mask.JSON.Response}} {
			message := byMessage.message
			for _, one := range byMessage.values {
				at := origin{document: d.name, key: "mask.json." + message + "." + one.Name}
				first, fresh := m.maskJSON[message].add(one.Name, one.Value, 0, at)
				m.limit(fresh, m.maskJSON[message], MaxRulePointers, at, message+" JSON masks")
				if !fresh && first.value != one.Value && !m.removedPointer(message, one.Name) {
					m.refuse(at, RuleConflict, "masks %s as %q, and %s masks it as %q: two rules that would keep "+
						"different values for one field are refused", one.Name, one.Value, first.origin, first.value)
				}
			}
		}
	}
	// Mask against truncate on one header, and masks whose pointers may match
	// one field with different values.
	for _, truncated := range m.truncate.entries {
		name := truncated.name
		if i, masked := m.maskHeaders.index[name]; masked && !removedHeader(name) {
			mask := m.maskHeaders.entries[i]
			m.refuse(truncated.origin, RuleConflict, "truncates %s, and %s masks it: a masked and a truncated "+
				"value are two different values for one field", name, mask.origin)
		}
	}
	for _, message := range []string{MessageRequest, MessageResponse} {
		masks := m.maskJSON[message].entries
		for i := range masks {
			for j := i + 1; j < len(masks); j++ {
				a, b := masks[i], masks[j]
				if a.value == b.value || !mayMatch(PointerTokens(a.name), PointerTokens(b.name)) {
					continue
				}
				if m.removedPointer(message, a.name) || m.removedPointer(message, b.name) {
					continue
				}
				m.refuse(b.origin, RuleConflict, "masks %s as %q, and %s masks %s as %q: the two pointers may "+
					"match one field, and would keep different values for it", b.name, b.value, a.origin,
					a.name, a.value)
			}
		}
	}
	return m
}

// removedPointer is whether a removal in message takes away everything
// pointer can match: a removal pointer that may match a prefix of it.
func (m *merged) removedPointer(message, pointer string) bool {
	want := PointerTokens(pointer)
	for _, removal := range m.removeJSON[message].entries {
		tokens := PointerTokens(removal.name)
		if len(tokens) <= len(want) && mayMatch(tokens, want[:len(tokens)]) {
			return true
		}
	}
	return false
}

// mayMatch is the static overlap of two pointers: one token list is a prefix
// of the other, and each pair of tokens is equal under simple case folding or
// one of them is "*".
func mayMatch(a, b []string) bool {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != "*" && b[i] != "*" && !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}

// generate compiles the merged rules into the plan: one exchanges pipeline
// holding every rule in the fixed order, written only when content is, and one
// connections pipeline. Every slot's arguments pass the internal layer's own
// check; a refusal there is the observer's defect.
func generate(file File, m *merged) (*ProcessingPlan, []Finding) {
	plan := &ProcessingPlan{resolved: Resolved{Observer: ResolvedObserver{
		Log: file.Log, Directory: file.Output,
		StateEverySeconds: file.Limits.StateEverySeconds, AdmittedEventLimit: file.Limits.Events,
		Workers: file.Limits.Workers,
	}}}
	var failures []Finding
	var slots []EffectiveSlot
	add := func(name, implementation string, arguments map[string]any, documents []string) {
		raw, err := json.Marshal(arguments)
		if err == nil {
			var args *Arguments
			if args, err = compileArguments(implementation, raw); err == nil {
				slots = append(slots, EffectiveSlot{Name: name, Implementation: implementation, Configuration: raw,
					Arguments: args, SelectedBy: strings.Join(documents, ",")})
				return
			}
		}
		failures = append(failures, Finding{Document: "configuration", Subject: name, Reason: InternalDefect,
			Detail: fmt.Sprintf("the internal layer refused the %s operation compiled from %s: %v; this is an "+
				"observer defect, not the configuration's error", implementation, strings.Join(documents, ", "), err)})
	}
	messages := func(set map[string][]origin) ([]string, []string) {
		var out, documents []string
		for _, message := range []string{MessageRequest, MessageResponse} {
			if len(set[message]) == 0 {
				continue
			}
			out = append(out, message)
			for _, at := range set[message] {
				if !slices.Contains(documents, at.document) {
					documents = append(documents, at.document)
				}
			}
		}
		return out, documents
	}

	// Remove.
	if len(m.removeHeaders.entries) > 0 {
		add("remove.headers", RemoveHeaders, map[string]any{"headers": m.removeHeaders.names()}, m.removeHeaders.documents())
	}
	if len(m.queryString) > 0 {
		var documents []string
		for _, at := range m.queryString {
			if !slices.Contains(documents, at.document) {
				documents = append(documents, at.document)
			}
		}
		add("remove.query_string", RemoveQuery, map[string]any{}, documents)
	}
	if len(m.query.entries) > 0 {
		add("remove.query", RemoveQueryParameters, map[string]any{"names": m.query.names()}, m.query.documents())
	}
	if selected, documents := messages(m.bodies); len(selected) > 0 {
		add("remove.bodies", RemoveBody, map[string]any{"messages": selected}, documents)
	}
	requestJSON, requestMasks := m.removeJSON[MessageRequest], m.maskJSON[MessageRequest]
	combined := len(m.form.entries) > 0 && (len(requestJSON.entries) > 0 || len(requestMasks.entries) > 0)
	if combined {
		// Form and JSON rules on the request together: one operation reads each
		// request body by the grammar the body and its labels allow.
		var masks []map[string]string
		for _, one := range requestMasks.entries {
			masks = append(masks, map[string]string{"pointer": one.name, "value": one.value})
		}
		documents := m.form.documents()
		for _, d := range append(requestJSON.documents(), requestMasks.documents()...) {
			if !slices.Contains(documents, d) {
				documents = append(documents, d)
			}
		}
		add("remove.form+json.request", RequestBodyFields, map[string]any{"names": m.form.names(),
			"pointers": nonNil(requestJSON.names()), "masks": nonNilMasks(masks)}, documents)
	} else {
		if len(m.form.entries) > 0 {
			add("remove.form", RemoveFormFields, map[string]any{"names": m.form.names()}, m.form.documents())
		}
		if len(requestJSON.entries) > 0 {
			add("remove.json.request", RemoveJSONFields, map[string]any{"messages": []string{MessageRequest},
				"pointers": requestJSON.names()}, requestJSON.documents())
		}
	}
	if response := m.removeJSON[MessageResponse]; len(response.entries) > 0 {
		add("remove.json.response", RemoveJSONFields, map[string]any{"messages": []string{MessageResponse},
			"pointers": response.names()}, response.documents())
	}

	// Mask: one operation per distinct value, in the order first written.
	for i, group := range groupByValue(m.maskHeaders.entries) {
		add(fmt.Sprintf("mask.headers.%d", i+1), ReplaceHeaderValues,
			map[string]any{"headers": group.names, "value": group.value}, group.documents)
	}
	for _, message := range []string{MessageRequest, MessageResponse} {
		if message == MessageRequest && combined {
			continue
		}
		for i, group := range groupByValue(m.maskJSON[message].entries) {
			add(fmt.Sprintf("mask.json.%s.%d", message, i+1), ReplaceJSONValues, map[string]any{
				"messages": []string{message}, "pointers": group.names, "value": group.value}, group.documents)
		}
	}

	// Truncate: one operation per distinct length.
	lengths := map[int]int{}
	var byLength []struct {
		length    int
		names     []string
		documents []string
	}
	for _, one := range m.truncate.entries {
		i, seen := lengths[one.number]
		if !seen {
			i = len(byLength)
			lengths[one.number] = i
			byLength = append(byLength, struct {
				length    int
				names     []string
				documents []string
			}{length: one.number})
		}
		byLength[i].names = append(byLength[i].names, one.name)
		for _, d := range one.documents {
			if !slices.Contains(byLength[i].documents, d) {
				byLength[i].documents = append(byLength[i].documents, d)
			}
		}
	}
	for i, group := range byLength {
		add(fmt.Sprintf("truncate.headers.%d", i+1), TruncateHeaderValues,
			map[string]any{"headers": group.names, "length": group.length}, group.documents)
	}

	// body_values.
	if selected, documents := messages(m.bodyValues); len(selected) > 0 {
		add("remove.body_values", ReduceBodyToStructure, map[string]any{"messages": selected}, documents)
	}

	if len(failures) > 0 {
		return nil, failures
	}
	if len(slots) > MaxCompiledSlots {
		return nil, []Finding{{Document: "configuration", Reason: InternalDefect, Detail: fmt.Sprintf(
			"the rules compiled to %d operations, above the %d the reader's limits allow; this is an observer "+
				"defect, not the configuration's error", len(slots), MaxCompiledSlots)}}
	}

	if file.WriteContent {
		plan.resolved.Pipelines = append(plan.resolved.Pipelines, EffectivePipeline{Name: ExchangesPipeline,
			Input: ReconstructionInput, Slots: slots, Sinks: []string{AccountSink}})
		plan.routes = append(plan.routes, DurableRoute{Pipeline: ExchangesPipeline, Sink: AccountSink, Kind: LocalAccountKind})
	}
	plan.resolved.Pipelines = append(plan.resolved.Pipelines, EffectivePipeline{Name: ConnectionsPipeline,
		Input: ConnectionInput, Slots: []EffectiveSlot{}, Sinks: []string{AccountSink}})
	plan.routes = append(plan.routes, DurableRoute{Pipeline: ConnectionsPipeline, Sink: AccountSink, Kind: LocalAccountKind})

	plan.exclusions = exclusionsOf(m)
	return plan, nil
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nonNilMasks(masks []map[string]string) []map[string]string {
	if masks == nil {
		return []map[string]string{}
	}
	return masks
}

// valueGroup is the names one operation carries with one value.
type valueGroup struct {
	value     string
	names     []string
	documents []string
}

func groupByValue(entries []entry) []valueGroup {
	var groups []valueGroup
	index := map[string]int{}
	for _, one := range entries {
		i, seen := index[one.value]
		if !seen {
			i = len(groups)
			index[one.value] = i
			groups = append(groups, valueGroup{value: one.value})
		}
		groups[i].names = append(groups[i].names, one.name)
		for _, d := range one.documents {
			if !slices.Contains(groups[i].documents, d) {
				groups[i].documents = append(groups[i].documents, d)
			}
		}
	}
	return groups
}

// exclusionsOf is one mandatory exclusion per distinct removal.
func exclusionsOf(m *merged) []Exclusion {
	var out []Exclusion
	add := func(at origin, field, header string, messages ...string) {
		out = append(out, Exclusion{Declaration: at.String(), Field: field, Header: header, Messages: messages})
	}
	for _, one := range m.removeHeaders.entries {
		add(one.origin, HeaderFieldPrefix+one.name, one.name, MessageRequest)
	}
	if len(m.queryString) > 0 {
		add(m.queryString[0], TargetQueryField, "", MessageRequest)
	}
	for _, one := range m.query.entries {
		add(one.origin, QueryFieldPrefix+one.name, "", MessageRequest)
	}
	for _, one := range m.form.entries {
		add(one.origin, FormFieldPrefix+one.name, "", MessageRequest)
	}
	for _, message := range []string{MessageRequest, MessageResponse} {
		for _, one := range m.removeJSON[message].entries {
			add(one.origin, JSONFieldPrefix+one.name, "", message)
		}
	}
	for _, message := range []string{MessageRequest, MessageResponse} {
		if at := m.bodies[message]; len(at) > 0 {
			add(at[0], BodyField, "", message)
		}
	}
	for _, message := range []string{MessageRequest, MessageResponse} {
		if at := m.bodyValues[message]; len(at) > 0 {
			add(at[0], BodyValuesField, "", message)
		}
	}
	return out
}

// assertCoverage holds the plan to the documents as parsed, not to what the
// compiler made of them: every removal any document wrote compiles to an
// exclusion AND, on every route that writes content, an operation that
// removes it from each message it names. A mismatch fails closed as the
// observer's defect, so a compiler that drops a removal can never start.
func assertCoverage(documents []document, plan *ProcessingPlan) []Finding {
	var failures []Finding
	check := func(d document, key, field string, messages ...string) {
		parsed, err := ParseExclusionField(field)
		if err != nil {
			failures = append(failures, Finding{Document: d.name, Subject: key, Reason: InternalDefect,
				Detail: fmt.Sprintf("the removal compiles to no exclusion field: %v", err)})
			return
		}
		for _, message := range messages {
			if !slices.ContainsFunc(plan.exclusions, func(e Exclusion) bool {
				return e.Field == field && slices.Contains(e.Messages, message)
			}) {
				failures = append(failures, Finding{Document: d.name, Subject: key, Reason: InternalDefect,
					Detail: fmt.Sprintf("the compiled plan records no exclusion of %s from the %s; the observer "+
						"refuses to start rather than not enforce it", field, message)})
			}
			for _, pipeline := range plan.resolved.Pipelines {
				if pipeline.Input != ReconstructionInput {
					continue
				}
				if !slices.ContainsFunc(pipeline.Slots, func(s EffectiveSlot) bool {
					return slices.Contains(covers(s, parsed), message)
				}) {
					failures = append(failures, Finding{Document: d.name, Subject: key, Reason: InternalDefect,
						Detail: fmt.Sprintf("nothing on route %s removes %s from the %s; the observer refuses to "+
							"start rather than write it", pipeline.Name, field, message)})
				}
			}
		}
	}
	for _, d := range documents {
		r := d.rules.Remove
		for i, name := range r.Headers {
			check(d, fmt.Sprintf("remove.headers[%d]", i), HeaderFieldPrefix+strings.ToLower(name), MessageRequest)
		}
		if r.QueryString {
			check(d, "remove.query_string", TargetQueryField, MessageRequest)
		}
		for i, name := range r.Query {
			check(d, fmt.Sprintf("remove.query[%d]", i), QueryFieldPrefix+name, MessageRequest)
		}
		for i, name := range r.Form {
			check(d, fmt.Sprintf("remove.form[%d]", i), FormFieldPrefix+name, MessageRequest)
		}
		for i, pointer := range r.JSON.Request {
			check(d, fmt.Sprintf("remove.json.request[%d]", i), JSONFieldPrefix+pointer, MessageRequest)
		}
		for i, pointer := range r.JSON.Response {
			check(d, fmt.Sprintf("remove.json.response[%d]", i), JSONFieldPrefix+pointer, MessageResponse)
		}
		for i, message := range r.Bodies {
			check(d, fmt.Sprintf("remove.bodies[%d]", i), BodyField, message)
		}
		for i, message := range r.BodyValues {
			check(d, fmt.Sprintf("remove.body_values[%d]", i), BodyValuesField, message)
		}
	}
	return failures
}

// revision digests what the processing revision binds: the rules as read,
// write_content, and the extensions as resolved.
func revision(file File, extensions []Extension) string {
	declaration, _ := json.Marshal(struct {
		Rules        Rules
		WriteContent bool
		Extensions   []Extension
	}{file.Rules, file.WriteContent, extensions})
	digest := sha256.New()
	digest.Write([]byte("observer.processing.generation/2"))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(declaration)))
	digest.Write(size[:])
	digest.Write(declaration)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}
