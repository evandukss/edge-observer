package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/evandukss/edge-observer/contract/policy"
)

// decode reads one document of one kind. Every member is defined by its
// type and an undefined one is refused, a member named in another case is
// refused, a key written twice is refused because the decoder would keep only
// the second, and nothing may follow the document.
func decode(content []byte, into any) error {
	if err := duplicateKeys(content); err != nil {
		return err
	}
	if err := exactMembers(content, reflect.TypeOf(into).Elem()); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("something follows the document, and a document is one value")
	}
	return nil
}

// exactMembers refuses a member whose name matches a defined one only when case
// is ignored. The decoder matches member names case-insensitively, so without
// this "VERSION" is read as the version and never reaches the unknown-member
// refusal, and "Packs" written after "packs" silently replaces it.
func exactMembers(content []byte, of reflect.Type) error {
	var document any
	if err := json.Unmarshal(content, &document); err != nil {
		// A document that is not JSON at all is the decoder's to refuse, in
		// its own words.
		return nil
	}
	return exact(document, of, "")
}

var rawMessage = reflect.TypeOf(json.RawMessage{})

func exact(value any, of reflect.Type, path string) error {
	for of.Kind() == reflect.Pointer {
		of = of.Elem()
	}
	if of == rawMessage {
		return nil
	}
	switch of.Kind() {
	case reflect.Struct:
		object, is := value.(map[string]any)
		if !is {
			return nil
		}
		members := map[string]reflect.Type{}
		collectMembers(of, members)
		for key, member := range object {
			at := key
			if path != "" {
				at = path + "." + key
			}
			if field, defined := members[key]; defined {
				if err := exact(member, field, at); err != nil {
					return err
				}
				continue
			}
			for name := range members {
				if strings.EqualFold(name, key) {
					return fmt.Errorf("%q is not a member; the member is %q, and a name is matched exactly", at, name)
				}
			}
		}
	case reflect.Map:
		object, is := value.(map[string]any)
		if !is {
			return nil
		}
		for key, member := range object {
			if err := exact(member, of.Elem(), path+"."+key); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		list, is := value.([]any)
		if !is {
			return nil
		}
		for index, member := range list {
			if err := exact(member, of.Elem(), fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

// collectMembers is every member name a struct's decoding reads, with the
// members of an embedded struct read as its own.
func collectMembers(of reflect.Type, into map[string]reflect.Type) {
	for i := range of.NumField() {
		field := of.Field(i)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if field.Anonymous && name == "" {
			embedded := field.Type
			for embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct {
				collectMembers(embedded, into)
				continue
			}
		}
		if !field.IsExported() {
			continue
		}
		if name == "" {
			name = field.Name
		}
		into[name] = field.Type
	}
}

// ReadConfiguration reads a configuration structurally, as Check does before
// composition, and returns what it read with the structural findings. A
// program that implements a subset of what the contract accepts reads what was
// written here before composing it against what it has.
func ReadConfiguration(content []byte) (Configuration, []Finding) {
	return readConfiguration(content)
}

// findings collects structural findings for one document.
type findings struct {
	document string
	list     []Finding
}

func (f *findings) add(path string, reason Reason, detail string, arguments ...any) {
	f.list = append(f.list, Finding{Document: f.document, Subject: path, Reason: reason, Detail: fmt.Sprintf(detail, arguments...)})
}

func (f *findings) required(path, value string) {
	if value == "" {
		f.add(path, Malformed, "required and absent")
	}
}

func (f *findings) oneOf(path, value string, allowed ...string) {
	if value == "" {
		f.add(path, Malformed, "required and absent")
	} else if !slices.Contains(allowed, value) {
		f.add(path, Malformed, "%q is not one of %v", value, allowed)
	}
}

func (f *findings) unique(path string, names []string) {
	seen := map[string]bool{}
	for _, name := range names {
		if name != "" && seen[name] {
			f.add(path, DuplicateName, "%q is named twice", name)
		}
		seen[name] = true
	}
}

func (f *findings) policy(path string, documents []json.RawMessage) {
	for index, raw := range documents {
		var document policy.Document
		if err := decode(raw, &document); err != nil {
			f.add(fmt.Sprintf("%s[%d]", path, index), Malformed, "not a policy document: %v", err)
		}
	}
}

func readConfiguration(content []byte) (Configuration, []Finding) {
	f := &findings{document: "configuration"}
	var c Configuration
	if err := decode(content, &c); err != nil {
		f.add("", Malformed, "%v", err)
		return c, f.list
	}
	if c.Version != ConfigurationVersion {
		f.add("version", UnknownVersion, "%q is not %s", c.Version, ConfigurationVersion)
		return c, f.list
	}

	f.required("observer.log", c.Observer.Log)
	f.required("observer.directory", c.Observer.Directory)
	if c.Observer.Log != "" && c.Observer.Log != "stdout" && !filepath.IsAbs(c.Observer.Log) {
		f.add("observer.log", Malformed, "%q is neither an absolute path nor stdout", c.Observer.Log)
	}
	if c.Observer.Directory != "" && !filepath.IsAbs(c.Observer.Directory) {
		f.add("observer.directory", Malformed, "%q is not an absolute path", c.Observer.Directory)
	}
	for _, member := range []struct {
		path  string
		value *int64
	}{{"observer.spool_bound_mib", c.Observer.SpoolBoundMiB}, {"observer.state_every_seconds", c.Observer.StateEverySeconds}} {
		if member.value != nil && *member.value < 1 {
			f.add(member.path, Malformed, "%d is not above zero", *member.value)
		}
	}

	if len(c.ObservationScope.Targets) == 0 {
		f.add("observation_scope.targets", Malformed, "a configuration that selects no instance observes nothing")
	}
	var targets []string
	for i, t := range c.ObservationScope.Targets {
		path := fmt.Sprintf("observation_scope.targets[%d]", i)
		f.required(path+".name", t.Name)
		targets = append(targets, t.Name)
		match(f, path+".match", t.Match)
		d := t.Descendants
		if d.Existing == nil {
			f.add(path+".descendants.existing", Malformed, "required and absent")
		}
		if d.Future == nil {
			f.add(path+".descendants.future", Malformed, "required and absent")
		}
		f.required(path+".descendants.boundary", d.Boundary)
		f.required(path+".descendants.root_exit", d.RootExit)
		f.required(path+".descendants.replacement", d.Replacement)
	}
	f.unique("observation_scope.targets", targets)
	for i, m := range c.ObservationScope.Exclude {
		match(f, fmt.Sprintf("observation_scope.exclude[%d]", i), m)
	}
	if c.ObservationScope.Libraries == nil {
		f.add("observation_scope.libraries", Malformed, "required and absent; written empty it approves any library")
	}
	for i, l := range c.ObservationScope.Libraries {
		path := fmt.Sprintf("observation_scope.libraries[%d]", i)
		f.required(path+".build_id", l.BuildID)
		if len(l.Symbols) == 0 {
			f.add(path+".symbols", Malformed, "a library approval names the offsets its entry points are approved at")
		}
	}

	if len(c.TrafficScope.Rules) == 0 {
		f.add("traffic_scope.rules", Malformed, "no rule admits any connection; a rule with direction any and no ports admits every one")
	}
	for i, r := range c.TrafficScope.Rules {
		path := fmt.Sprintf("traffic_scope.rules[%d]", i)
		f.oneOf(path+".direction", r.Direction, DirectionInbound, DirectionOutbound, DirectionAny)
		for _, port := range append(slices.Clone(r.LocalPorts), r.RemotePorts...) {
			if port < 1 || port > 65535 {
				f.add(path, Malformed, "port %d is not a TCP port", port)
			}
		}
	}

	if c.RetentionExport.RetainPlaintext == nil {
		f.add("retention_and_export.retain_plaintext", Malformed, "required and absent")
	}
	if c.RetentionExport.ExportSinks == nil {
		f.add("retention_and_export.export_sinks", Malformed, "required and absent; an empty list exports nothing")
	}

	f.unique("packs", c.Packs)
	var sinks []string
	for i, s := range c.Sinks {
		path := fmt.Sprintf("sinks[%d]", i)
		f.required(path+".name", s.Name)
		f.required(path+".kind", s.Kind)
		sinks = append(sinks, s.Name)
	}
	f.unique("sinks", sinks)

	if len(c.Pipelines) == 0 {
		f.add("pipelines", Malformed, "no pipeline is configured; the no-extension path is a pipeline with no slots, written out")
	}
	pipelines(f, "pipelines", c.Pipelines)

	var subscribers []string
	for i, s := range c.Subscribers {
		path := fmt.Sprintf("subscribers[%d]", i)
		f.required(path+".name", s.Name)
		f.required(path+".stream", s.Stream)
		f.required(path+".implementation", s.Implementation)
		subscribers = append(subscribers, s.Name)
	}
	f.unique("subscribers", subscribers)

	f.policy("policy", c.Policy)
	return c, f.list
}

func match(f *findings, path string, m Match) {
	if m.Exe == "" && m.Args == nil && m.Cgroup == "" && m.PID == nil && m.Port == nil && m.Interface == "" {
		f.add(path, Malformed, "names no condition, and a match with none would select every instance")
	}
	if m.Port != nil && (*m.Port < 1 || *m.Port > 65535) {
		f.add(path+".port", Malformed, "%d is not a TCP port", *m.Port)
	}
}

func pipelines(f *findings, path string, list []Pipeline) {
	var names []string
	for i, p := range list {
		at := fmt.Sprintf("%s[%d]", path, i)
		f.required(at+".name", p.Name)
		f.required(at+".input", p.Input)
		names = append(names, p.Name)
		if p.Slots == nil {
			f.add(at+".slots", Malformed, "required and absent; a pipeline with no slots writes an empty list")
		}
		var slots []string
		for j, s := range p.Slots {
			sat := fmt.Sprintf("%s.slots[%d]", at, j)
			f.required(sat+".name", s.Name)
			f.required(sat+".implementation", s.Implementation)
			f.oneOf(sat+".on_failure", s.OnFailure, OnFailureDropAndAccount, OnFailureStopPipeline)
			slots = append(slots, s.Name)
		}
		f.unique(at+".slots", slots)
		if len(p.Sinks) == 0 {
			f.add(at+".sinks", Malformed, "a pipeline dispatches through at least one sink")
		}
		f.unique(at+".sinks", p.Sinks)
		var queues []string
		for j, q := range p.Queues {
			f.required(fmt.Sprintf("%s.queues[%d].name", at, j), q.Name)
			queues = append(queues, q.Name)
		}
		f.unique(at+".queues", queues)
	}
	f.unique(path, names)
}

func readManifest(supplied Supplied) (Manifest, []Finding) {
	f := &findings{document: "manifest:" + supplied.Name}
	var m Manifest
	if err := decode(supplied.Content, &m); err != nil {
		f.add("", Malformed, "%v", err)
		return m, f.list
	}
	if m.Version != ManifestVersion {
		f.add("version", UnknownVersion, "%q is not %s", m.Version, ManifestVersion)
		return m, f.list
	}
	f.required("name", m.Name)
	f.required("pack_version", m.PackVersion)

	var names []string
	for i, c := range m.Components {
		path := fmt.Sprintf("components[%d]", i)
		component(f, path, c)
		if c.Execution != "" && c.Execution != ExecutionExternal {
			f.add(path+".execution", Malformed, "a pack supplies external components only; a built-in is the runtime's")
		}
		names = append(names, c.Name)
	}
	f.unique("components", names)

	pipelines(f, "pipelines", m.Pipelines)

	for i, r := range m.Replacements {
		path := fmt.Sprintf("replacements[%d]", i)
		f.required(path+".pipeline", r.Pipeline)
		f.required(path+".slot", r.Slot)
		f.required(path+".implementation", r.Implementation)
	}

	f.policy("policy", m.Policy)
	return m, f.list
}

// component reads one component declaration a manifest carries. The runtime's
// built-ins arrive in Available and are not read through it.
func component(f *findings, path string, c Component) {
	if c.Interface != ComponentVersion {
		f.add(path+".interface", UnknownVersion, "%q is not %s", c.Interface, ComponentVersion)
		return
	}
	f.required(path+".name", c.Name)
	f.required(path+".version", c.Version)
	f.oneOf(path+".role", c.Role, RoleProcessor, RoleSubscriber)
	f.oneOf(path+".execution", c.Execution, ExecutionBuiltin, ExecutionExternal)
	if len(c.Input.Types) == 0 {
		f.add(path+".input.types", Malformed, "a component receives at least one type")
	}
	f.unique(path+".input.types", c.Input.Types)
	f.oneOf(path+".input.delivery", c.Input.Delivery, DeliveryRecord, DeliveryBatch)
	f.oneOf(path+".state", c.State, StateNone, StatePerConnection, StatePerStream, StatePipeline)
	f.oneOf(path+".ordering.records", c.Ordering.Records, RecordsNone, RecordsInOrderPerConnection)

	l := c.Lifecycle
	for _, hook := range [][2]string{
		{"startup", l.Startup}, {"configuration_change", l.ConfigurationChange}, {"stream_closure", l.StreamClosure},
		{"flush", l.Flush}, {"shutdown", l.Shutdown},
	} {
		f.oneOf(path+".lifecycle."+hook[0], hook[1], HookHandled, HookIgnored)
	}
	if c.State != "" && c.State != StateNone && (l.StreamClosure != HookHandled || l.Flush != HookHandled) {
		f.add(path+".lifecycle", Malformed, "a component keeping %s state handles stream_closure and flush, or its state has no end", c.State)
	}

	if len(c.Failures) == 0 {
		f.add(path+".failures", Malformed, "a component declares the failure results it can return; fatal at least")
	}
	for _, failure := range c.Failures {
		if !slices.Contains([]string{FailureRecord, FailureFatal, FailureConfiguration}, failure) {
			f.add(path+".failures", Malformed, "%q is not a failure result", failure)
		}
	}
	if !slices.Contains(c.Failures, FailureFatal) && len(c.Failures) > 0 {
		f.add(path+".failures", Malformed, "every component can fail fatally, and one that says it cannot has said something false")
	}
	f.unique(path+".failures", c.Failures)

	o := c.Output
	switch c.Role {
	case RoleSubscriber:
		if len(o.Records) > 0 || len(o.Derived) > 0 || o.Suppression || !o.Findings {
			f.add(path+".output", Malformed, "a subscriber returns linked findings only, and never records or suppression decisions")
		}
	case RoleProcessor:
		if o.Findings {
			f.add(path+".output.findings", Malformed, "findings are a subscriber's; a processor returns records, derived records or suppression decisions")
		}
		if len(o.Records) == 0 && len(o.Derived) == 0 && !o.Suppression {
			f.add(path+".output", Malformed, "a processor returns records, derived records or suppression decisions; a component that only observes and reports is a subscriber returning findings")
		}
	}
	for _, name := range append(slices.Clone(c.Ordering.After), c.Ordering.Before...) {
		if name == c.Name {
			f.add(path+".ordering", Malformed, "a component cannot be ordered against itself")
		}
	}
}

// duplicateKeys refuses a key written twice in one object, anywhere in the
// document. The decoder keeps the last of two and says nothing, so a member
// written twice with two values is read as whichever came second.
func duplicateKeys(content []byte) error {
	type frame struct {
		object bool
		keys   map[string]bool
		key    bool
	}
	var stack []*frame
	decoder := json.NewDecoder(bytes.NewReader(content))
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			// A document that is not JSON at all is the decoder's to refuse,
			// in its own words.
			return nil
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				stack = append(stack, &frame{object: true, keys: map[string]bool{}, key: true})
			case '[':
				stack = append(stack, &frame{})
			default:
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].key = true
				}
			}
		default:
			if top == nil || !top.object {
				continue
			}
			if top.key {
				name, _ := value.(string)
				if top.keys[name] {
					return fmt.Errorf("the key %q is written twice in one object, and only one of the two would be read", name)
				}
				top.keys[name] = true
				top.key = false
				continue
			}
			top.key = true
		}
	}
}
