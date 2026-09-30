package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// PackName is the rule a pack's name meets. It becomes a file name,
// packs/<name>.json beside the configuration, so it can never reach outside
// that directory.
var PackName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ReadFile reads the configuration a user writes. It is strict at every level:
// an unknown key, a key written twice, a wrong type, a missing required key or
// anything after the document is refused, naming the key. A document of
// another version is refused by its version and nothing else in it is read.
func ReadFile(content []byte) (File, []Finding) {
	r := &reader{document: "configuration"}
	file := File{Log: LogStdout, WriteContent: true,
		Limits: Limits{OutputMiB: DefaultApprovedOutputBoundMiB, Events: DefaultAdmittedEventLimit,
			StateEverySeconds: DefaultStateEverySeconds}}
	root := r.root(content)
	if root == nil || !r.version(root, FileVersion, PackVersion, "a pack, not a configuration") {
		return file, r.list
	}
	r.keys(root, "", "version", "output", "log", "watch", "ignore", "libraries", "write_content", "remove", "mask",
		"truncate", "limits", "packs")

	if output, found := r.required(root, "", "output"); found {
		if value, ok := r.text(output, "output"); ok {
			if !filepath.IsAbs(value) {
				r.add("output", InvalidValue, "%q is not an absolute path", value)
			}
			file.Output = value
		}
	}
	if log := root.member("log"); log != nil {
		if value, ok := r.text(log, "log"); ok {
			if value != LogStdout && !filepath.IsAbs(value) {
				r.add("log", InvalidValue, "%q is neither %s nor an absolute path", value, LogStdout)
			}
			file.Log = value
		}
	}
	if watch, found := r.required(root, "", "watch"); found {
		file.Watch = r.watch(watch)
	}
	if ignore := root.member("ignore"); ignore != nil {
		for i, item := range r.array(ignore, "ignore") {
			path := fmt.Sprintf("ignore[%d]", i)
			if r.object(item, path) {
				r.keys(item, path, matchKeys...)
				file.Ignore = append(file.Ignore, r.match(item, path))
			}
		}
	}
	if libraries := root.member("libraries"); libraries != nil {
		for i, item := range r.array(libraries, "libraries") {
			if library, ok := r.library(item, fmt.Sprintf("libraries[%d]", i)); ok {
				file.Libraries = append(file.Libraries, library)
			}
		}
	}
	if write := root.member("write_content"); write != nil {
		if value, ok := r.boolean(write, "write_content"); ok {
			file.WriteContent = value
		}
	}
	file.Rules = r.rules(root, "")
	if limits := root.member("limits"); limits != nil && r.object(limits, "limits") {
		r.keys(limits, "limits", "output_mib", "events", "state_every_seconds")
		for _, one := range []struct {
			key  string
			max  int64
			into *int64
		}{
			{"output_mib", MaxOutputMiB, &file.Limits.OutputMiB},
			{"events", MaxEvents, &file.Limits.Events},
			{"state_every_seconds", MaxStateEverySeconds, &file.Limits.StateEverySeconds},
		} {
			if value := limits.member(one.key); value != nil {
				if n, ok := r.integer(value, "limits."+one.key, 1, one.max); ok {
					*one.into = n
				}
			}
		}
	}
	if packs := root.member("packs"); packs != nil {
		seen := map[string]bool{}
		for i, item := range r.array(packs, "packs") {
			path := fmt.Sprintf("packs[%d]", i)
			name, ok := r.text(item, path)
			if !ok {
				continue
			}
			switch {
			case !PackName.MatchString(name):
				r.add(path, PackNameInvalid, "%q does not match %s, so no file is looked for", name, PackName.String())
			case seen[name]:
				r.add(path, DuplicateName, "the pack %q is enabled twice", name)
			default:
				seen[name] = true
				file.Packs = append(file.Packs, name)
			}
		}
		if len(file.Packs) > MaxProcessingPacks {
			r.add(fmt.Sprintf("packs[%d]", MaxProcessingPacks), LimitExceeded, "at most %d packs are enabled",
				MaxProcessingPacks)
		}
	}
	return file, r.list
}

// ReadPack reads one pack, supplied under the name its loader gives it. The
// pack's own name must be that name.
func ReadPack(supplied Supplied) (Pack, []Finding) {
	r := &reader{document: "pack:" + supplied.Name}
	var pack Pack
	root := r.root(supplied.Content)
	if root == nil || !r.version(root, PackVersion, FileVersion, "a configuration, not a pack") {
		return pack, r.list
	}
	r.keys(root, "", "version", "name", "remove", "mask", "truncate")
	if name, found := r.required(root, "", "name"); found {
		if value, ok := r.text(name, "name"); ok {
			switch {
			case !PackName.MatchString(value):
				r.add("name", PackNameInvalid, "%q does not match %s", value, PackName.String())
			case value != supplied.Name:
				r.add("name", PackNameMismatch, "the pack names itself %q and is enabled as %q", value, supplied.Name)
			}
			pack.Name = value
		}
	}
	pack.Rules = r.rules(root, "")
	return pack, r.list
}

// matchKeys are the conditions that select a program, as matched today.
var matchKeys = []string{"exe", "args", "cgroup", "pid", "port", "interface"}

func (r *reader) watch(n *node) []Watch {
	var list []Watch
	items := r.array(n, "watch")
	if n.kind == kindArray && len(items) == 0 {
		r.add("watch", InvalidValue, "a configuration that watches nothing observes nothing")
	}
	names := map[string]bool{}
	for i, item := range items {
		path := fmt.Sprintf("watch[%d]", i)
		if !r.object(item, path) {
			continue
		}
		r.keys(item, path, append([]string{"name", "children"}, matchKeys...)...)
		one := Watch{Children: ChildrenAll, Match: r.match(item, path)}
		if name, found := r.required(item, path, "name"); found {
			if value, ok := r.text(name, path+".name"); ok {
				switch {
				case value == "":
					r.add(path+".name", InvalidValue, "a watch entry is named")
				case names[value]:
					r.add(path+".name", DuplicateName, "%q names two watch entries", value)
				}
				names[value] = true
				one.Name = value
			}
		}
		if children := item.member("children"); children != nil {
			if value, ok := r.text(children, path+".children"); ok {
				if !slices.Contains([]string{ChildrenAll, ChildrenExisting, ChildrenNone}, value) {
					r.add(path+".children", InvalidValue, "%q is not one of %s, %s or %s", value, ChildrenAll,
						ChildrenExisting, ChildrenNone)
				}
				one.Children = value
			}
		}
		list = append(list, one)
	}
	return list
}

func (r *reader) match(n *node, path string) Match {
	var m Match
	named := false
	if exe := n.member("exe"); exe != nil {
		m.Exe, _ = r.text(exe, path+".exe")
		named = true
	}
	if args := n.member("args"); args != nil {
		list := []string{}
		for i, item := range r.array(args, path+".args") {
			if value, ok := r.text(item, fmt.Sprintf("%s.args[%d]", path, i)); ok {
				list = append(list, value)
			}
		}
		m.Args = &list
		named = true
	}
	if cgroup := n.member("cgroup"); cgroup != nil {
		m.Cgroup, _ = r.text(cgroup, path+".cgroup")
		named = true
	}
	if pid := n.member("pid"); pid != nil {
		at := path + ".pid"
		if r.object(pid, at) {
			r.keys(pid, at, "pid", "start", "boot")
			guard := &PIDGuard{}
			if value, found := r.required(pid, at, "pid"); found {
				if number, ok := r.integer(value, at+".pid", 1, math.MaxInt32); ok {
					guard.PID = int32(number)
				}
			}
			if value, found := r.required(pid, at, "start"); found {
				guard.Start, _ = r.unsigned(value, at+".start")
			}
			if value, found := r.required(pid, at, "boot"); found {
				guard.Boot, _ = r.text(value, at+".boot")
			}
			m.PID = guard
		}
		named = true
	}
	if port := n.member("port"); port != nil {
		if number, ok := r.integer(port, path+".port", 1, 65535); ok {
			value := int(number)
			m.Port = &value
		}
		named = true
	}
	if iface := n.member("interface"); iface != nil {
		m.Interface, _ = r.text(iface, path+".interface")
		named = true
	}
	if !named {
		r.add(path, MissingKey, "names none of %s, and a match with none would select every process",
			strings.Join(matchKeys, ", "))
	}
	return m
}

func (r *reader) library(n *node, path string) (Library, bool) {
	var library Library
	if !r.object(n, path) {
		return library, false
	}
	r.keys(n, path, "build_id", "symbols")
	ok := true
	if id, found := r.required(n, path, "build_id"); found {
		library.BuildID, _ = r.text(id, path+".build_id")
		if library.BuildID == "" {
			r.add(path+".build_id", InvalidValue, "a library approval names a build by its build id")
			ok = false
		}
	} else {
		ok = false
	}
	if symbols, found := r.required(n, path, "symbols"); found && r.object(symbols, path+".symbols") {
		library.Symbols = map[string]uint64{}
		for _, key := range symbols.keys {
			if offset, valid := r.unsigned(symbols.members[key], path+".symbols."+key); valid {
				library.Symbols[key] = offset
			}
		}
		if len(library.Symbols) == 0 {
			r.add(path+".symbols", InvalidValue, "a library approval names the offsets its entry points are approved at")
			ok = false
		}
	} else {
		ok = false
	}
	return library, ok
}

// rules reads remove, mask and truncate, the same shapes in a configuration
// and in a pack.
func (r *reader) rules(root *node, path string) Rules {
	var rules Rules
	at := func(key string) string { return join(path, key) }
	if remove := root.member("remove"); remove != nil && r.object(remove, at("remove")) {
		base := at("remove")
		r.keys(remove, base, "headers", "query", "query_string", "form", "json", "bodies", "body_values")
		rules.Remove.Headers = r.names(remove.member("headers"), base+".headers", headerRule)
		rules.Remove.Query = r.names(remove.member("query"), base+".query", ValidParameterName)
		if query := remove.member("query_string"); query != nil {
			rules.Remove.QueryString, _ = r.boolean(query, base+".query_string")
		}
		rules.Remove.Form = r.names(remove.member("form"), base+".form", ValidParameterName)
		if pointers := remove.member("json"); pointers != nil && r.object(pointers, base+".json") {
			r.keys(pointers, base+".json", MessageRequest, MessageResponse)
			rules.Remove.JSON.Request = r.names(pointers.member(MessageRequest), base+".json.request", ValidPointer)
			rules.Remove.JSON.Response = r.names(pointers.member(MessageResponse), base+".json.response", ValidPointer)
		}
		rules.Remove.Bodies = r.messages(remove.member("bodies"), base+".bodies")
		rules.Remove.BodyValues = r.messages(remove.member("body_values"), base+".body_values")
	}
	if mask := root.member("mask"); mask != nil && r.object(mask, at("mask")) {
		base := at("mask")
		r.keys(mask, base, "headers", "json")
		rules.Mask.Headers = r.values(mask.member("headers"), base+".headers", headerRule, MaxHeaderValueBytes)
		if pointers := mask.member("json"); pointers != nil && r.object(pointers, base+".json") {
			r.keys(pointers, base+".json", MessageRequest, MessageResponse)
			rules.Mask.JSON.Request = r.values(pointers.member(MessageRequest), base+".json.request", ValidPointer,
				MaxJSONValueBytes)
			rules.Mask.JSON.Response = r.values(pointers.member(MessageResponse), base+".json.response", ValidPointer,
				MaxJSONValueBytes)
		}
	}
	if truncate := root.member("truncate"); truncate != nil && r.object(truncate, at("truncate")) {
		base := at("truncate")
		r.keys(truncate, base, "headers")
		if headers := truncate.member("headers"); headers != nil && r.object(headers, base+".headers") {
			for _, key := range headers.keys {
				path := base + ".headers." + key
				if err := headerRule(key); err != nil {
					r.add(path, InvalidValue, "%v", err)
					continue
				}
				if length, ok := r.integer(headers.members[key], path, 0, MaxHeaderValueBytes); ok {
					rules.Truncate.Headers = append(rules.Truncate.Headers, NamedLength{Name: key, Length: int(length)})
				}
			}
		}
	}
	return rules
}

func headerRule(name string) error {
	if !headerName(name) {
		return fmt.Errorf("%q is not an HTTP header name", name)
	}
	return nil
}

// names reads a list of names or pointers, each checked by valid.
func (r *reader) names(n *node, path string, valid func(string) error) []string {
	if n == nil {
		return nil
	}
	var list []string
	for i, item := range r.array(n, path) {
		at := fmt.Sprintf("%s[%d]", path, i)
		if value, ok := r.text(item, at); ok {
			if err := valid(value); err != nil {
				r.add(at, InvalidValue, "%v", err)
				continue
			}
			list = append(list, value)
		}
	}
	return list
}

// values reads an object of name or pointer to the value written in its place.
func (r *reader) values(n *node, path string, valid func(string) error, maxBytes int) []NamedValue {
	if n == nil || !r.object(n, path) {
		return nil
	}
	var list []NamedValue
	for _, key := range n.keys {
		at := path + "." + key
		if err := valid(key); err != nil {
			r.add(at, InvalidValue, "%v", err)
			continue
		}
		value, ok := r.text(n.members[key], at)
		if !ok {
			continue
		}
		switch {
		case len(value) > maxBytes:
			r.add(at, InvalidValue, "a masked value is at most %d bytes", maxBytes)
		case !printable(value):
			r.add(at, InvalidValue, "a masked value is printable ASCII")
		default:
			list = append(list, NamedValue{Name: key, Value: value})
		}
	}
	return list
}

// messages reads a list of request and response, each at most once.
func (r *reader) messages(n *node, path string) []string {
	if n == nil {
		return nil
	}
	var list []string
	for i, item := range r.array(n, path) {
		at := fmt.Sprintf("%s[%d]", path, i)
		value, ok := r.text(item, at)
		if !ok {
			continue
		}
		switch {
		case value != MessageRequest && value != MessageResponse:
			r.add(at, InvalidValue, "%q is neither %s nor %s", value, MessageRequest, MessageResponse)
		case slices.Contains(list, value):
			r.add(at, DuplicateName, "%s is written twice", value)
		default:
			list = append(list, value)
		}
	}
	return list
}

// reader collects the refusals of one document.
type reader struct {
	document string
	list     []Finding
}

func (r *reader) add(path string, reason Reason, detail string, arguments ...any) {
	r.list = append(r.list, Finding{Document: r.document, Subject: path, Reason: reason,
		Detail: fmt.Sprintf(detail, arguments...)})
}

// root parses the document, refusing what is not one JSON object with no key
// written twice and nothing after it.
func (r *reader) root(content []byte) *node {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	root, path, err := parse(decoder, "")
	switch {
	case errors.Is(err, errDuplicate):
		r.add(path, DuplicateKey, "the key is written twice in one object, and only one of the two would be read")
		return nil
	case err != nil:
		r.add(path, Malformed, "not a JSON document: %v", err)
		return nil
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		r.add("", TrailingContent, "something follows the document, and a document is one JSON object")
		return nil
	}
	if !r.object(root, "") {
		return nil
	}
	return root
}

// version reads the version, and refuses one that is not this document's. The
// version of the other document is named as that document.
func (r *reader) version(root *node, want, other, otherIs string) bool {
	n, found := r.required(root, "", "version")
	if !found {
		return false
	}
	value, ok := r.text(n, "version")
	switch {
	case !ok:
		return false
	case value == other:
		r.add("version", UnknownVersion, "%q is %s; this document must be %s", value, otherIs, want)
		return false
	case value != want:
		r.add("version", UnknownVersion, "%q is not %s", value, want)
		return false
	}
	return true
}

// keys refuses every key of an object that is not one of allowed.
func (r *reader) keys(n *node, path string, allowed ...string) {
	for _, key := range n.keys {
		if slices.Contains(allowed, key) {
			continue
		}
		detail := fmt.Sprintf("%q is not a key here; the keys are %s", key, strings.Join(allowed, ", "))
		for _, one := range allowed {
			if strings.EqualFold(one, key) {
				detail = fmt.Sprintf("%q is not a key; the key is %q, and a key is matched exactly", key, one)
			}
		}
		r.add(join(path, key), UnknownKey, "%s", detail)
	}
}

func (r *reader) required(n *node, path, key string) (*node, bool) {
	member := n.member(key)
	if member == nil {
		r.add(join(path, key), MissingKey, "required and absent")
		return nil, false
	}
	return member, true
}

func (r *reader) object(n *node, path string) bool {
	if n.kind != kindObject {
		r.add(path, WrongType, "%s, where an object is written", n.kind)
		return false
	}
	return true
}

func (r *reader) array(n *node, path string) []*node {
	if n.kind != kindArray {
		r.add(path, WrongType, "%s, where a list is written", n.kind)
		return nil
	}
	return n.items
}

func (r *reader) text(n *node, path string) (string, bool) {
	if n.kind != kindString {
		r.add(path, WrongType, "%s, where a string is written", n.kind)
		return "", false
	}
	return n.text, true
}

func (r *reader) boolean(n *node, path string) (bool, bool) {
	if n.kind != kindBool {
		r.add(path, WrongType, "%s, where true or false is written", n.kind)
		return false, false
	}
	return n.boolean, true
}

func (r *reader) integer(n *node, path string, least, most int64) (int64, bool) {
	if n.kind != kindNumber {
		r.add(path, WrongType, "%s, where a whole number is written", n.kind)
		return 0, false
	}
	value, err := n.number.Int64()
	if err != nil || value < least || value > most {
		r.add(path, InvalidValue, "%s is not a whole number from %d to %d", n.number, least, most)
		return 0, false
	}
	return value, true
}

func (r *reader) unsigned(n *node, path string) (uint64, bool) {
	if n.kind != kindNumber {
		r.add(path, WrongType, "%s, where a whole number is written", n.kind)
		return 0, false
	}
	value, err := strconv.ParseUint(string(n.number), 10, 64)
	if err != nil {
		r.add(path, InvalidValue, "%s is not a whole number from 0 to %d", n.number, uint64(math.MaxUint64))
		return 0, false
	}
	return value, true
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// node is one parsed JSON value, with an object's keys in the order written.
type node struct {
	kind    kind
	keys    []string
	members map[string]*node
	items   []*node
	text    string
	number  json.Number
	boolean bool
}

func (n *node) member(key string) *node {
	if n == nil || n.kind != kindObject {
		return nil
	}
	return n.members[key]
}

type kind string

const (
	kindObject kind = "an object"
	kindArray  kind = "a list"
	kindString kind = "a string"
	kindNumber kind = "a number"
	kindBool   kind = "true or false"
	kindNull   kind = "null"
)

var errDuplicate = errors.New("a key written twice")

// parse reads one value and returns the path of anything it refuses.
func parse(decoder *json.Decoder, path string) (*node, string, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, path, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			n := &node{kind: kindObject, members: map[string]*node{}}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, path, err
				}
				key, _ := keyToken.(string)
				at := join(path, key)
				if _, twice := n.members[key]; twice {
					return nil, at, errDuplicate
				}
				member, where, err := parse(decoder, at)
				if err != nil {
					return nil, where, err
				}
				n.keys = append(n.keys, key)
				n.members[key] = member
			}
			if _, err := decoder.Token(); err != nil {
				return nil, path, err
			}
			return n, path, nil
		case '[':
			n := &node{kind: kindArray}
			for decoder.More() {
				item, where, err := parse(decoder, fmt.Sprintf("%s[%d]", path, len(n.items)))
				if err != nil {
					return nil, where, err
				}
				n.items = append(n.items, item)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, path, err
			}
			return n, path, nil
		}
		return nil, path, fmt.Errorf("unexpected %v", value)
	case string:
		return &node{kind: kindString, text: value}, path, nil
	case json.Number:
		return &node{kind: kindNumber, number: value}, path, nil
	case bool:
		return &node{kind: kindBool, boolean: value}, path, nil
	case nil:
		return &node{kind: kindNull}, path, nil
	}
	return nil, path, fmt.Errorf("unexpected token %v", token)
}
