package account

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
)

// The member a reference names, before its colon.
const (
	ReferenceAccount         = "account"
	ReferenceConnections     = "connections"
	ReferenceReconstructions = "reconstructions"
	ReferenceObservations    = "observations"
)

// ReferenceOutcome is where resolving one reference ended.
type ReferenceOutcome string

const (
	// Resolved is a reference exactly one member of the bundle matches.
	Resolved ReferenceOutcome = "resolved"
	// Unresolved is a reference in the form that no member matches, or that
	// more than one matches.
	Unresolved ReferenceOutcome = "unresolved"
	// NotAReference is a string not in the form: a path, a location outside the
	// bundle, a member this form does not name, or a malformed part.
	NotAReference ReferenceOutcome = "not_a_reference"
)

// Resolution is what one reference resolved to.
type Resolution struct {
	Reference string           `json:"reference"`
	Outcome   ReferenceOutcome `json:"outcome"`

	// Member is the bundle-relative path of the member it names, and At where
	// inside it: a line number of a record member, or the account path.
	Member string `json:"member,omitempty"`
	At     string `json:"at,omitempty"`

	// Matches is how many records matched, so an ambiguous reference is told
	// from one that matched nothing.
	Matches int    `json:"matches"`
	Why     string `json:"why,omitempty"`
}

var (
	accountPath = regexp.MustCompile(`^[a-z_]+(\[[0-9]+\])*(\.[a-z_]+(\[[0-9]+\])*)*$`)
	pathElement = regexp.MustCompile(`^([a-z_]+)((?:\[[0-9]+\])*)$`)
	decimalPart = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
)

// Resolve resolves one evidence reference within a bundle and nowhere else. A
// reference carries no path, so there is nowhere outside the bundle for it to
// name; the member it resolves in is the one the bundle's own manifest names for
// that role.
func Resolve(bundle fs.FS, reference string) Resolution {
	out := Resolution{Reference: reference, Outcome: NotAReference}
	name, rest, found := strings.Cut(reference, ":")
	if !found || rest == "" {
		out.Why = "a reference is <member>:<part>"
		return out
	}

	var role string
	switch name {
	case ReferenceAccount:
		if !accountPath.MatchString(rest) {
			out.Why = fmt.Sprintf("%q is not a dotted account path", rest)
			return out
		}
		role = RoleAccount
	case ReferenceConnections, ReferenceReconstructions, ReferenceObservations:
		role = name
	default:
		out.Why = fmt.Sprintf("%q is not a member a reference names", name)
		return out
	}

	parts := strings.Split(rest, "/")
	switch name {
	case ReferenceConnections:
		if len(parts) != 2 || !decimalPart.MatchString(parts[0]) || !decimalPart.MatchString(parts[1]) {
			out.Why = "a connection is connections:<pid>/<id>"
			return out
		}
	case ReferenceReconstructions:
		if (len(parts) != 2 && len(parts) != 4) || !decimalPart.MatchString(parts[0]) || !decimalPart.MatchString(parts[1]) ||
			len(parts) == 4 && (!decimalPart.MatchString(parts[2]) || (parts[3] != "request" && parts[3] != "response")) {
			out.Why = "a reconstruction is reconstructions:<pid>/<id>, or /<index>/<request|response> for one half"
			return out
		}
	case ReferenceObservations:
		if len(parts) != 1 || !decimalPart.MatchString(parts[0]) {
			out.Why = "an observation is observations:<index>"
			return out
		}
	}

	out.Outcome = Unresolved
	member, content, why := memberOf(bundle, role)
	if why != "" {
		out.Why = why
		return out
	}
	out.Member = member

	switch name {
	case ReferenceAccount:
		resolveAccount(&out, content, rest)
	case ReferenceObservations:
		index, _ := strconv.Atoi(parts[0])
		lines := 0
		eachLine(content, func(int, []byte) { lines++ })
		if index < lines {
			out.Outcome, out.Matches, out.At = Resolved, 1, fmt.Sprintf("line %d", index+1)
		} else {
			out.Why = fmt.Sprintf("the session has %d observations", lines)
		}
	default:
		resolveRecord(&out, content, parts)
	}
	return out
}

// memberOf is the member the bundle's manifest names for a role, and its bytes.
func memberOf(bundle fs.FS, role string) (string, []byte, string) {
	content, err := fs.ReadFile(bundle, ManifestName)
	if err != nil {
		return "", nil, "the bundle has no readable manifest: " + err.Error()
	}
	var manifest Manifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		return "", nil, "the bundle's manifest is not readable: " + err.Error()
	}
	for _, member := range manifest.Members {
		if member.Role != role {
			continue
		}
		if !fs.ValidPath(member.Path) {
			return "", nil, fmt.Sprintf("the manifest names %q for %s, which is not a path inside the bundle", member.Path, role)
		}
		data, err := fs.ReadFile(bundle, member.Path)
		if err != nil {
			return member.Path, nil, "the member cannot be read: " + err.Error()
		}
		return member.Path, data, ""
	}
	return "", nil, fmt.Sprintf("the manifest names no %s member", role)
}

func eachLine(content []byte, visit func(int, []byte)) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 64*1024), 64*1024*1024)
	number := 0
	for scanner.Scan() {
		number++
		visit(number, scanner.Bytes())
	}
}

// resolveRecord matches connection and reconstruction references by pid and id,
// counting every match so that more than one does not resolve.
func resolveRecord(out *Resolution, content []byte, parts []string) {
	pid, _ := strconv.ParseInt(parts[0], 10, 32)
	var at []string
	eachLine(content, func(number int, line []byte) {
		var one struct {
			ID         string              `json:"id"`
			Process    struct{ PID int32 } `json:"process"`
			Connection *struct {
				ID      string              `json:"id"`
				Process struct{ PID int32 } `json:"process"`
			} `json:"connection"`
			Exchanges []struct {
				Index int `json:"index"`
			} `json:"exchanges"`
		}
		if json.Unmarshal(line, &one) != nil {
			return
		}
		id, owner := one.ID, one.Process.PID
		if one.Connection != nil {
			id, owner = one.Connection.ID, one.Connection.Process.PID
		}
		if int64(owner) != pid || id != parts[1] {
			return
		}
		if len(parts) == 4 {
			index, _ := strconv.Atoi(parts[2])
			held := false
			for _, exchange := range one.Exchanges {
				held = held || exchange.Index == index
			}
			if !held {
				return
			}
		}
		at = append(at, fmt.Sprintf("line %d", number))
	})
	out.Matches = len(at)
	switch len(at) {
	case 1:
		out.Outcome, out.At = Resolved, at[0]
	case 0:
		out.Why = "no record matches"
	default:
		out.Why = fmt.Sprintf("%d records match, so it names no one record", len(at))
	}
}

// resolveAccount walks the account document along a dotted path.
func resolveAccount(out *Resolution, content []byte, path string) {
	var value any
	if err := json.Unmarshal(content, &value); err != nil {
		out.Why = "the account is not readable: " + err.Error()
		return
	}
	for _, element := range strings.Split(path, ".") {
		match := pathElement.FindStringSubmatch(element)
		object, ok := value.(map[string]any)
		if !ok {
			out.Why = fmt.Sprintf("%s is not inside an object", element)
			return
		}
		if value, ok = object[match[1]]; !ok {
			out.Why = fmt.Sprintf("the account holds no %s there", match[1])
			return
		}
		for _, position := range strings.FieldsFunc(match[2], func(r rune) bool { return r == '[' || r == ']' }) {
			index, _ := strconv.Atoi(position)
			list, ok := value.([]any)
			if !ok || index >= len(list) {
				out.Why = fmt.Sprintf("%s has no element %d", match[1], index)
				return
			}
			value = list[index]
		}
	}
	out.Outcome, out.Matches, out.At = Resolved, 1, path
}
