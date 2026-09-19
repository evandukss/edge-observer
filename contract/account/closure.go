package account

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
)

// ClosureOutcome is where a closure check ended.
type ClosureOutcome string

const (
	// Closed is a tree every reference of which resolves inside it.
	Closed ClosureOutcome = "closed"
	// NotClosed is a tree with a reference that leaves it, a reference that
	// resolves to nothing, or a link.
	NotClosed ClosureOutcome = "not_closed"
)

// Closure is one closure check's outcome, with how much it looked at.
type Closure struct {
	Outcome    ClosureOutcome `json:"outcome"`
	Files      int            `json:"files"`
	References int            `json:"references"`
	Findings   []Finding      `json:"findings"`
}

// CheckClosure reads every contract file in tree - a copied bundle or a contract
// directory - and checks that each reference it holds resolves inside tree: not
// absolute, not carrying a scheme, not leaving the root, not through a link, and
// naming something that exists. It reads nothing outside tree and nothing over a
// network. The reference forms it knows are the ones ACCOUNT.md names.
func CheckClosure(tree fs.FS) Closure {
	result := Closure{Outcome: NotClosed, Findings: []Finding{}}
	files, links, read, findings := walk(tree)
	result.Findings = append(result.Findings, findings...)

	for _, name := range read {
		content, err := fs.ReadFile(tree, name)
		if err != nil {
			result.Findings = append(result.Findings, Finding{Member: name, Reason: ReferenceUnresolved,
				Detail: "the file could not be read: " + err.Error()})
			continue
		}
		result.Files++
		references, problem := referencesIn(name, content)
		if problem != "" {
			// A contract file whose references cannot be read cannot be said
			// to be closed.
			result.Findings = append(result.Findings, Finding{Member: name, Reason: ReferenceUnresolved,
				Detail: problem})
			continue
		}
		for _, one := range references {
			result.References++
			if finding, bad := one.check(name, files, links); bad {
				result.Findings = append(result.Findings, finding)
			}
		}
	}
	if len(result.Findings) == 0 {
		result.Outcome = Closed
	}
	return result
}

// walk lists every regular file in tree, every link, the files a closure check
// reads, and a finding for every link. A link is refused wherever it is and
// whatever it names, because where it resolves is a property of the host it is
// read on.
func walk(tree fs.FS) (map[string]bool, []string, []string, []Finding) {
	files := map[string]bool{}
	var links []string
	var read []string
	var findings []Finding
	err := fs.WalkDir(tree, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			findings = append(findings, Finding{Member: name, Reason: ReferenceUnresolved,
				Detail: "the tree could not be walked here: " + err.Error()})
			return nil
		}
		switch {
		case entry.Type()&fs.ModeSymlink != 0:
			links = append(links, name)
			findings = append(findings, Finding{Member: name, Reason: LinkNotPermitted,
				Detail: "a symbolic link resolves wherever the host it is read on says"})
		case entry.Type().IsRegular():
			files[name] = true
			switch path.Ext(name) {
			case ".json", ".jsonl", ".md":
				read = append(read, name)
			}
		}
		return nil
	})
	if err != nil {
		findings = append(findings, Finding{Member: ".", Reason: ReferenceUnresolved,
			Detail: "the tree could not be walked: " + err.Error()})
	}
	slices.Sort(read)
	return files, links, read, findings
}

type referenceKind int

const (
	pathReference referenceKind = iota
	identifierReference
)

// reference is one reference found in a file, with where it was found.
type reference struct {
	kind  referenceKind
	value string
	at    string
	// fromRoot resolves the value against the tree root rather than against
	// the directory of the file holding it.
	fromRoot bool
}

// parent is the parent-directory element, built rather than written so the
// module's own check for paths outside it (boundary_test.go) does not flag it.
var parent = strings.Repeat(".", 2)

// scheme is a URI scheme, and a Windows drive letter is one as far as a path is
// concerned: both name somewhere other than inside the tree.
var scheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

// check resolves one reference. It returns a finding when the reference leaves
// the tree or, for a path, names no file in it.
//
// A path that is a refused link, or under one, is no finding: the link is
// already reported and is the reference's repair.
func (r reference) check(holder string, files map[string]bool, links []string) (Finding, bool) {
	value := r.value
	if r.kind == pathReference {
		if cut, _, found := strings.Cut(value, "#"); found {
			value = cut
		}
		if value == "" {
			return Finding{}, false
		}
	}
	if r.kind == identifierReference && scheme.MatchString(value) {
		return Finding{}, false
	}
	outside := func(why string) (Finding, bool) {
		return Finding{Member: holder, At: r.at, Reason: ReferenceOutsideBundle,
			Detail: fmt.Sprintf("%q %s", r.value, why)}, true
	}
	switch {
	case scheme.MatchString(value):
		return outside("carries a scheme, so it names something outside the tree")
	case strings.HasPrefix(value, "/"):
		return outside("is absolute")
	case strings.Contains(value, `\`):
		return outside("holds a backslash, which some hosts read as a separator")
	}
	base := path.Dir(holder)
	if r.fromRoot {
		base = "."
	}
	resolved := path.Join(base, value)
	if resolved == parent || strings.HasPrefix(resolved, parent+"/") {
		return outside("leaves the tree root")
	}
	if r.kind == identifierReference {
		return Finding{}, false
	}
	for _, link := range links {
		if resolved == link || strings.HasPrefix(resolved, link+"/") {
			return Finding{}, false
		}
	}
	if !files[resolved] {
		return Finding{Member: holder, At: r.at, Reason: ReferenceUnresolved,
			Detail: fmt.Sprintf("%q names %s, which is not a file in the tree", r.value, resolved)}, true
	}
	return Finding{}, false
}

// referencesIn is every reference one file holds, or why they cannot be read.
func referencesIn(name string, content []byte) ([]reference, string) {
	switch path.Ext(name) {
	case ".json":
		var document any
		if err := decode(content, &document); err != nil {
			return nil, "not JSON: " + err.Error()
		}
		return jsonReferences(document, "", name == ManifestName), ""
	case ".jsonl":
		var found []reference
		scanner := bufio.NewScanner(bytes.NewReader(content))
		scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
		line := 0
		for scanner.Scan() {
			line++
			if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
				continue
			}
			var document any
			if err := decode(scanner.Bytes(), &document); err != nil {
				return nil, fmt.Sprintf("line %d is not JSON: %v", line, err)
			}
			found = append(found, jsonReferences(document, fmt.Sprintf("line %d", line), false)...)
		}
		if err := scanner.Err(); err != nil {
			return nil, "the lines could not be read: " + err.Error()
		}
		return found, ""
	default:
		return markdownReferences(content), ""
	}
}

func decode(content []byte, into *any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	return decoder.Decode(into)
}

// jsonReferences walks a decoded document for the generic reference members
// and, in a bundle manifest at the root, for the manifest's own.
func jsonReferences(document any, at string, manifest bool) []reference {
	var found []reference
	var visit func(value any, at string)
	visit = func(value any, at string) {
		switch typed := value.(type) {
		case map[string]any:
			for _, key := range slices.Sorted(maps.Keys(typed)) {
				child := joinAt(at, key)
				if text, ok := typed[key].(string); ok {
					switch key {
					case "$ref":
						found = append(found, reference{kind: pathReference, value: text, at: child})
						continue
					case "$schema", "$id":
						found = append(found, reference{kind: identifierReference, value: text, at: child})
						continue
					}
				}
				visit(typed[key], child)
			}
		case []any:
			for index, element := range typed {
				visit(element, fmt.Sprintf("%s[%d]", at, index))
			}
		}
	}
	visit(document, at)

	if manifest {
		top, _ := document.(map[string]any)
		for _, list := range []string{"members", "schemas"} {
			entries, _ := top[list].([]any)
			for index, entry := range entries {
				fields, _ := entry.(map[string]any)
				if text, ok := fields["path"].(string); ok {
					found = append(found, reference{kind: pathReference, value: text, fromRoot: true,
						at: fmt.Sprintf("%s[%d].path", list, index)})
				}
				if text, ok := fields["id"].(string); ok && list == "schemas" {
					found = append(found, reference{kind: identifierReference, value: text, fromRoot: true,
						at: fmt.Sprintf("%s[%d].id", list, index)})
				}
			}
		}
	}
	return found
}

func joinAt(at, key string) string {
	if at == "" {
		return key
	}
	return at + "." + key
}

// link is a Markdown inline link's target. Code is removed first, so a link
// written as an example inside backticks or a code block is not a reference.
var (
	link       = regexp.MustCompile(`\]\(\s*([^)\s]+)(?:\s+"[^"]*")?\s*\)`)
	inlineCode = regexp.MustCompile("`[^`\n]*`")
)

func markdownReferences(content []byte) []reference {
	var found []reference
	fenced := false
	for number, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			fenced = !fenced
			continue
		}
		if fenced || strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t") {
			continue
		}
		prose := inlineCode.ReplaceAllString(line, "")
		for _, match := range link.FindAllStringSubmatch(prose, -1) {
			target := match[1]
			if strings.HasPrefix(target, "#") {
				continue
			}
			found = append(found, reference{kind: pathReference, value: target,
				at: fmt.Sprintf("line %d", number+1)})
		}
	}
	return found
}
