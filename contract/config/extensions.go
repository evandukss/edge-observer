package config

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// ExtensionName is the rule an extension's name meets. The name keys the
// extension's counts in the account and names its derived output file, so it
// is lowercase, where two names differing only in case would name one file on
// a filesystem that ignores case, and it cannot reach outside a directory.
var ExtensionName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

// The fields an extension entry may select. Each maps to a part of the
// observer's own record, documented in docs/extensions.md.
const (
	FieldRequestLine     = "request.line"
	FieldRequestHeaders  = "request.headers"
	FieldRequestBody     = "request.body"
	FieldResponseLine    = "response.line"
	FieldResponseHeaders = "response.headers"
	FieldResponseBody    = "response.body"
	FieldConnection      = "connection"
)

// ExtensionFields is every field an entry may select, in published order.
var ExtensionFields = []string{FieldRequestLine, FieldRequestHeaders, FieldRequestBody, FieldResponseLine,
	FieldResponseHeaders, FieldResponseBody, FieldConnection}

// Bounds on the extensions a configuration declares. MaxExtensionTimeoutMS
// bounds what one exchange can wait at one extension, which every exchange of
// its connection behind it waits too.
const (
	MaxExtensions         = 8
	MaxExtensionTimeoutMS = 60_000
)

// Extension is one extension entry: a user's own executable the observer starts
// and feeds records to.
type Extension struct {
	Name string `json:"name"`
	// Command is the argument vector. Its first element is the executable,
	// which Compile resolves against the configuration file's directory where
	// it is written relative. Nothing is run through a shell.
	Command   []string `json:"command"`
	Fields    []string `json:"fields"`
	TimeoutMS int64    `json:"timeout_ms"`
}

// extensions reads the extensions section. writeContent is the file's
// write_content, since with it false only the connection is selectable.
func (r *reader) extensions(n *node, writeContent bool) []Extension {
	var list []Extension
	names := map[string]bool{}
	items := r.array(n, "extensions")
	if len(items) > MaxExtensions {
		r.add(fmt.Sprintf("extensions[%d]", MaxExtensions), LimitExceeded, "at most %d extensions are configured",
			MaxExtensions)
	}
	for i, item := range items {
		path := fmt.Sprintf("extensions[%d]", i)
		if !r.object(item, path) {
			continue
		}
		r.keys(item, path, "name", "command", "fields", "timeout_ms")
		var one Extension
		if name, found := r.required(item, path, "name"); found {
			if value, ok := r.text(name, path+".name"); ok {
				switch {
				case !ExtensionName.MatchString(value):
					r.add(path+".name", InvalidValue, "%q does not match %s", value, ExtensionName.String())
				case names[value]:
					r.add(path+".name", DuplicateName, "%q names two extensions", value)
				}
				names[value] = true
				one.Name = value
			}
		}
		if command, found := r.required(item, path, "command"); found {
			one.Command = r.command(command, path+".command")
		}
		if fields, found := r.required(item, path, "fields"); found {
			one.Fields = r.fields(fields, path+".fields", writeContent)
		}
		if timeout, found := r.required(item, path, "timeout_ms"); found {
			one.TimeoutMS, _ = r.integer(timeout, path+".timeout_ms", 1, MaxExtensionTimeoutMS)
		}
		list = append(list, one)
	}
	return list
}

// command reads an argument vector: at least the executable, every element a
// string a process can be given.
func (r *reader) command(n *node, path string) []string {
	items := r.array(n, path)
	if n.kind == kindArray && len(items) == 0 {
		r.add(path, InvalidValue, "a command names at least its executable")
	}
	var list []string
	for i, item := range items {
		at := fmt.Sprintf("%s[%d]", path, i)
		value, ok := r.text(item, at)
		switch {
		case !ok:
		case strings.ContainsRune(value, 0):
			r.add(at, InvalidValue, "an argument cannot hold a NUL byte")
		case i == 0 && value == "":
			r.add(at, InvalidValue, "the executable is a path, and an empty one names nothing")
		default:
			list = append(list, value)
		}
	}
	return list
}

// fields reads the fields an extension receives, each once.
func (r *reader) fields(n *node, path string, writeContent bool) []string {
	items := r.array(n, path)
	if n.kind == kindArray && len(items) == 0 {
		r.add(path, InvalidValue, "an extension receives at least one field")
	}
	var list []string
	for i, item := range items {
		at := fmt.Sprintf("%s[%d]", path, i)
		value, ok := r.text(item, at)
		switch {
		case !ok:
		case !slices.Contains(ExtensionFields, value):
			r.add(at, InvalidValue, "%q is not a field; the fields are %s", value, strings.Join(ExtensionFields, ", "))
		case slices.Contains(list, value):
			r.add(at, DuplicateName, "%s is written twice", value)
		case !writeContent && value != FieldConnection:
			r.add(at, InvalidValue, "%s is content, and with write_content false only %s is selectable", value,
				FieldConnection)
		default:
			list = append(list, value)
		}
	}
	return list
}

// resolveCommands resolves each extension's executable against directory, the
// absolute directory holding the configuration file, and refuses one that is
// not an executable regular file now, naming the entry, so a missing or
// unusable command is found before capture rather than when the extension is
// first started. A link is followed. The returned list carries the resolved
// path in place of the one written.
func resolveCommands(extensions []Extension, directory string) ([]Extension, []Finding) {
	var findings []Finding
	resolved := make([]Extension, 0, len(extensions))
	for i, one := range extensions {
		subject := fmt.Sprintf("extensions[%d].command[0]", i)
		refuse := func(reason Reason, detail string, arguments ...any) {
			findings = append(findings, Finding{Document: "configuration", Subject: subject, Reason: reason,
				Detail: fmt.Sprintf("extension %q: ", one.Name) + fmt.Sprintf(detail, arguments...)})
		}
		executable := one.Command[0]
		if !filepath.IsAbs(executable) {
			if !filepath.IsAbs(directory) {
				refuse(InvalidValue, "%q is relative, and no configuration directory is known to resolve it against",
					executable)
				continue
			}
			executable = filepath.Join(directory, executable)
		}
		info, err := os.Stat(executable)
		switch {
		case err != nil:
			refuse(CommandNotExecutable, "%s: %v", executable, err)
			continue
		case !info.Mode().IsRegular():
			refuse(CommandNotExecutable, "%s is %s, and a command is an executable regular file", executable,
				describe(info.Mode()))
			continue
		case info.Mode().Perm()&0o111 == 0:
			refuse(CommandNotExecutable, "%s is a regular file with no execute permission (%s)", executable,
				info.Mode().Perm())
			continue
		}
		one.Command = append([]string{executable}, one.Command[1:]...)
		one.Fields = slices.Clone(one.Fields)
		resolved = append(resolved, one)
	}
	return resolved, findings
}

func describe(mode fs.FileMode) string {
	switch {
	case mode.IsDir():
		return "a directory"
	case mode&fs.ModeNamedPipe != 0:
		return "a named pipe"
	case mode&fs.ModeSocket != 0:
		return "a socket"
	case mode&fs.ModeDevice != 0:
		return "a device"
	default:
		return "not a regular file (" + mode.Type().String() + ")"
	}
}
