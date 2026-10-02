package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// executable writes an executable regular file named name in directory and
// returns its path.
func executable(t *testing.T, directory, name string) string {
	t.Helper()
	at := filepath.Join(directory, name)
	if err := os.MkdirAll(filepath.Dir(at), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(at, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return at
}

// extension is one extensions entry with these members spliced over a valid
// one.
func extension(members map[string]string) string {
	entry := map[string]string{"name": `"inventory"`, "command": `["./inventory", "--flag"]`,
		"fields": `["request.line", "response.line"]`, "timeout_ms": `250`}
	for key, value := range members {
		entry[key] = value
	}
	var parts []string
	for _, key := range []string{"name", "command", "fields", "timeout_ms"} {
		if value, ok := entry[key]; ok && value != "" {
			parts = append(parts, fmt.Sprintf("%q: %s", key, value))
		}
	}
	for key, value := range entry {
		if !slices.Contains([]string{"name", "command", "fields", "timeout_ms"}, key) {
			parts = append(parts, fmt.Sprintf("%q: %s", key, value))
		}
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func withExtensions(entries ...string) string {
	return withRules(`"extensions": [` + strings.Join(entries, ", ") + `]`)
}

// A valid entry compiles, its relative executable resolved against the
// configuration's directory and its arguments kept. Every refusal below is
// one change from this.
func TestAnExtensionEntryCompilesWithItsCommandResolved(t *testing.T) {
	directory := t.TempDir()
	executable(t, directory, "inventory")
	compiled, findings := Compile([]byte(withExtensions(extension(nil))), directory)
	if len(findings) != 0 {
		t.Fatalf("refused: %+v", findings)
	}
	got := compiled.Plan.Extensions()
	want := Extension{Name: "inventory", Command: []string{filepath.Join(directory, "inventory"), "--flag"},
		Fields: []string{FieldRequestLine, FieldResponseLine}, TimeoutMS: 250}
	if len(got) != 1 || got[0].Name != want.Name || !slices.Equal(got[0].Command, want.Command) ||
		!slices.Equal(got[0].Fields, want.Fields) || got[0].TimeoutMS != want.TimeoutMS {
		t.Errorf("the plan carries %+v, want %+v", got, want)
	}
	if written := compiled.File.Extensions[0].Command[0]; written != "./inventory" {
		t.Errorf("the file as read carries %q, want the command as written", written)
	}

	absolute := executable(t, t.TempDir(), "elsewhere")
	compiled, findings = Compile([]byte(withExtensions(extension(map[string]string{
		"command": fmt.Sprintf("[%q]", absolute)}))), directory)
	if len(findings) != 0 || compiled.Plan.Extensions()[0].Command[0] != absolute {
		t.Errorf("an absolute executable is not used as written: %+v %+v", findings, compiled)
	}
}

// Every refusal of an entry, each one change from the valid entry above.
func TestEachExtensionRefusalNamesTheEntry(t *testing.T) {
	directory := t.TempDir()
	executable(t, directory, "inventory")
	notExecutable := filepath.Join(directory, "data")
	if err := os.WriteFile(notExecutable, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(directory, "folder"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(directory, "fifo"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, one := range []struct {
		name    string
		content string
		subject string
		reason  Reason
	}{
		{"an unknown field", withExtensions(extension(map[string]string{"fields": `["request.line", "request.method"]`})),
			"extensions[0].fields[1]", InvalidValue},
		{"a field written twice", withExtensions(extension(map[string]string{"fields": `["request.line", "request.line"]`})),
			"extensions[0].fields[1]", DuplicateName},
		{"no field", withExtensions(extension(map[string]string{"fields": `[]`})), "extensions[0].fields", InvalidValue},
		{"a content field with write_content false", strings.Replace(withExtensions(extension(map[string]string{
			"fields": `["connection", "response.headers"]`})), `"extensions"`, `"write_content": false, "extensions"`, 1),
			"extensions[0].fields[1]", InvalidValue},
		{"two entries with one name", withExtensions(extension(nil), extension(nil)), "extensions[1].name", DuplicateName},
		{"a name with a path separator", withExtensions(extension(map[string]string{"name": `"../inventory"`})),
			"extensions[0].name", InvalidValue},
		{"a name in upper case", withExtensions(extension(map[string]string{"name": `"Inventory"`})),
			"extensions[0].name", InvalidValue},
		{"an empty name", withExtensions(extension(map[string]string{"name": `""`})), "extensions[0].name", InvalidValue},
		{"a name too long", withExtensions(extension(map[string]string{"name": `"` + strings.Repeat("a", 64) + `"`})),
			"extensions[0].name", InvalidValue},
		{"an empty command", withExtensions(extension(map[string]string{"command": `[]`})), "extensions[0].command",
			InvalidValue},
		{"an empty executable", withExtensions(extension(map[string]string{"command": `[""]`})),
			"extensions[0].command[0]", InvalidValue},
		{"a command as one string", withExtensions(extension(map[string]string{"command": `"./inventory --flag"`})),
			"extensions[0].command", WrongType},
		{"a NUL in an argument", withExtensions(extension(map[string]string{"command": `["./inventory", "a\u0000b"]`})),
			"extensions[0].command[1]", InvalidValue},
		{"a timeout of zero", withExtensions(extension(map[string]string{"timeout_ms": `0`})), "extensions[0].timeout_ms",
			InvalidValue},
		{"a timeout past the bound", withExtensions(extension(map[string]string{"timeout_ms": fmt.Sprint(MaxExtensionTimeoutMS + 1)})),
			"extensions[0].timeout_ms", InvalidValue},
		{"a timeout in seconds", withExtensions(extension(map[string]string{"timeout": `1`})), "extensions[0].timeout",
			UnknownKey},
		{"no timeout", withExtensions(extension(map[string]string{"timeout_ms": ""})), "extensions[0].timeout_ms", MissingKey},
		{"no command", withExtensions(extension(map[string]string{"command": ""})), "extensions[0].command", MissingKey},
		{"no fields", withExtensions(extension(map[string]string{"fields": ""})), "extensions[0].fields", MissingKey},
		{"no name", withExtensions(extension(map[string]string{"name": ""})), "extensions[0].name", MissingKey},
		{"more entries than the bound", withExtensions(func() []string {
			var entries []string
			for i := range MaxExtensions + 1 {
				entries = append(entries, extension(map[string]string{"name": fmt.Sprintf(`"e%d"`, i)}))
			}
			return entries
		}()...), fmt.Sprintf("extensions[%d]", MaxExtensions), LimitExceeded},
		{"a missing executable", withExtensions(extension(map[string]string{"command": `["./absent"]`})),
			"extensions[0].command[0]", CommandNotExecutable},
		{"a regular file with no execute permission", withExtensions(extension(map[string]string{"command": `["./data"]`})),
			"extensions[0].command[0]", CommandNotExecutable},
		{"a directory", withExtensions(extension(map[string]string{"command": `["./folder"]`})),
			"extensions[0].command[0]", CommandNotExecutable},
		{"a named pipe with execute bits", withExtensions(extension(map[string]string{"command": `["./fifo"]`})),
			"extensions[0].command[0]", CommandNotExecutable},
	} {
		t.Run(one.name, func(t *testing.T) {
			_, findings := Compile([]byte(one.content), directory)
			f := refused(t, findings, "configuration", one.subject, one.reason)
			if one.reason == CommandNotExecutable && !strings.Contains(f.Detail, `extension "inventory"`) {
				t.Errorf("the refusal does not name the entry: %s", f.Detail)
			}
		})
	}

	// The control: connection alone with write_content false compiles.
	content := strings.Replace(withExtensions(extension(map[string]string{"fields": `["connection"]`})), `"extensions"`,
		`"write_content": false, "extensions"`, 1)
	if _, findings := Compile([]byte(content), directory); len(findings) != 0 {
		t.Errorf("connection alone with write_content false is refused: %+v", findings)
	}
}

// A relative executable is resolved against the directory the caller names,
// never the working directory: with none named it is refused, and the same
// file compiles once its directory is known.
func TestARelativeCommandNeedsTheConfigurationsDirectory(t *testing.T) {
	directory := t.TempDir()
	executable(t, directory, "inventory")
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(working) })
	_, findings := Compile([]byte(withExtensions(extension(nil))), "")
	refused(t, findings, "configuration", "extensions[0].command[0]", InvalidValue)
	if findings := CheckDocument([]byte(withExtensions(extension(nil)))); len(findings) != 0 {
		t.Errorf("reading the document alone looked for the command: %+v", findings)
	}
}
