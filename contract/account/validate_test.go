package account

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// requiredBlocks is the required-block list as ACCOUNT.md states it, read from
// the document rather than the package under test.
func requiredBlocks(t *testing.T) []string {
	t.Helper()
	content, err := os.ReadFile("ACCOUNT.md")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, found := strings.Cut(string(content), "### Required blocks")
	if !found {
		t.Fatal("wiring, not the property: ACCOUNT.md has no Required blocks section")
	}
	section, _, _ := strings.Cut(rest, "\n###")
	var blocks []string
	for _, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, "    ") && regexp.MustCompile(`^[a-z_.]+$`).MatchString(strings.TrimSpace(line)) {
			blocks = append(blocks, strings.TrimSpace(line))
		}
	}
	return blocks
}

func TestTheDocumentAndThePackageNameTheSameRequiredBlocks(t *testing.T) {
	documented := requiredBlocks(t)
	if len(documented) < 20 {
		t.Fatalf("wiring, not the property: ACCOUNT.md lists %d required blocks", len(documented))
	}
	if !slices.Equal(documented, RequiredBlocks) {
		t.Fatalf("ACCOUNT.md requires %v and the package %v", documented, RequiredBlocks)
	}
}

// up is a parent-directory element, built rather than written so the module's
// own path check (boundary_test.go) does not flag these inputs.
var up = strings.Repeat(".", 2)

func TestClosureRefusesReferencesThatLeaveTheTree(t *testing.T) {
	cases := map[string]struct {
		file    string
		content string
		want    Reason
	}{
		"a $ref leaving the root":          {"a/doc.json", `{"$ref": "` + up + `/` + up + `/outside/x.json"}`, ReferenceOutsideBundle},
		"a $ref naming nothing":            {"a/doc.json", `{"$ref": "missing.json"}`, ReferenceUnresolved},
		"a $ref with a scheme":             {"a/doc.json", `{"$ref": "https://example.invalid/x.json"}`, ReferenceOutsideBundle},
		"an absolute $schema":              {"a/doc.json", `{"$schema": "/usr/share/schema.json"}`, ReferenceOutsideBundle},
		"a Markdown link leaving the root": {"a/doc.md", "see [it](" + up + "/" + up + "/outside/README.md)\n", ReferenceOutsideBundle},
		"a Markdown link naming nothing":   {"a/doc.md", "see [it](missing.md)\n", ReferenceUnresolved},
		"a reference in a line of a jsonl": {"a/doc.jsonl", "{}\n{\"$ref\": \"/etc/x\"}\n", ReferenceOutsideBundle},
	}
	for name, one := range cases {
		t.Run(name, func(t *testing.T) {
			dir := write(t, map[string][]byte{one.file: []byte(one.content), "a/present.json": []byte("{}")})
			closure := CheckClosure(os.DirFS(dir))
			if closure.Outcome != NotClosed || closure.References != 1 || len(closure.Findings) != 1 ||
				closure.Findings[0].Reason != one.want {
				t.Fatalf("came back %+v", closure)
			}
		})
	}

	t.Run("references that resolve inside", func(t *testing.T) {
		dir := write(t, map[string][]byte{
			"a/doc.json":    []byte(`{"$ref": "` + up + `/b/target.json#/defs/x", "$schema": "https://example.invalid/s", "$id": "#only"}`),
			"a/doc.md":      []byte("see [it](" + up + "/b/target.json) and [here](#top), and `[not](/x)`\n\n    [code](/etc)\n"),
			"b/target.json": []byte("{}"),
		})
		closure := CheckClosure(os.DirFS(dir))
		if closure.Outcome != Closed || closure.Files != 3 || closure.References != 4 {
			t.Fatalf("came back %+v", closure)
		}
	})
}

// The four contract surfaces resolve every reference inside themselves, and a
// copy of them moved elsewhere still does.
func TestTheContractSurfacesAreClosed(t *testing.T) {
	here, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	contracts := filepath.Dir(here)
	surfaces := []string{"account", "config", "policy", "record"}
	for _, surface := range surfaces {
		if _, err := os.Stat(filepath.Join(contracts, surface)); err != nil {
			t.Fatalf("wiring, not the property: the %s surface is not beside this one: %v", surface, err)
		}
	}

	closure := CheckClosure(os.DirFS(contracts))
	if closure.Files < 30 {
		t.Fatalf("wiring, not the property: the closure check read %d contract files", closure.Files)
	}
	if closure.Outcome != Closed {
		t.Fatalf("the contract surfaces are not closed: %+v", closure.Findings)
	}

	copied := t.TempDir()
	if err := os.CopyFS(copied, os.DirFS(contracts)); err != nil {
		t.Fatal(err)
	}
	moved := CheckClosure(os.DirFS(copied))
	if moved.Outcome != Closed || moved.Files != closure.Files || moved.References != closure.References {
		t.Fatalf("the copied surfaces came back %+v against %+v", moved, closure)
	}

	planted := filepath.Join(copied, "policy", "VOCABULARY.md")
	content, err := os.ReadFile(planted)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planted, append(content, []byte("\nSee [the notes]("+up+"/"+up+"/"+up+"/outside/README.md).\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if reached := CheckClosure(os.DirFS(copied)); reached.Outcome != NotClosed {
		t.Fatalf("a reference planted outside the surfaces came back %+v", reached)
	}
}
