package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"

	contractaccount "github.com/evandukss/edge-observer/contract/account"
)

func checkDocumentBundle(examples fs.FS) map[string]error {
	result := contractaccount.Validate(examples)
	if result.Outcome != contractaccount.Validated || result.Examined.Members != 5 ||
		result.Examined.Records == 0 || result.Examined.Blocks == 0 {
		return map[string]error{"": fmt.Errorf("dummy bundle validation: %+v", result)}
	}
	return nil
}

// Discover version identifiers from production Go constant declarations, not a
// second list of document kinds. The internal numeric operational account is
// outside this published string-version vocabulary. Count only top-level JSON
// discriminators: a manifest's reference to a record is not a record example.
func TestEveryVersionedDocumentKindHasAnExample(t *testing.T) {
	tree := os.DirFS(moduleRoot(t))
	kinds := map[string]string{}
	covered := map[string]bool{}
	sources, documents := 0, 0
	err := fs.WalkDir(tree, "contract", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			content, err := fs.ReadFile(tree, name)
			if err != nil {
				return err
			}
			source, err := parser.ParseFile(token.NewFileSet(), name, content, 0)
			if err != nil {
				return err
			}
			sources++
			for _, declaration := range source.Decls {
				group, ok := declaration.(*ast.GenDecl)
				if !ok || group.Tok != token.CONST {
					continue
				}
				for _, spec := range group.Specs {
					for _, value := range spec.(*ast.ValueSpec).Values {
						literal, ok := value.(*ast.BasicLit)
						if !ok || literal.Kind != token.STRING {
							continue
						}
						version, err := strconv.Unquote(literal.Value)
						if err != nil {
							return err
						}
						if strings.HasPrefix(version, "observer.") && strings.Contains(version, "/") {
							kinds[version] = name
						}
					}
				}
			}
		}
		if !isExample(name) || (!strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".jsonl")) {
			return nil
		}
		content, err := fs.ReadFile(tree, name)
		if err != nil {
			return err
		}
		decoder := json.NewDecoder(bytes.NewReader(content))
		for {
			var document any
			if err := decoder.Decode(&document); err == io.EOF {
				break
			} else if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			documents++
			object, _ := document.(map[string]any)
			for _, key := range []string{"version", "account", "bundle", "interface", "vocabulary"} {
				if version, ok := object[key].(string); ok {
					covered[version] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if sources == 0 || len(kinds) == 0 || documents == 0 {
		t.Fatalf("empty coverage input: %d source files, %d kinds, %d JSON documents", sources, len(kinds), documents)
	}
	t.Logf("read %d source files and %d example documents for %d versioned kinds", sources, documents, len(kinds))
	for version, source := range kinds {
		if !covered[version] {
			t.Errorf("%s declared in %s has no example document", version, source)
		}
	}
}
