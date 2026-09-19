package observer

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Every package the module and its tests depend on comes from the module
// itself or from a module go.mod declares. A go.work file above the tree can
// resolve an import go.mod never names; this is what refuses it.
func TestObserverReachesNothingOutsideItself(t *testing.T) {
	declared := declaredModules(t)
	for _, dependency := range nonStandardImports(t) {
		if !declared[dependency.module] {
			t.Errorf("observer imports %s from module %q, which go.mod does not declare", dependency.path, dependency.module)
		}
	}
}

// declaredModules is this module and every module go.mod requires.
func declaredModules(t *testing.T) map[string]bool {
	t.Helper()

	cmd := exec.Command("go", "mod", "edit", "-json")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go mod edit -json: %v\n%s", err, stderr.String())
	}
	var file struct {
		Module  struct{ Path string }
		Require []struct{ Path string }
	}
	if err := json.Unmarshal(out, &file); err != nil {
		t.Fatalf("go mod edit -json: %v", err)
	}
	if file.Module.Path == "" {
		t.Fatal("go.mod names no module, so the boundary was not measured")
	}
	declared := map[string]bool{file.Module.Path: true}
	for _, required := range file.Require {
		declared[required.Path] = true
	}
	return declared
}

type dependency struct{ path, module string }

// nonStandardImports is every non-standard package the module's packages and
// their tests depend on, with the module each resolves from.
//
// -test makes test-only imports count. It also synthesises the test binary's
// packages (ForTest, and the .test main), which nobody wrote and are dropped.
func nonStandardImports(t *testing.T) []dependency {
	t.Helper()

	cmd := exec.Command("go", "list", "-deps", "-test", "-f",
		"{{if and (not .Standard) (not .ForTest)}}{{.ImportPath}} {{with .Module}}{{.Path}}{{end}}{{end}}", "./...")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps -test: %v\n%s", err, stderr.String())
	}

	var dependencies []dependency
	for _, line := range strings.Split(string(out), "\n") {
		path, module, _ := strings.Cut(strings.TrimSpace(line), " ")
		if path == "" || strings.HasSuffix(path, ".test") {
			continue
		}
		dependencies = append(dependencies, dependency{path: path, module: module})
	}

	// The module always depends on at least itself; empty means nothing was
	// measured.
	if len(dependencies) == 0 {
		t.Fatal("go list -deps -test returned nothing; the boundary was not measured")
	}
	return dependencies
}

// No file names a path outside the module. go list sees imports, not reads,
// so string literals are checked too; a path in a comment is not a finding.
func TestNoFileInThisModuleNamesAPathOutsideIt(t *testing.T) {
	files := goFiles(t)
	if len(files) < 8 {
		t.Fatalf("the walk found %d Go files, too few to be the module", len(files))
	}

	// Built rather than written, so this file does not report itself.
	parent := strings.Repeat(".", 2)

	for _, path := range files {
		fileSet := token.NewFileSet()
		parsed, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}

		ast.Inspect(parsed, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				return true
			}
			for _, element := range strings.Split(filepath.ToSlash(value), "/") {
				if element == parent {
					t.Errorf("%s:%d names the path %q; this module reaches nothing outside itself",
						path, fileSet.Position(literal.Pos()).Line, value)
					return true
				}
			}
			return true
		})
	}
}

// goFiles is every Go file of the module, found by walking so that testdata
// and files behind build tags are included.
func goFiles(t *testing.T) []string {
	t.Helper()

	var files []string
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}
	return files
}
