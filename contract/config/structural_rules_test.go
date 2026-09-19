package config_test

// The rule rows of CONFIG.md's "What the structural check refuses" and the
// refusal sites of structural.go are one set, read here in both directions: a
// refusal no row describes, and a row no refusal performs, are both findings,
// and each one is named rather than counted.
//
// NEITHER SIDE CAN BE COUNTED LEXICALLY, which is what decides the shape of
// this file. `required`, `oneOf` and `unique` each call `add` once and serve
// many call sites, so counting `add` counts neither side; and one row may
// aggregate several members, which counting table lines misses in the other
// direction. So:
//
//	a refusal  one call of the findings vocabulary, resolved to the member
//	           path it refuses. A METHOD on *findings is one rule primitive -
//	           "required and absent", "absent or outside its set" - and counts
//	           once, at the path its own body adds at. A FUNCTION taking
//	           *findings is a GROUP of rules and is recursed into with its path
//	           argument bound, so a helper serving twenty call sites is twenty
//	           refusals, one per call site
//	a rule     one row of the section's four blocks, resolved to the members it
//	           names. A row that aggregates declares how many: "<each of five>"
//	           claims that exactly five refusals exist under that prefix, so a
//	           sixth is red although the row still covers it
//
// Both sides are counted per (document scope, member path, reason) and the
// counts are compared, so a member refused twice for one reason wants two rows.
// What that does NOT establish is which prose sentence belongs to which site:
// where one member is refused twice for one reason, a lost site is caught and
// nothing binds the remaining row to the remaining code.
//
// Nothing is read from a comment. One side is a walk of call expressions, which
// cannot see one; the other reads only the indented rows of one named section.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

// A refusal is one member refused for one reason in one document scope: the
// unit both the rule rows and the refusal sites are counted in.
type refusal struct {
	scope  string
	path   string
	reason string
}

func (r refusal) String() string {
	path := r.path
	if path == "" {
		path = "(document)"
	}
	return fmt.Sprintf("%s %s %s", r.scope, path, r.reason)
}

// Every refusal the structural check performs has a rule row describing it.
func TestEveryStructuralRefusalHasADocumentedRule(t *testing.T) {
	undocumented, _ := reconcileRefusals(t)
	for _, finding := range undocumented {
		t.Error(finding)
	}
}

// Every rule row has a refusal behind it. This is the direction a guard over
// the code alone cannot reach: a documented refusal no code performs reads as
// a promise and nothing anywhere refuses.
func TestEveryDocumentedRuleHasAStructuralRefusal(t *testing.T) {
	_, unperformed := reconcileRefusals(t)
	for _, finding := range unperformed {
		t.Error(finding)
	}
}

// The floors each side must read before anything is compared. Two live
// readings compared with each other AGREE when both come back empty, so a
// section that stopped being found, or a walk that stopped finding sites, would
// otherwise report the two as one set having measured nothing.
//
// THEY GUARD EMPTINESS AND MUST NOT PIN THE POPULATION. Each side reads 84 on
// the tree that set them, and a floor AT 84 fires on a single lost refusal - so
// the run reports its instrument as broken where a rule is what is broken, and
// names a count instead of the member. What pins the population to one is the
// other side of the comparison; this only says that both sides were read.
const (
	refusalFloor = 60
	ruleFloor    = 60
)

// reconcileRefusals returns what each direction found, as one line per finding.
func reconcileRefusals(t *testing.T) (undocumented, unperformed []string) {
	t.Helper()

	performed, where := refusalSites(t)
	rules, aggregates := documentedRules(t)

	sites := 0
	for _, count := range performed {
		sites += count
	}
	rows := 0
	for _, count := range rules {
		rows += count
	}
	for _, aggregate := range aggregates {
		rows += aggregate.want
	}
	if sites < refusalFloor || rows < ruleFloor {
		t.Fatalf("wiring, not the contract: %d refusal sites and %d rule rows read, where at least %d and %d are written; nothing below has measured anything",
			sites, rows, refusalFloor, ruleFloor)
	}

	// Each refusal is attributed to the row that names it exactly, or failing
	// that to an aggregating row whose prefix covers it. What neither covers is
	// a refusal nobody wrote down.
	covered := map[int]int{}
	for one, count := range performed {
		if _, named := rules[one]; named {
			continue
		}
		index, found := -1, false
		for i, aggregate := range aggregates {
			if aggregate.covers(one) {
				index, found = i, true
				break
			}
		}
		if !found {
			undocumented = append(undocumented, fmt.Sprintf(
				"%s is refused at %s, and no rule row of CONFIG.md describes it",
				one, strings.Join(where[one], ", ")))
			continue
		}
		covered[index] += count
	}
	for i, aggregate := range aggregates {
		got := covered[i]
		if got == aggregate.want {
			continue
		}
		finding := fmt.Sprintf("%s %s* %s: the row says %d and %d are refused (%s)",
			aggregate.scope, aggregate.prefix, aggregate.reason, aggregate.want, got,
			strings.Join(aggregate.members(performed), ", "))
		if got > aggregate.want {
			undocumented = append(undocumented, finding)
		} else {
			unperformed = append(unperformed, finding)
		}
	}
	for one, rows := range rules {
		sites := performed[one]
		switch {
		case sites == rows:
		case sites == 0:
			unperformed = append(unperformed, fmt.Sprintf(
				"%s has %d rule row(s) in CONFIG.md and no refusal performs it", one, rows))
		case sites > rows:
			undocumented = append(undocumented, fmt.Sprintf(
				"%s is refused %d times (%s) against %d rule row(s)", one, sites, strings.Join(where[one], ", "), rows))
		default:
			unperformed = append(unperformed, fmt.Sprintf(
				"%s has %d rule row(s) against %d refusal(s) (%s)", one, rows, sites, strings.Join(where[one], ", ")))
		}
	}
	slices.Sort(undocumented)
	slices.Sort(unperformed)
	return undocumented, unperformed
}

// An aggregated rule claims a count under a prefix rather than naming its
// members: "<target>.descendants.<each of five>" is five refusals under
// "...descendants.", and a sixth one is a refusal that row does not describe.
type aggregatedRule struct {
	scope  string
	prefix string
	reason string
	want   int
}

func (a aggregatedRule) covers(one refusal) bool {
	return one.scope == a.scope && one.reason == a.reason && strings.HasPrefix(one.path, a.prefix)
}

func (a aggregatedRule) members(performed map[refusal]int) []string {
	var named []string
	for one := range performed {
		if a.covers(one) {
			named = append(named, one.path)
		}
	}
	slices.Sort(named)
	return named
}

// pathArgument stands for a findings method's path argument while its own
// refusal is being resolved, so `policy` is read as refusing at
// "<its argument>[index]" wherever it is called.
const pathArgument = "\x00"

// indexNames renames index variables by depth. The identifier a loop happens to
// use is a coordinate rather than content: the check's own `policy[index]` and
// the document's `policy[i]` are one member.
var (
	indexVariable = regexp.MustCompile(`\[[A-Za-z_][A-Za-z0-9_]*\]`)
	indexNames    = []string{"i", "j", "k"}
)

func normaliseIndices(path string) string {
	depth := 0
	return indexVariable.ReplaceAllStringFunc(path, func(string) string {
		name := "[deeper than this rule names]"
		if depth < len(indexNames) {
			name = "[" + indexNames[depth] + "]"
		}
		depth++
		return name
	})
}

// refusalSites is every refusal the structural check performs, with the call
// sites of each.
func refusalSites(t *testing.T) (map[refusal]int, map[refusal][]string) {
	t.Helper()

	source := loadStructuralSource(t)

	// One site is one call resolved to one path. A site inside a shared helper
	// is one refusal however many documents reach it, and the documents that do
	// reach it are what says which block of the section describes it.
	type site struct{ at, path, reason string }
	reached := map[site]map[string]bool{}
	for _, entry := range source.entries {
		walker := &refusalWalk{source: source, emit: func(at, path, reason string) {
			one := site{at: at, path: path, reason: reason}
			if reached[one] == nil {
				reached[one] = map[string]bool{}
			}
			reached[one][entry.scope] = true
		}}
		bound := &bindings{
			strings:     map[string][]string{},
			composites:  map[string]*compositeRange{},
			findingsVar: findingsVariable(entry.function),
		}
		if err := walker.function(entry.function, bound); err != nil {
			t.Fatalf("wiring, not the contract: %s is not readable as refusals: %v", entry.function.Name.Name, err)
		}
	}

	performed := map[refusal]int{}
	where := map[refusal][]string{}
	for one, scopes := range reached {
		scope := "shared"
		if len(scopes) == 1 {
			for only := range scopes {
				scope = only
			}
		}
		key := refusal{scope: scope, path: normaliseIndices(one.path), reason: one.reason}
		performed[key]++
		where[key] = append(where[key], one.at)
	}
	for key := range where {
		slices.Sort(where[key])
	}
	return performed, where
}

// structuralSource is the package's own source: the findings vocabulary, the
// functions that read a document through it, and the reasons they give.
type structuralSource struct {
	fset    *token.FileSet
	files   []*ast.File
	reasons map[string]string
	methods map[string]*ast.FuncDecl
	helpers map[string]*ast.FuncDecl
	entries []documentEntry
	effects map[string]methodEffect
}

// A document entry is a function that constructs a findings collector. Its
// scope is that collector's own document name, so a third document added later
// arrives as a scope of its own rather than as silence.
type documentEntry struct {
	function *ast.FuncDecl
	scope    string
}

// A method's effect is the path it adds at, relative to its path argument, and
// the reason it gives. `oneOf` refuses an absent member and a member outside
// its set through two `add` calls and is one rule about one member, which is
// how the document writes it.
type methodEffect struct {
	template string
	reason   string
}

func loadStructuralSource(t *testing.T) *structuralSource {
	t.Helper()

	source := &structuralSource{
		fset:    token.NewFileSet(),
		reasons: map[string]string{},
		methods: map[string]*ast.FuncDecl{},
		helpers: map[string]*ast.FuncDecl{},
		effects: map[string]methodEffect{},
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(source.fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		source.files = append(source.files, file)
	}

	for _, file := range source.files {
		for _, declaration := range file.Decls {
			switch declared := declaration.(type) {
			case *ast.GenDecl:
				source.collectReasons(declared)
			case *ast.FuncDecl:
				source.collectFunction(declared)
			}
		}
	}
	if len(source.entries) != 2 {
		t.Fatalf("wiring, not the contract: %d functions construct a findings collector where 2 are written; the scope rule reads a site reached from more than one of them as shared",
			len(source.entries))
	}
	if len(source.methods) == 0 || len(source.helpers) == 0 || len(source.reasons) == 0 {
		t.Fatalf("wiring, not the contract: %d findings methods, %d readers and %d reasons, so nothing would be walked",
			len(source.methods), len(source.helpers), len(source.reasons))
	}
	return source
}

// collectReasons reads the spelling of each reason from its own declaration, so
// the document's `malformed` and the code's `Malformed` are joined by the
// constant rather than by a table kept beside it.
func (s *structuralSource) collectReasons(declared *ast.GenDecl) {
	if declared.Tok != token.CONST {
		return
	}
	for _, spec := range declared.Specs {
		value, is := spec.(*ast.ValueSpec)
		if !is {
			continue
		}
		named, is := value.Type.(*ast.Ident)
		if !is || named.Name != "Reason" || len(value.Names) != 1 || len(value.Values) != 1 {
			continue
		}
		literal, is := value.Values[0].(*ast.BasicLit)
		if !is || literal.Kind != token.STRING {
			continue
		}
		spelling, err := strconv.Unquote(literal.Value)
		if err != nil {
			continue
		}
		s.reasons[value.Names[0].Name] = spelling
	}
}

func (s *structuralSource) collectFunction(declared *ast.FuncDecl) {
	if declared.Body == nil {
		return
	}
	if isFindings(receiverType(declared)) {
		s.methods[declared.Name.Name] = declared
		return
	}
	for _, parameter := range parameterList(declared) {
		if isFindings(parameter.Type) {
			s.helpers[declared.Name.Name] = declared
			break
		}
	}
	ast.Inspect(declared.Body, func(node ast.Node) bool {
		literal, is := node.(*ast.CompositeLit)
		if !is {
			return true
		}
		named, is := literal.Type.(*ast.Ident)
		if !is || named.Name != "findings" {
			return true
		}
		if scope, found := documentScope(literal); found {
			s.entries = append(s.entries, documentEntry{function: declared, scope: scope})
		}
		return true
	})
}

// documentScope is the document a collector names, cut at the first colon: a
// manifest's document carries the name of the supplied file after it, and the
// section describes manifests as one kind.
func documentScope(literal *ast.CompositeLit) (string, bool) {
	for _, element := range literal.Elts {
		field, is := element.(*ast.KeyValueExpr)
		if !is {
			continue
		}
		key, is := field.Key.(*ast.Ident)
		if !is || key.Name != "document" {
			continue
		}
		value := field.Value
		for {
			binary, is := value.(*ast.BinaryExpr)
			if !is {
				break
			}
			value = binary.X
		}
		text, is := value.(*ast.BasicLit)
		if !is || text.Kind != token.STRING {
			return "", false
		}
		name, err := strconv.Unquote(text.Value)
		if err != nil {
			return "", false
		}
		name, _, _ = strings.Cut(name, ":")
		return name, true
	}
	return "", false
}

func receiverType(declared *ast.FuncDecl) ast.Expr {
	if declared.Recv == nil || len(declared.Recv.List) != 1 {
		return nil
	}
	return declared.Recv.List[0].Type
}

func isFindings(expr ast.Expr) bool {
	pointer, is := expr.(*ast.StarExpr)
	if !is {
		return false
	}
	named, is := pointer.X.(*ast.Ident)
	return is && named.Name == "findings"
}

type parameter struct {
	name string
	Type ast.Expr
}

func parameterList(declared *ast.FuncDecl) []parameter {
	var list []parameter
	if declared.Type.Params == nil {
		return list
	}
	for _, field := range declared.Type.Params.List {
		if len(field.Names) == 0 {
			list = append(list, parameter{Type: field.Type})
			continue
		}
		for _, name := range field.Names {
			list = append(list, parameter{name: name.Name, Type: field.Type})
		}
	}
	return list
}

// findingsVariable is what a function calls its collector, whether it is the
// receiver or a parameter.
func findingsVariable(declared *ast.FuncDecl) string {
	if declared.Recv != nil && len(declared.Recv.List) == 1 && isFindings(declared.Recv.List[0].Type) {
		if len(declared.Recv.List[0].Names) == 1 {
			return declared.Recv.List[0].Names[0].Name
		}
	}
	for _, one := range parameterList(declared) {
		if isFindings(one.Type) {
			return one.name
		}
	}
	return ""
}

// bindings are the values an identifier can hold at one point in the source: a
// string a path is built from, or the elements a range variable takes. An
// identifier bound to something this rule cannot read is POISONED rather than
// left to resolve against an outer one of the same name, because a path built
// from the wrong binding is a refusal attributed to the wrong member.
type bindings struct {
	outer       *bindings
	strings     map[string][]string
	composites  map[string]*compositeRange
	findingsVar string
}

type compositeRange struct {
	elements []*ast.CompositeLit
	fields   map[string]int
}

func (b *bindings) child() *bindings {
	return &bindings{
		outer:       b,
		strings:     map[string][]string{},
		composites:  map[string]*compositeRange{},
		findingsVar: b.findingsVar,
	}
}

func (b *bindings) lookupString(name string) ([]string, bool) {
	for scope := b; scope != nil; scope = scope.outer {
		if values, bound := scope.strings[name]; bound {
			return values, values != nil
		}
		if _, bound := scope.composites[name]; bound {
			return nil, false
		}
	}
	return nil, false
}

func (b *bindings) lookupComposite(name string) (*compositeRange, bool) {
	for scope := b; scope != nil; scope = scope.outer {
		if elements, bound := scope.composites[name]; bound {
			return elements, elements != nil
		}
		if _, bound := scope.strings[name]; bound {
			return nil, false
		}
	}
	return nil, false
}

func (b *bindings) poison(name string) {
	if name == "" || name == "_" {
		return
	}
	b.strings[name] = nil
}

// refusalWalk reads one function's refusals. It counts the refusal-bearing
// calls it visited against the calls the function holds, so a refusal reached
// through a construct this rule does not read is an error rather than a
// refusal silently left out of the population.
type refusalWalk struct {
	source  *structuralSource
	emit    func(at, path, reason string)
	visited int
	reading map[string]bool
}

func (w *refusalWalk) function(declared *ast.FuncDecl, bound *bindings) error {
	name := declared.Name.Name
	if w.reading == nil {
		w.reading = map[string]bool{}
	}
	if w.reading[name] {
		return fmt.Errorf("%s reads itself, which this rule cannot resolve to a member", name)
	}
	w.reading[name] = true
	outer := w.visited
	w.visited = 0
	err := w.statements(declared.Body.List, bound)
	read := w.visited
	w.visited = outer
	delete(w.reading, name)
	if err != nil {
		return err
	}
	// The ran-against-collected comparison, for the walk itself: a refusal
	// reached through a construct this rule does not read is an error, never a
	// refusal quietly left out of the population.
	if held := w.source.refusalCalls(declared, bound.findingsVar); read != held {
		return fmt.Errorf("%s holds %d refusal calls and this rule read %d", name, held, read)
	}
	return nil
}

// refusalCalls is how many refusal-bearing calls a function holds, counted
// flat. It is the ran-against-collected comparison for the walk itself.
func (s *structuralSource) refusalCalls(declared *ast.FuncDecl, findingsVar string) int {
	held := 0
	ast.Inspect(declared.Body, func(node ast.Node) bool {
		call, is := node.(*ast.CallExpr)
		if !is {
			return true
		}
		if s.refusalMethod(call, findingsVar) != "" {
			held++
			return true
		}
		if named, is := call.Fun.(*ast.Ident); is {
			if _, reader := s.helpers[named.Name]; reader {
				held++
			}
		}
		return true
	})
	return held
}

// refusalMethod is the findings method a call names, or "" where it names none.
func (s *structuralSource) refusalMethod(call *ast.CallExpr, findingsVar string) string {
	selector, is := call.Fun.(*ast.SelectorExpr)
	if !is {
		return ""
	}
	receiver, is := selector.X.(*ast.Ident)
	if !is || receiver.Name != findingsVar || findingsVar == "" {
		return ""
	}
	if _, known := s.methods[selector.Sel.Name]; !known {
		return ""
	}
	return selector.Sel.Name
}

func (w *refusalWalk) statements(list []ast.Stmt, bound *bindings) error {
	for _, statement := range list {
		if err := w.statement(statement, bound); err != nil {
			return err
		}
	}
	return nil
}

func (w *refusalWalk) statement(statement ast.Stmt, bound *bindings) error {
	switch held := statement.(type) {
	case *ast.AssignStmt:
		w.bind(held, bound)
		return nil
	case *ast.ExprStmt:
		call, is := held.X.(*ast.CallExpr)
		if !is {
			return nil
		}
		return w.call(call, bound)
	case *ast.IfStmt:
		inner := bound.child()
		if held.Init != nil {
			if err := w.statement(held.Init, inner); err != nil {
				return err
			}
		}
		if err := w.statements(held.Body.List, inner); err != nil {
			return err
		}
		if held.Else != nil {
			return w.statement(held.Else, inner)
		}
		return nil
	case *ast.BlockStmt:
		return w.statements(held.List, bound.child())
	case *ast.RangeStmt:
		inner := bound.child()
		if key, is := held.Key.(*ast.Ident); is {
			inner.poison(key.Name)
		}
		if value, is := held.Value.(*ast.Ident); is {
			inner.poison(value.Name)
			if elements := compositeElements(held.X); elements != nil {
				inner.composites[value.Name] = elements
				delete(inner.strings, value.Name)
			}
		}
		return w.statements(held.Body.List, inner)
	case *ast.ForStmt:
		inner := bound.child()
		if held.Init != nil {
			if err := w.statement(held.Init, inner); err != nil {
				return err
			}
		}
		return w.statements(held.Body.List, inner)
	case *ast.SwitchStmt:
		inner := bound.child()
		if held.Init != nil {
			if err := w.statement(held.Init, inner); err != nil {
				return err
			}
		}
		for _, clause := range held.Body.List {
			one, is := clause.(*ast.CaseClause)
			if !is {
				continue
			}
			if err := w.statements(one.Body, inner.child()); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

// bind records what an assignment makes an identifier hold. What cannot be
// resolved is poisoned rather than dropped.
func (w *refusalWalk) bind(assignment *ast.AssignStmt, bound *bindings) {
	if len(assignment.Lhs) != len(assignment.Rhs) {
		for _, target := range assignment.Lhs {
			if named, is := target.(*ast.Ident); is {
				bound.poison(named.Name)
			}
		}
		return
	}
	for i, target := range assignment.Lhs {
		named, is := target.(*ast.Ident)
		if !is {
			continue
		}
		// A function that opens a collector of its own is a document entry, and
		// what it calls that collector is what its refusals are made through.
		if constructsFindings(assignment.Rhs[i]) {
			bound.poison(named.Name)
			bound.findingsVar = named.Name
			continue
		}
		values, err := w.source.resolve(assignment.Rhs[i], bound)
		if err != nil {
			bound.poison(named.Name)
			continue
		}
		bound.strings[named.Name] = values
	}
}

func (w *refusalWalk) call(call *ast.CallExpr, bound *bindings) error {
	if method := w.source.refusalMethod(call, bound.findingsVar); method != "" {
		w.visited++
		return w.refusal(method, call, bound)
	}
	named, is := call.Fun.(*ast.Ident)
	if !is {
		return nil
	}
	reader, known := w.source.helpers[named.Name]
	if !known {
		return nil
	}
	w.visited++
	inner, err := w.source.arguments(reader, call, bound)
	if err != nil {
		return fmt.Errorf("the call to %s at %s: %w", named.Name, w.source.at(call.Pos()), err)
	}
	return w.function(reader, inner)
}

// refusal emits what one call of the findings vocabulary refuses. `add` names
// its own path and reason; every other method is one rule at the path its body
// adds at.
func (w *refusalWalk) refusal(method string, call *ast.CallExpr, bound *bindings) error {
	at := w.source.at(call.Pos())
	if len(call.Args) < 2 {
		return fmt.Errorf("the call to %s at %s takes %d arguments", method, at, len(call.Args))
	}
	paths, err := w.source.resolve(call.Args[0], bound)
	if err != nil {
		return fmt.Errorf("the path of %s at %s: %w", method, at, err)
	}
	if method == "add" {
		named, is := call.Args[1].(*ast.Ident)
		if !is {
			return fmt.Errorf("the reason of add at %s is not a named reason", at)
		}
		reason, known := w.source.reasons[named.Name]
		if !known {
			return fmt.Errorf("the reason %s given at %s is not a declared reason", named.Name, at)
		}
		for _, path := range paths {
			w.emit(at, path, reason)
		}
		return nil
	}
	effect, err := w.source.effect(method)
	if err != nil {
		return err
	}
	for _, path := range paths {
		w.emit(at, strings.ReplaceAll(effect.template, pathArgument, path), effect.reason)
	}
	return nil
}

// effect is what a findings method refuses, resolved once from its own body.
// A method that refuses at more than one member, or for more than one reason,
// is not one rule primitive and the rule says so rather than counting it as
// one.
func (s *structuralSource) effect(method string) (methodEffect, error) {
	if known, computed := s.effects[method]; computed {
		return known, nil
	}
	declared := s.methods[method]
	var found []methodEffect
	walker := &refusalWalk{source: s, emit: func(_, path, reason string) {
		found = append(found, methodEffect{template: path, reason: reason})
	}}
	bound := &bindings{
		strings:     map[string][]string{},
		composites:  map[string]*compositeRange{},
		findingsVar: findingsVariable(declared),
	}
	for _, one := range parameterList(declared) {
		if named, is := one.Type.(*ast.Ident); is && named.Name == "string" {
			bound.strings[one.name] = []string{pathArgument}
			break
		}
	}
	if err := walker.function(declared, bound); err != nil {
		return methodEffect{}, fmt.Errorf("the findings method %s: %w", method, err)
	}
	if len(found) == 0 {
		return methodEffect{}, fmt.Errorf("the findings method %s refuses nothing", method)
	}
	for _, one := range found[1:] {
		if one != found[0] {
			return methodEffect{}, fmt.Errorf("the findings method %s refuses %s as %s and %s as %s, so it is not one rule",
				method, found[0].template, found[0].reason, one.template, one.reason)
		}
	}
	s.effects[method] = found[0]
	return found[0], nil
}

// arguments binds a reader's string parameters to what its caller passes.
func (s *structuralSource) arguments(reader *ast.FuncDecl, call *ast.CallExpr, bound *bindings) (*bindings, error) {
	inner := &bindings{
		strings:     map[string][]string{},
		composites:  map[string]*compositeRange{},
		findingsVar: findingsVariable(reader),
	}
	list := parameterList(reader)
	if len(list) != len(call.Args) {
		return nil, fmt.Errorf("%d arguments against %d parameters", len(call.Args), len(list))
	}
	for i, one := range list {
		named, is := one.Type.(*ast.Ident)
		if !is || named.Name != "string" {
			continue
		}
		values, err := s.resolve(call.Args[i], bound)
		if err != nil {
			return nil, fmt.Errorf("the argument for %s: %w", one.name, err)
		}
		inner.strings[one.name] = values
	}
	return inner, nil
}

func (s *structuralSource) at(pos token.Pos) string {
	position := s.fset.Position(pos)
	return fmt.Sprintf("%s:%d", filepath.Base(position.Filename), position.Line)
}

// resolve reads a path expression. A path can stand for several members where
// it is built from a range over a literal - the two observer settings, the five
// lifecycle hooks - so every value is returned and each is its own refusal.
func (s *structuralSource) resolve(expr ast.Expr, bound *bindings) ([]string, error) {
	switch held := expr.(type) {
	case *ast.ParenExpr:
		return s.resolve(held.X, bound)
	case *ast.BasicLit:
		if held.Kind != token.STRING {
			return nil, fmt.Errorf("%s is not a string", held.Value)
		}
		text, err := strconv.Unquote(held.Value)
		if err != nil {
			return nil, err
		}
		return []string{text}, nil
	case *ast.Ident:
		values, known := bound.lookupString(held.Name)
		if !known {
			return nil, fmt.Errorf("%s holds no value this rule can read", held.Name)
		}
		return values, nil
	case *ast.BinaryExpr:
		if held.Op != token.ADD {
			return nil, fmt.Errorf("a path is not built with %s", held.Op)
		}
		left, err := s.resolve(held.X, bound)
		if err != nil {
			return nil, err
		}
		right, err := s.resolve(held.Y, bound)
		if err != nil {
			return nil, err
		}
		return join(left, right), nil
	case *ast.SelectorExpr:
		return s.field(held, bound)
	case *ast.IndexExpr:
		return s.element(held, bound)
	case *ast.CallExpr:
		return s.format(held, bound)
	default:
		return nil, fmt.Errorf("%T is not an expression this rule reads", expr)
	}
}

func join(left, right []string) []string {
	var joined []string
	for _, l := range left {
		for _, r := range right {
			joined = append(joined, l+r)
		}
	}
	return joined
}

// field reads one member of every element of a range over a literal.
func (s *structuralSource) field(selector *ast.SelectorExpr, bound *bindings) ([]string, error) {
	named, is := selector.X.(*ast.Ident)
	if !is {
		return nil, fmt.Errorf("%T.%s is not a value this rule reads", selector.X, selector.Sel.Name)
	}
	elements, found := bound.lookupComposite(named.Name)
	if !found {
		return nil, fmt.Errorf("%s.%s holds no value this rule can read", named.Name, selector.Sel.Name)
	}
	at, declared := elements.fields[selector.Sel.Name]
	if !declared {
		return nil, fmt.Errorf("%s has no member %s", named.Name, selector.Sel.Name)
	}
	return s.elementsAt(elements, at, bound)
}

func (s *structuralSource) element(index *ast.IndexExpr, bound *bindings) ([]string, error) {
	named, is := index.X.(*ast.Ident)
	if !is {
		return nil, fmt.Errorf("%T[...] is not a value this rule reads", index.X)
	}
	elements, found := bound.lookupComposite(named.Name)
	if !found {
		return nil, fmt.Errorf("%s holds no value this rule can read", named.Name)
	}
	literal, is := index.Index.(*ast.BasicLit)
	if !is || literal.Kind != token.INT {
		return nil, fmt.Errorf("%s is indexed by something this rule cannot read", named.Name)
	}
	at, err := strconv.Atoi(literal.Value)
	if err != nil {
		return nil, err
	}
	return s.elementsAt(elements, at, bound)
}

func (s *structuralSource) elementsAt(elements *compositeRange, at int, bound *bindings) ([]string, error) {
	var values []string
	for _, element := range elements.elements {
		if at >= len(element.Elts) {
			return nil, fmt.Errorf("an element of the literal has %d members", len(element.Elts))
		}
		resolved, err := s.resolve(element.Elts[at], bound)
		if err != nil {
			return nil, err
		}
		values = append(values, resolved...)
	}
	return values, nil
}

var formatVerb = regexp.MustCompile(`%.`)

// format reads a path built with fmt.Sprintf. An index argument stands for
// itself, so the member is `targets[i]` rather than a number: a refusal is
// about a member of a list, not about one entry of one document.
func (s *structuralSource) format(call *ast.CallExpr, bound *bindings) ([]string, error) {
	selector, is := call.Fun.(*ast.SelectorExpr)
	if !is || selector.Sel.Name != "Sprintf" {
		return nil, fmt.Errorf("a path is not built by this call")
	}
	if len(call.Args) == 0 {
		return nil, fmt.Errorf("Sprintf with no format")
	}
	formats, err := s.resolve(call.Args[0], bound)
	if err != nil {
		return nil, err
	}
	if len(formats) != 1 {
		return nil, fmt.Errorf("%d format strings", len(formats))
	}
	format := formats[0]
	values := []string{""}
	argument := 1
	rest := format
	for {
		verb := formatVerb.FindStringIndex(rest)
		if verb == nil {
			values = join(values, []string{rest})
			break
		}
		values = join(values, []string{rest[:verb[0]]})
		if argument >= len(call.Args) {
			return nil, fmt.Errorf("%q takes more arguments than it is given", format)
		}
		switch rest[verb[0]:verb[1]] {
		case "%s":
			resolved, err := s.resolve(call.Args[argument], bound)
			if err != nil {
				return nil, err
			}
			values = join(values, resolved)
		case "%d":
			named, is := call.Args[argument].(*ast.Ident)
			if !is {
				return nil, fmt.Errorf("an index this rule cannot name")
			}
			values = join(values, []string{named.Name})
		default:
			return nil, fmt.Errorf("%q holds a verb this rule does not read", format)
		}
		argument++
		rest = rest[verb[1]:]
	}
	if argument != len(call.Args) {
		return nil, fmt.Errorf("%q is given %d arguments and uses %d", format, len(call.Args)-1, argument-1)
	}
	return values, nil
}

func constructsFindings(expr ast.Expr) bool {
	if unary, is := expr.(*ast.UnaryExpr); is && unary.Op == token.AND {
		expr = unary.X
	}
	literal, is := expr.(*ast.CompositeLit)
	if !is {
		return false
	}
	named, is := literal.Type.(*ast.Ident)
	return is && named.Name == "findings"
}

// The section's four blocks, and the document scope each one describes. A
// heading this table does not carry is an error rather than a block read as
// nothing: rows nobody read are rules nobody checked, and that failure is
// silent in the direction that matters.
var ruleBlocks = []struct{ heading, scope string }{
	{"**The configuration**", "configuration"},
	{"**Every pipeline**", "shared"},
	{"**A manifest**", "manifest"},
	{"**A component declaration in a manifest.**", "manifest"},
}

// What the section's own preamble means by its stand-ins, as the member paths
// a finding carries.
var ruleStandIns = map[string]string{
	"<target>":    "observation_scope.targets[i]",
	"<rule>":      "traffic_scope.rules[i]",
	"<library>":   "observation_scope.libraries[i]",
	"<sink>":      "sinks[i]",
	"<pipeline>":  "pipelines[i]",
	"<component>": "components[i]",
	"(document)":  "",
}

const (
	rulesHeading = "## What the structural check refuses"

	// A row starts at the column its block's rows start at; a member list too
	// long for one line continues just inside it, and a condition continues
	// under the condition column. Only the first two are read.
	rowIndent    = 4
	memberIndent = 8
)

var (
	ruleRow        = regexp.MustCompile(`^ {4}(\S.*?) {2,}(\S+) {2,}(\S.*)$`)
	aggregated     = regexp.MustCompile(`^(.*\.)<each of ([a-z]+)>$`)
	standIn        = regexp.MustCompile(`<[^>]*>`)
	writtenNumbers = map[string]int{"two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10}
)

type parsedRow struct {
	scope  string
	spec   string
	reason string
	line   int
}

// documentedRules is every rule row of the section, as the refusals each row
// describes. A row that aggregates is returned as its claim rather than as
// members, because the members are exactly what it declines to name.
func documentedRules(t *testing.T) (map[refusal]int, []aggregatedRule) {
	t.Helper()

	content, err := os.ReadFile("CONFIG.md")
	if err != nil {
		t.Fatalf("read the specification: %v", err)
	}
	rows, blocks := parseRuleRows(t, string(content))
	for _, block := range ruleBlocks {
		if !blocks[block.heading] {
			t.Fatalf("wiring, not the contract: CONFIG.md has no %s block, so its rules were not read", block.heading)
		}
	}

	rules := map[refusal]int{}
	var aggregates []aggregatedRule
	used := map[string]bool{}
	for _, row := range rows {
		if !slices.Contains(config.StructuralReasons, config.Reason(row.reason)) {
			t.Fatalf("wiring, not the contract: CONFIG.md:%d gives %q, which is not a structural reason", row.line, row.reason)
		}
		members := expandMembers(t, row, used)
		for _, member := range members {
			if parts := aggregated.FindStringSubmatch(member); parts != nil {
				want, written := writtenNumbers[parts[2]]
				if !written {
					t.Fatalf("wiring, not the contract: CONFIG.md:%d aggregates %q members, which is not a number this rule reads", row.line, parts[2])
				}
				aggregates = append(aggregates, aggregatedRule{scope: row.scope, prefix: normaliseIndices(parts[1]), reason: row.reason, want: want})
				continue
			}
			if left := standIn.FindString(member); left != "" {
				t.Fatalf("wiring, not the contract: CONFIG.md:%d names %s, which this rule does not expand", row.line, left)
			}
			rules[refusal{scope: row.scope, path: normaliseIndices(member), reason: row.reason}]++
		}
	}
	for name := range ruleStandIns {
		if !used[name] {
			t.Fatalf("wiring, not the contract: no rule row uses %s, so this rule expands a stand-in the document no longer writes", name)
		}
	}
	return rules, aggregates
}

func parseRuleRows(t *testing.T, content string) ([]parsedRow, map[string]bool) {
	t.Helper()

	var rows []parsedRow
	blocks := map[string]bool{}
	inSection, scope := false, ""
	for number, line := range strings.Split(content, "\n") {
		at := number + 1
		if strings.HasPrefix(line, "## ") {
			inSection, scope = line == rulesHeading, ""
			continue
		}
		if !inSection {
			continue
		}
		if strings.HasPrefix(line, "**") {
			scope = ""
			for _, block := range ruleBlocks {
				if strings.HasPrefix(line, block.heading) {
					scope, blocks[block.heading] = block.scope, true
					break
				}
			}
			if scope == "" {
				t.Fatalf("wiring, not the contract: CONFIG.md:%d opens a block this rule does not read: %s", at, line)
			}
			continue
		}
		if parts := ruleRow.FindStringSubmatch(line); parts != nil {
			if scope == "" {
				t.Fatalf("wiring, not the contract: CONFIG.md:%d is a rule row inside no block: %s", at, line)
			}
			rows = append(rows, parsedRow{scope: scope, spec: parts[1], reason: parts[2], line: at})
			continue
		}
		trimmed := strings.TrimLeft(line, " ")
		indent := len(line) - len(trimmed)
		switch {
		case trimmed == "":
		case indent == rowIndent:
			t.Fatalf("wiring, not the contract: CONFIG.md:%d starts a rule row this rule cannot read: %s", at, line)
		case indent > rowIndent && indent <= memberIndent:
			if len(rows) == 0 || !strings.HasSuffix(rows[len(rows)-1].spec, ",") {
				t.Fatalf("wiring, not the contract: CONFIG.md:%d continues a member list that is not open: %s", at, line)
			}
			rows[len(rows)-1].spec += " " + trimmed
		}
		// Anything further in is the condition's own continuation, which
		// nothing here reads: the prose says when a member is refused and the
		// member and the reason are what is being reconciled.
	}
	return rows, blocks
}

// expandMembers is the members one row names. A member written from the last
// one's own prefix - ".stream" under "subscribers[i].name" - is read against
// it, which is how the document writes a member list too long for one line.
func expandMembers(t *testing.T, row parsedRow, used map[string]bool) []string {
	t.Helper()

	var members []string
	for _, piece := range strings.Split(row.spec, ",") {
		piece = strings.TrimSpace(piece)
		if piece == "" {
			continue
		}
		if strings.HasPrefix(piece, ".") {
			if len(members) == 0 {
				t.Fatalf("wiring, not the contract: CONFIG.md:%d starts a member list with %q", row.line, piece)
			}
			previous := members[len(members)-1]
			cut := strings.LastIndex(previous, ".")
			if cut < 0 {
				t.Fatalf("wiring, not the contract: CONFIG.md:%d writes %q under %q, which has no member to take", row.line, piece, previous)
			}
			members = append(members, previous[:cut]+piece)
			continue
		}
		for name, path := range ruleStandIns {
			if strings.HasPrefix(piece, name) {
				piece, used[name] = path+piece[len(name):], true
				break
			}
		}
		members = append(members, piece)
	}
	if len(members) == 0 {
		t.Fatalf("wiring, not the contract: CONFIG.md:%d names no member", row.line)
	}
	return members
}

// compositeElements is the elements of a range over a literal, with the member
// names of its element type where it has them.
func compositeElements(over ast.Expr) *compositeRange {
	literal, is := over.(*ast.CompositeLit)
	if !is {
		return nil
	}
	array, is := literal.Type.(*ast.ArrayType)
	if !is {
		return nil
	}
	elements := &compositeRange{fields: map[string]int{}}
	if structure, is := array.Elt.(*ast.StructType); is && structure.Fields != nil {
		at := 0
		for _, field := range structure.Fields.List {
			for _, name := range field.Names {
				elements.fields[name.Name] = at
				at++
			}
		}
	}
	for _, element := range literal.Elts {
		inner, is := element.(*ast.CompositeLit)
		if !is {
			return nil
		}
		elements.elements = append(elements.elements, inner)
	}
	if len(elements.elements) == 0 {
		return nil
	}
	return elements
}
