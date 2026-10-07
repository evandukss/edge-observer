package config

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// minimal is the smallest configuration that compiles.
const minimal = `{"version": "observer.config/1", "output": "/var/lib/observer",
	"watch": [{"name": "api", "exe": "/usr/bin/php"}]}`

// withRules is minimal with rules spliced in at the top level.
func withRules(rules string) string {
	return strings.Replace(minimal, `"watch"`, rules+`, "watch"`, 1)
}

// refused asserts one finding with this document, subject and reason, and
// returns it.
func refused(t *testing.T, findings []Finding, document, subject string, reason Reason) Finding {
	t.Helper()
	for _, f := range findings {
		if f.Document == document && f.Subject == subject && f.Reason == reason {
			return f
		}
	}
	t.Fatalf("no %s refusal of %s %q among %+v", reason, document, subject, findings)
	return Finding{}
}

func compiles(t *testing.T, configuration string) *Compiled {
	t.Helper()
	compiled, findings := Compile([]byte(configuration), "")
	if len(findings) > 0 || compiled == nil {
		t.Fatalf("refused: %+v", findings)
	}
	return compiled
}

func exchangeSlots(t *testing.T, c *Compiled) []EffectiveSlot {
	t.Helper()
	for _, p := range c.Plan.Pipelines() {
		if p.Name == ExchangesPipeline {
			return p.Slots
		}
	}
	t.Fatalf("no %s pipeline in %+v", ExchangesPipeline, c.Plan.Pipelines())
	return nil
}

func implementations(slots []EffectiveSlot) []string {
	var out []string
	for _, s := range slots {
		out = append(out, s.Implementation)
	}
	return out
}

func TestTheConfigurationIsRefusedAtAnotherVersionNamingItsOwn(t *testing.T) {
	_, findings := ReadFile([]byte(`{"version": "observer.config/draft", "output": "/x", "watch": []}`))
	if f := refused(t, findings, "configuration", "version", UnknownVersion); !strings.Contains(f.Detail, FileVersion) {
		t.Errorf("the refusal does not name %s: %s", FileVersion, f.Detail)
	}
}

func TestTheReaderIsStrictAndNamesTheKey(t *testing.T) {
	for _, one := range []struct {
		name, content, subject string
		reason                 Reason
	}{
		{"unknown top-level key", withRules(`"remvoe": {}`), "remvoe", UnknownKey},
		{"unknown key inside remove", withRules(`"remove": {"remvoe": []}`), "remove.remvoe", UnknownKey},
		{"a key in another case", withRules(`"Remove": {}`), "Remove", UnknownKey},
		{"a key written twice", withRules(`"remove": {"headers": [], "headers": ["cookie"]}`), "remove.headers", DuplicateKey},
		{"a wrong type", withRules(`"remove": {"headers": "cookie"}`), "remove.headers", WrongType},
		{"output missing", `{"version": "observer.config/1", "watch": [{"name": "a", "exe": "/x"}]}`, "output", MissingKey},
		{"watch missing", `{"version": "observer.config/1", "output": "/x"}`, "watch", MissingKey},
		{"a watch entry naming no condition", `{"version": "observer.config/1", "output": "/x", "watch": [{"name": "a"}]}`,
			"watch[0]", MissingKey},
		{"children outside its values", `{"version": "observer.config/1", "output": "/x",
			"watch": [{"name": "a", "exe": "/x", "children": "some"}]}`, "watch[0].children", InvalidValue},
		{"a bad header name", withRules(`"remove": {"headers": ["bad name"]}`), "remove.headers[0]", InvalidValue},
		{"a bad pointer", withRules(`"remove": {"json": {"request": ["card"]}}`), "remove.json.request[0]", InvalidValue},
		{"a truncation too long", withRules(`"truncate": {"headers": {"x-trace-id": 4097}}`), "truncate.headers.x-trace-id", InvalidValue},
		{"a limit of zero", withRules(`"limits": {"events": 0}`), "limits.events", InvalidValue},
		{"no workers", withRules(`"limits": {"workers": 0}`), "limits.workers", InvalidValue},
		{"more workers than the bound", withRules(fmt.Sprintf(`"limits": {"workers": %d}`, MaxWorkers+1)),
			"limits.workers", InvalidValue},
		// packs is not a key of this format: refused by name, never read and
		// never ignored.
		{"packs", withRules(`"packs": ["credentials"]`), "packs", UnknownKey},
	} {
		t.Run(one.name, func(t *testing.T) {
			_, findings := ReadFile([]byte(one.content))
			refused(t, findings, "configuration", one.subject, one.reason)
		})
	}
	_, findings := ReadFile([]byte(minimal + ` {}`))
	refused(t, findings, "configuration", "", TrailingContent)
	if _, findings := ReadFile([]byte(minimal)); len(findings) != 0 {
		t.Fatalf("wiring, not the property: the minimal file is refused: %+v", findings)
	}
}

func TestAbsentKeysResolveToTheirDefaults(t *testing.T) {
	file, findings := ReadFile([]byte(minimal))
	if len(findings) != 0 {
		t.Fatal(findings)
	}
	if file.Log != LogStdout || !file.WriteContent || file.Watch[0].Children != ChildrenAll ||
		file.Limits != (Limits{DefaultAdmittedEventLimit, DefaultStateEverySeconds,
			DefaultWorkers}) || file.Extensions != nil {
		t.Errorf("defaults: %+v", file)
	}
}

// The contract's own example compiles, in the fixed order, with every removal
// an exclusion.
func TestTheContractExampleCompilesInTheFixedOrder(t *testing.T) {
	c := compiles(t, `{
	  "version": "observer.config/1", "output": "/var/lib/observer", "log": "stdout",
	  "watch": [{"name": "api", "exe": "/usr/bin/php", "args": ["/srv/api/main.php"], "children": "all"}],
	  "ignore": [{"exe": "/usr/bin/curl"}], "libraries": [], "write_content": true,
	  "remove": {"headers": ["authorization", "cookie"], "query": ["token"], "query_string": false,
	    "form": ["card_number"], "json": {"request": ["/card/number"], "response": ["/items/*/pan"]},
	    "bodies": [], "body_values": []},
	  "mask": {"headers": {"x-api-key": "withheld"}, "json": {"response": {"/email": "withheld"}}},
	  "truncate": {"headers": {"x-trace-id": 8}},
	  "limits": {"events": 16384, "state_every_seconds": 30, "workers": 1}}`)
	want := []string{RemoveHeaders, RemoveQueryParameters, RequestBodyFields, RemoveJSONFields, ReplaceHeaderValues,
		ReplaceJSONValues, TruncateHeaderValues}
	if got := implementations(exchangeSlots(t, c)); !slices.Equal(got, want) {
		t.Errorf("operations %v, want %v", got, want)
	}
	if got := exchangeSlots(t, c)[0].Arguments.Headers; !slices.Equal(got, []string{"authorization", "cookie"}) {
		t.Errorf("removed headers %v", got)
	}
	var fields []string
	for _, e := range c.Plan.Exclusions() {
		fields = append(fields, e.Field)
	}
	for _, field := range []string{"message.headers.cookie", "message.query.token", "message.form.card_number",
		"message.body.json/card/number", "message.body.json/items/*/pan"} {
		if !slices.Contains(fields, field) {
			t.Errorf("no exclusion of %s among %v", field, fields)
		}
	}
	routes := c.Plan.Routes()
	if len(routes) != 2 || routes[0] != (DurableRoute{ExchangesPipeline, AccountSink, LocalAccountKind}) ||
		routes[1] != (DurableRoute{ConnectionsPipeline, AccountSink, LocalAccountKind}) {
		t.Errorf("routes %+v", routes)
	}
}

func TestWriteContentFalseWritesConnectionsOnly(t *testing.T) {
	c := compiles(t, withRules(`"write_content": false, "remove": {"headers": ["cookie"]}`))
	if routes := c.Plan.Routes(); len(routes) != 1 || routes[0].Pipeline != ConnectionsPipeline {
		t.Errorf("routes %+v, want connections alone", routes)
	}
	if len(c.Plan.Exclusions()) != 1 {
		t.Errorf("the removal is not recorded as an exclusion: %+v", c.Plan.Exclusions())
	}
}

// Removal wins over every other rule and is never a conflict.
func TestRemovalWinsAndIsNeverAConflict(t *testing.T) {
	compiles(t, withRules(`"remove": {"headers": ["x-api-key"]}, "mask": {"headers": {"X-Api-Key": "withheld"}}`))
	compiles(t, withRules(`"remove": {"json": {"response": ["/card"]}}, "mask": {"json": {"response": {"/card/number": "a"}}}`))
	compiles(t, withRules(`"remove": {"headers": ["x-a"]}, "mask": {"headers": {"x-a": "v"}}, "truncate": {"headers": {"x-a": 4}}`))
}

func TestTwoRulesKeepingDifferentValuesForOneFieldAreRefused(t *testing.T) {
	// One header written in two cases is one field.
	_, findings := Compile([]byte(withRules(`"mask": {"headers": {"x-a": "one", "X-A": "two"}}`)), "")
	if f := refused(t, findings, "configuration", "mask.headers.X-A", RuleConflict); !strings.Contains(f.Detail, "configuration mask.headers.x-a") {
		t.Errorf("the refusal does not name the other key: %s", f.Detail)
	}
	_, findings = Compile([]byte(withRules(`"mask": {"headers": {"x-a": "v"}}, "truncate": {"headers": {"x-a": 4}}`)), "")
	refused(t, findings, "configuration", "truncate.headers.x-a", RuleConflict)
	_, findings = Compile([]byte(withRules(`"truncate": {"headers": {"x-a": 4, "X-A": 8}}`)), "")
	refused(t, findings, "configuration", "truncate.headers.X-A", RuleConflict)
	_, findings = Compile([]byte(withRules(`"mask": {"json": {"response": {"/card": "a", "/Card/*": "b"}}}`)), "")
	refused(t, findings, "configuration", "mask.json.response./Card/*", RuleConflict)
	// The same value twice is one rule, not a conflict.
	compiles(t, withRules(`"mask": {"headers": {"x-a": "v", "X-A": "v"}}`))
}

func TestOneOperationPastItsLimitIsRefusedInTheUsersTerms(t *testing.T) {
	var names []string
	for i := range MaxRuleNames {
		names = append(names, fmt.Sprintf("%q", fmt.Sprintf("p%d", i)))
	}
	compiles(t, withRules(`"remove": {"query": [`+strings.Join(names, ", ")+`]}`))
	_, findings := Compile([]byte(withRules(`"remove": {"query": [`+strings.Join(names, ", ")+`, "p0", "extra"]}`)), "")
	refused(t, findings, "configuration", fmt.Sprintf("remove.query[%d]", MaxRuleNames+1), LimitExceeded)
}

func TestFormAndRequestJSONRulesCompileToTheOneRequestBodyOperation(t *testing.T) {
	c := compiles(t, withRules(`"remove": {"form": ["card_number"], "json": {"request": ["/card/number"]}},
		"mask": {"json": {"request": {"/email": "withheld"}}}`))
	slots := exchangeSlots(t, c)
	if got := implementations(slots); !slices.Equal(got, []string{RequestBodyFields}) {
		t.Fatalf("operations %v", got)
	}
	a := slots[0].Arguments
	if !slices.Equal(a.Names, []string{"card_number"}) || !slices.Equal(a.Pointers, []string{"/card/number"}) ||
		!slices.Equal(a.Masks, []JSONMask{{Pointer: "/email", Value: "withheld"}}) {
		t.Errorf("arguments %+v", a)
	}
}

// The coverage assertion reads the documents as parsed: a plan missing the
// operation, or the exclusion, for a removal a document wrote fails closed.
func TestAPlanThatDoesNotEnforceAWrittenRemovalFailsClosed(t *testing.T) {
	c := compiles(t, withRules(`"remove": {"headers": ["authorization"]}`))
	documents := []document{{name: "configuration", rules: c.File.Rules}}
	if failures := assertCoverage(documents, c.Plan); len(failures) != 0 {
		t.Fatalf("wiring, not the property: the compiled plan fails its own assertion: %+v", failures)
	}
	noSlot := *c.Plan
	noSlot.resolved.Pipelines = slices.Clone(c.Plan.Pipelines())
	noSlot.resolved.Pipelines[0].Slots = nil
	refused(t, assertCoverage(documents, &noSlot), "configuration", "remove.headers[0]", InternalDefect)
	noExclusion := *c.Plan
	noExclusion.exclusions = nil
	refused(t, assertCoverage(documents, &noExclusion), "configuration", "remove.headers[0]", InternalDefect)
}

// Reload applies a file that only adds a watch entry: the revision binds the
// rules, write_content and the extensions, and not the watch list or a limit.
func TestTheProcessingRevisionBindsTheRulesAndNotTheWatchList(t *testing.T) {
	base := compiles(t, withRules(`"mask": {"headers": {"x-a": "v"}}`))
	added := compiles(t, strings.Replace(withRules(`"mask": {"headers": {"x-a": "v"}}`), `"watch": [`,
		`"watch": [{"name": "second", "exe": "/usr/bin/other"}, `, 1))
	changed := compiles(t, withRules(`"mask": {"headers": {"x-a": "w"}}`))
	if base.ProcessingRevision != added.ProcessingRevision {
		t.Errorf("adding a watch entry changed the processing revision")
	}
	if base.ProcessingRevision == changed.ProcessingRevision {
		t.Errorf("changing a mask value kept the processing revision")
	}
	workers := compiles(t, withRules(`"mask": {"headers": {"x-a": "v"}}, "limits": {"workers": 4}`))
	if base.ProcessingRevision != workers.ProcessingRevision {
		t.Errorf("changing limits.workers changed the processing revision")
	}

	directory := t.TempDir()
	executable(t, directory, "inventory")
	entry := func(timeout int) string {
		return fmt.Sprintf(`"extensions": [{"name": "inventory", "command": ["./inventory"], `+
			`"fields": ["request.line"], "timeout_ms": %d}]`, timeout)
	}
	extended, findings := Compile([]byte(withRules(entry(100))), directory)
	retimed, findings2 := Compile([]byte(withRules(entry(200))), directory)
	if len(findings) != 0 || len(findings2) != 0 {
		t.Fatalf("wiring, not the property: an extension entry was refused: %+v %+v", findings, findings2)
	}
	plain := compiles(t, minimal)
	if extended.ProcessingRevision == plain.ProcessingRevision {
		t.Errorf("adding an extension kept the processing revision")
	}
	if extended.ProcessingRevision == retimed.ProcessingRevision {
		t.Errorf("changing an extension's timeout_ms kept the processing revision")
	}
}

// reasons is every reason the reader and the compiler give, as CONFIG.md's
// Refusals table lists them.
var reasons = []Reason{
	UnknownVersion, Malformed, UnknownKey, DuplicateKey, WrongType, TrailingContent, MissingKey, InvalidValue,
	LimitExceeded, DuplicateName, RuleConflict, ConfigurationTooLarge, CommandNotExecutable, InternalDefect,
}

// CONFIG.md's Refusals table and the reasons the reader and the compiler
// give are one set.
func TestTheSpecificationAndTheReasonsAgree(t *testing.T) {
	content, err := os.ReadFile("CONFIG.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, found := strings.Cut(string(content), "\n## Refusals\n")
	if !found {
		t.Fatal("wiring, not the property: CONFIG.md has no Refusals section")
	}
	section, _, _ = strings.Cut(section, "\n## ")
	var written []Reason
	for _, line := range strings.Split(section, "\n") {
		if match := regexp.MustCompile("^\\| `([a-z_]+)` \\|").FindStringSubmatch(line); match != nil {
			written = append(written, Reason(match[1]))
		}
	}
	if len(written) < 10 {
		t.Fatalf("wiring, not the property: the Refusals table lists %d reasons", len(written))
	}
	if !slices.Equal(written, reasons) {
		t.Errorf("CONFIG.md lists %v and the package gives %v", written, reasons)
	}
}
