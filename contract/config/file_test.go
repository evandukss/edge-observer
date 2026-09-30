package config

import (
	"fmt"
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

func pack(name, rules string) Supplied {
	body := fmt.Sprintf(`{"version": "observer.pack/1", "name": %q`, name)
	if rules != "" {
		body += ", " + rules
	}
	return Supplied{Name: name, Content: []byte(body + "}")}
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

func compiles(t *testing.T, configuration string, packs ...Supplied) *Compiled {
	t.Helper()
	compiled, findings := Compile([]byte(configuration), packs)
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

func TestEachDocumentIsRefusedAtAnotherVersionNamingItsOwn(t *testing.T) {
	_, findings := ReadFile([]byte(`{"version": "observer.config/draft", "output": "/x", "watch": []}`))
	if f := refused(t, findings, "configuration", "version", UnknownVersion); !strings.Contains(f.Detail, FileVersion) {
		t.Errorf("the refusal does not name %s: %s", FileVersion, f.Detail)
	}
	_, findings = ReadFile([]byte(`{"version": "observer.pack/1", "name": "credentials"}`))
	if f := refused(t, findings, "configuration", "version", UnknownVersion); !strings.Contains(f.Detail, "a pack") {
		t.Errorf("a pack given as a configuration is not named as a pack: %s", f.Detail)
	}
	_, findings = ReadPack(Supplied{Name: "p", Content: []byte(`{"version": "observer.pack/draft", "name": "p"}`)})
	if f := refused(t, findings, "pack:p", "version", UnknownVersion); !strings.Contains(f.Detail, PackVersion) {
		t.Errorf("the refusal does not name %s: %s", PackVersion, f.Detail)
	}
	_, findings = ReadPack(Supplied{Name: "p", Content: []byte(minimal)})
	if f := refused(t, findings, "pack:p", "version", UnknownVersion); !strings.Contains(f.Detail, "a configuration") {
		t.Errorf("a configuration given as a pack is not named as a configuration: %s", f.Detail)
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
		file.Limits != (Limits{DefaultApprovedOutputBoundMiB, DefaultAdmittedEventLimit, DefaultStateEverySeconds}) {
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
	  "limits": {"output_mib": 64, "events": 16384, "state_every_seconds": 30},
	  "packs": ["credentials"]}`,
		pack("credentials", `"remove": {"headers": ["authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"]}`))
	want := []string{RemoveHeaders, RemoveQueryParameters, RequestBodyFields, RemoveJSONFields, ReplaceHeaderValues,
		ReplaceJSONValues, TruncateHeaderValues}
	if got := implementations(exchangeSlots(t, c)); !slices.Equal(got, want) {
		t.Errorf("operations %v, want %v", got, want)
	}
	if got := exchangeSlots(t, c)[0].Arguments.Headers; !slices.Equal(got,
		[]string{"authorization", "cookie", "proxy-authorization", "set-cookie", "x-api-key"}) {
		t.Errorf("removed headers %v", got)
	}
	var fields []string
	for _, e := range c.Plan.Exclusions() {
		fields = append(fields, e.Field)
	}
	for _, field := range []string{"message.headers.x-api-key", "message.query.token", "message.form.card_number",
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
	compiles(t, withRules(`"remove": {"headers": ["x-api-key"]}, "packs": ["masking"]`),
		pack("masking", `"mask": {"headers": {"x-api-key": "withheld"}}`))
	compiles(t, withRules(`"remove": {"json": {"response": ["/card"]}}, "mask": {"json": {"response": {"/card/number": "a"}}}`))
	compiles(t, withRules(`"remove": {"headers": ["x-a"]}, "mask": {"headers": {"x-a": "v"}}, "truncate": {"headers": {"x-a": 4}}`))
}

func TestTwoRulesKeepingDifferentValuesForOneFieldAreRefused(t *testing.T) {
	_, findings := Compile([]byte(withRules(`"mask": {"headers": {"x-a": "one"}}, "packs": ["other"]`)),
		[]Supplied{pack("other", `"mask": {"headers": {"X-A": "two"}}`)})
	if f := refused(t, findings, "pack:other", "mask.headers.X-A", RuleConflict); !strings.Contains(f.Detail, "configuration mask.headers.x-a") {
		t.Errorf("the refusal does not name the other document and key: %s", f.Detail)
	}
	_, findings = Compile([]byte(withRules(`"mask": {"headers": {"x-a": "v"}}, "truncate": {"headers": {"x-a": 4}}`)), nil)
	refused(t, findings, "configuration", "truncate.headers.x-a", RuleConflict)
	_, findings = Compile([]byte(withRules(`"truncate": {"headers": {"x-a": 4}}, "packs": ["p"]`)),
		[]Supplied{pack("p", `"truncate": {"headers": {"x-a": 8}}`)})
	refused(t, findings, "pack:p", "truncate.headers.x-a", RuleConflict)
	_, findings = Compile([]byte(withRules(`"mask": {"json": {"response": {"/card": "a", "/Card/*": "b"}}}`)), nil)
	refused(t, findings, "configuration", "mask.json.response./Card/*", RuleConflict)
	// The same value twice is one rule, not a conflict.
	compiles(t, withRules(`"mask": {"headers": {"x-a": "v"}}, "packs": ["p"]`), pack("p", `"mask": {"headers": {"X-A": "v"}}`))
}

func TestOneOperationPastItsLimitIsRefusedInTheUsersTerms(t *testing.T) {
	var names []string
	for i := range MaxRuleNames {
		names = append(names, fmt.Sprintf("%q", fmt.Sprintf("p%d", i)))
	}
	compiles(t, withRules(`"remove": {"query": [`+strings.Join(names, ", ")+`]}`))
	_, findings := Compile([]byte(withRules(`"remove": {"query": [`+strings.Join(names, ", ")+`]}, "packs": ["more"]`)),
		[]Supplied{pack("more", `"remove": {"query": ["p0", "extra"]}`)})
	refused(t, findings, "pack:more", "remove.query[1]", LimitExceeded)
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
// rules, write_content and the packs, and not the watch list.
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
	packed := compiles(t, withRules(`"packs": ["p"]`), pack("p", `"remove": {"headers": ["a"]}`))
	repacked := compiles(t, withRules(`"packs": ["p"]`), pack("p", `"remove": {"headers": ["b"]}`))
	if packed.ProcessingRevision == repacked.ProcessingRevision {
		t.Errorf("changing a pack's bytes kept the processing revision")
	}
}

func TestAPackIsReadUnderTheNameItIsEnabledBy(t *testing.T) {
	_, findings := Compile([]byte(withRules(`"packs": ["credentials"]`)), nil)
	refused(t, findings, "configuration", "packs[0]", UnknownPack)
	_, findings = Compile([]byte(withRules(`"packs": ["credentials"]`)),
		[]Supplied{{Name: "credentials", Content: []byte(`{"version": "observer.pack/1", "name": "other"}`)}})
	refused(t, findings, "pack:credentials", "name", PackNameMismatch)
}
