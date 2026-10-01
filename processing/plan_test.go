package processing_test

import (
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/processing"
)

// compileRules compiles a configuration writing these rules, given as the
// configuration's own members ("remove": {...}), or none. Its plan is the
// exchanges pipeline holding the rules in the fixed order, beside the
// connections pipeline.
func compileRules(t *testing.T, rules string) (*config.ProcessingPlan, []config.Finding) {
	t.Helper()
	document := `{"version": "observer.config/1", "output": "/var/lib/observer", ` +
		`"watch": [{"name": "api", "exe": "/usr/bin/php"}]`
	if rules != "" {
		document += ", " + rules
	}
	compiled, findings := config.Compile([]byte(document+"}"), "")
	if compiled == nil {
		return nil, findings
	}
	return compiled.Plan, findings
}

// rulesPlan is compileRules' plan, failing the case as wiring where the rules
// are refused.
func rulesPlan(t *testing.T, rules string) *config.ProcessingPlan {
	t.Helper()
	plan, findings := compileRules(t, rules)
	if plan == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: the fixture's rules were refused: %+v", findings)
	}
	return plan
}

// routed is the log's records of one pipeline, in the order written.
func (o *outputLog) routed(pipeline string) ([]processing.Artifact, [][]byte) {
	var artifacts []processing.Artifact
	var lines [][]byte
	for i, a := range o.artifacts {
		if a.Route.Pipeline == pipeline {
			artifacts = append(artifacts, a)
			lines = append(lines, o.lines[i])
		}
	}
	return artifacts, lines
}

// counted requires the worker's written count to be the log's records, and
// the log to hold this many exchange records and this many connection records.
func counted(t *testing.T, o processing.Outcome, out *outputLog, exchanges, connections int) {
	t.Helper()
	gotExchanges, _ := out.routed(config.ExchangesPipeline)
	gotConnections, _ := out.routed(config.ConnectionsPipeline)
	if o.Written != uint64(len(out.artifacts)) || len(gotExchanges) != exchanges || len(gotConnections) != connections {
		t.Fatalf("written %d; exchange records %d, want %d; connection records %d, want %d: %+v", o.Written,
			len(gotExchanges), exchanges, len(gotConnections), connections, o)
	}
}
