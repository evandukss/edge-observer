package processing_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

// listed is n JSON strings, prefix and index.
func listed(prefix string, n int) string {
	var items []string
	for i := range n {
		items = append(items, fmt.Sprintf("%q", fmt.Sprintf("%s%d", prefix, i)))
	}
	return "[" + strings.Join(items, ", ") + "]"
}

// keyed is n members, the key prefix and index, each with the value value(i).
func keyed(prefix string, n int, value func(i int) string) string {
	var items []string
	for i := range n {
		items = append(items, fmt.Sprintf("%q: %s", fmt.Sprintf("%s%d", prefix, i), value(i)))
	}
	return "{" + strings.Join(items, ", ") + "}"
}

// largest is a configuration with every rule key at its limit and every limit
// at its largest value. With form rules, the form and
// the request JSON rules compile to one operation; without them, every rule
// key compiles to operations of its own.
func largest(form bool) string {
	value := func(i int) string { return fmt.Sprintf("%q", fmt.Sprintf("v%d", i)) }
	remove := `"headers": ` + listed("x-r", config.MaxRemovedHeaders) +
		`, "query": ` + listed("q", config.MaxRuleNames) + `, "query_string": true` +
		`, "json": {"request": ` + listed("/r", config.MaxRulePointers) + `, "response": ` + listed("/r", config.MaxRulePointers) + `}` +
		`, "bodies": ["request", "response"], "body_values": ["request", "response"]`
	if form {
		remove += `, "form": ` + listed("f", config.MaxRuleNames)
	}
	return `"remove": {` + remove + `}` +
		`, "mask": {"headers": ` + keyed("x-m", config.MaxMaskedHeaders, value) +
		`, "json": {"request": ` + keyed("/m", config.MaxRulePointers, value) + `, "response": ` + keyed("/m", config.MaxRulePointers, value) + `}}` +
		`, "truncate": {"headers": ` + keyed("x-t", config.MaxTruncatedHeaders, func(i int) string { return fmt.Sprint(i + 1) }) + `}` +
		fmt.Sprintf(`, "limits": {"output_mib": %d, "events": %d, "state_every_seconds": %d, "workers": %d}`,
			config.MaxOutputMiB, config.MaxEvents, config.MaxStateEverySeconds, config.MaxWorkers)
}

// The largest configuration a user can write compiles, the internal layer
// never refusing it, and an exchange goes through every operation to approved
// output. Without form rules every key compiles to operations of its own, the
// most any configuration compiles to.
func TestTheLargestConfigurationCompilesAndWrites(t *testing.T) {
	for _, form := range []bool{true, false} {
		t.Run(map[bool]string{true: "with form rules", false: "every key its own operation"}[form], func(t *testing.T) {
			document := `{"version": "observer.config/1", "output": "/var/lib/observer", ` +
				`"watch": [{"name": "api", "exe": "/usr/bin/php"}], ` + largest(form) + `}`
			if len(document) > config.MaxProcessingBytes {
				t.Fatalf("wiring, not the property: the file is %d bytes, over the budget", len(document))
			}
			compiled, findings := config.Compile([]byte(document), "")
			if len(findings) != 0 {
				t.Fatalf("PROPERTY: the largest configuration was refused: %+v", findings)
			}
			var slots []config.EffectiveSlot
			for _, p := range compiled.Plan.Pipelines() {
				if p.Name == config.ExchangesPipeline {
					slots = p.Slots
				}
			}
			if len(slots) > config.MaxCompiledSlots {
				t.Errorf("the rules compiled to %d operations, above the internal bound %d", len(slots), config.MaxCompiledSlots)
			}
			if observer := compiled.Plan.Observer(); observer.ApprovedOutputBoundMiB != config.MaxOutputMiB ||
				observer.AdmittedEventLimit != config.MaxEvents || observer.StateEverySeconds != config.MaxStateEverySeconds ||
				observer.Workers != config.MaxWorkers {
				t.Errorf("the limits resolved to %+v", observer)
			}
			out := &outputLog{}
			w, store := worker(t, compiled.Plan, out)
			enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
			counted(t, drain(t, w), out, 1, 1)
			t.Logf("%d operations; one exchange and its connection record written", len(slots))
		})
	}
}
