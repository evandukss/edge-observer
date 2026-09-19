package record

import (
	"testing"

	"github.com/evandukss/edge-observer/connection"
)

// A name shared by two source values is a fact merged away, so each vocabulary
// is read in both directions.
func TestEveryVocabularyNameIsOneValue(t *testing.T) {
	check := func(what string, names []string) {
		held := map[string]bool{}
		for _, n := range names {
			if n == "" || held[n] {
				t.Errorf("%s: the name %q is empty or held by two values", what, n)
			}
			held[n] = true
		}
	}
	values := func(m any) []string {
		var out []string
		switch table := m.(type) {
		case map[connection.Ending]string:
			for _, v := range table {
				out = append(out, v)
			}
		case map[connection.State]string:
			for _, v := range table {
				out = append(out, v)
			}
		case map[connection.Reason]string:
			for _, v := range table {
				out = append(out, v)
			}
		case map[connection.Joinability]string:
			for _, v := range table {
				out = append(out, v)
			}
		case map[connection.JoinReason]string:
			for _, v := range table {
				out = append(out, v)
			}
		case map[connection.Source]string:
			for _, v := range table {
				out = append(out, v)
			}
		case map[connection.Basis]string:
			for _, v := range table {
				out = append(out, v)
			}
		case map[connection.Positions]string:
			for _, v := range table {
				out = append(out, v)
			}
		default:
			t.Fatalf("no reader for %T", m)
		}
		return out
	}
	for what, table := range map[string]any{"ending": endings, "state": states, "reason": reasons, "join": joins,
		"join reason": joinReasons, "source": sources, "basis": bases, "positions": positions} {
		check(what, values(table))
	}
}
