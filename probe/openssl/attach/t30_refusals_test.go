//go:build attach

package attach_test

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/contract/config"
)

// t30Refusal is one file the format refuses, beside the neighbouring file one
// change away that activates and writes.
type t30Refusal struct {
	name   string
	reason config.Reason
	// named is every key and document the refusal must name, as contract 52
	// has it: the key and index of one rule, and both documents and both keys
	// of a conflict.
	named []string
	// build writes the refused (fault true) or neighbouring file into c and
	// returns its bytes and the packs it enables.
	build func(t *testing.T, c configured, watch []map[string]any, fault bool) ([]byte, []config.Supplied)
}

// t30Unnamed is the names text does not carry whole. A name continued by more
// of a key does not count: mask.json.response./card is not named by
// mask.json.response./card/number, nor remove.headers[3] by remove.headers[32].
func t30Unnamed(text string, named []string) []string {
	var unnamed []string
	for _, name := range named {
		whole := regexp.MustCompile(`(^|[^A-Za-z0-9_-])` + regexp.QuoteMeta(name) + `($|[^A-Za-z0-9_/*-])`)
		if !whole.MatchString(text) {
			unnamed = append(unnamed, name)
		}
	}
	return unnamed
}

// t30Replace is content with old replaced once by new, failing if old is not
// there exactly once.
func t30Replace(t *testing.T, content []byte, old, new string) []byte {
	t.Helper()
	if n := bytes.Count(content, []byte(old)); n != 1 {
		t.Fatalf("wiring: %q occurs %d times in %s", old, n, content)
	}
	return bytes.Replace(content, []byte(old), []byte(new), 1)
}

func t30Refusals() []t30Refusal {
	simple := func(keys func(fault bool) map[string]any) func(*testing.T, configured, []map[string]any, bool) ([]byte, []config.Supplied) {
		return func(t *testing.T, c configured, watch []map[string]any, fault bool) ([]byte, []config.Supplied) {
			return t30Encoded(t, t30Document(c, watch, keys(fault))), nil
		}
	}
	headers := func(n int) []string {
		names := make([]string, n)
		for i := range names {
			names[i] = fmt.Sprintf("x-t30-%d", i)
		}
		return names
	}
	base := map[string]any{"write_content": true, "remove": map[string]any{"headers": []string{"authorization"}}}
	return []t30Refusal{
		{"an unknown key at the top level", config.UnknownKey, []string{"remvoe"},
			func(t *testing.T, c configured, watch []map[string]any, fault bool) ([]byte, []config.Supplied) {
				content := t30Encoded(t, t30Document(c, watch, base))
				if fault {
					content = t30Replace(t, content, `"remove":`, `"remvoe":`)
				}
				return content, nil
			}},
		{"an unknown key inside remove", config.UnknownKey, []string{"remove.heders"},
			func(t *testing.T, c configured, watch []map[string]any, fault bool) ([]byte, []config.Supplied) {
				content := t30Encoded(t, t30Document(c, watch, base))
				if fault {
					content = t30Replace(t, content, `"headers":`, `"heders":`)
				}
				return content, nil
			}},
		{"a duplicate key at the top level", config.DuplicateKey, []string{"write_content"},
			func(t *testing.T, c configured, watch []map[string]any, fault bool) ([]byte, []config.Supplied) {
				content := t30Encoded(t, t30Document(c, watch, base))
				if fault {
					content = t30Replace(t, content, `"write_content":true`, `"write_content":true,"write_content":true`)
				}
				return content, nil
			}},
		{"a duplicate key inside remove", config.DuplicateKey, []string{"remove.headers"},
			func(t *testing.T, c configured, watch []map[string]any, fault bool) ([]byte, []config.Supplied) {
				content := t30Encoded(t, t30Document(c, watch, base))
				if fault {
					content = t30Replace(t, content, `"remove":{`, `"remove":{"headers":["cookie"],`)
				}
				return content, nil
			}},
		{"a wrong type", config.WrongType, []string{"write_content"}, simple(func(fault bool) map[string]any {
			return map[string]any{"write_content": map[bool]any{true: "yes", false: true}[fault]}
		})},
		// Trailing content follows every key, so the refusal names its reason.
		{"trailing content", config.TrailingContent, []string{string(config.TrailingContent)},
			func(t *testing.T, c configured, watch []map[string]any, fault bool) ([]byte, []config.Supplied) {
				content := t30Encoded(t, t30Document(c, watch, base))
				if fault {
					content = append(content, []byte(`{"write_content":false}`)...)
				}
				return content, nil
			}},
		{"a missing required key", config.MissingKey, []string{"watch"},
			func(t *testing.T, c configured, watch []map[string]any, fault bool) ([]byte, []config.Supplied) {
				document := t30Document(c, watch, base)
				if fault {
					delete(document, "watch")
				}
				return t30Encoded(t, document), nil
			}},
		{"a mask and a truncation of one header", config.RuleConflict,
			[]string{"truncate.headers.x-api-key", "mask.headers.x-api-key"}, simple(func(fault bool) map[string]any {
				keys := map[string]any{"mask": map[string]any{"headers": map[string]any{"x-api-key": "withheld"}}}
				if fault {
					keys["truncate"] = map[string]any{"headers": map[string]any{"x-api-key": 8}}
				}
				return keys
			})},
		{"the operator and a pack masking one header differently", config.RuleConflict,
			[]string{"t30-masking", "configuration", "mask.headers.x-api-key"},
			func(t *testing.T, c configured, watch []map[string]any, fault bool) ([]byte, []config.Supplied) {
				value := map[bool]string{true: "hidden", false: "withheld"}[fault]
				pack := t30PackBytes(t, c, "t30-masking", map[string]any{"mask": map[string]any{"headers": map[string]any{"x-api-key": value}}})
				return t30Encoded(t, t30Document(c, watch, map[string]any{
					"packs": []string{"t30-masking"},
					"mask":  map[string]any{"headers": map[string]any{"x-api-key": "withheld"}},
				})), []config.Supplied{pack}
			}},
		// The pack writes the header in another case, so the two are one field
		// only under the header names' case folding.
		{"the operator and a pack truncating one header differently", config.RuleConflict,
			[]string{"t30-truncating", "configuration", "truncate.headers.x-trace-id", "truncate.headers.X-Trace-Id"},
			func(t *testing.T, c configured, watch []map[string]any, fault bool) ([]byte, []config.Supplied) {
				length := map[bool]int{true: 4, false: 8}[fault]
				pack := t30PackBytes(t, c, "t30-truncating", map[string]any{"truncate": map[string]any{"headers": map[string]any{"X-Trace-Id": length}}})
				return t30Encoded(t, t30Document(c, watch, map[string]any{
					"packs":    []string{"t30-truncating"},
					"truncate": map[string]any{"headers": map[string]any{"x-trace-id": 8}},
				})), []config.Supplied{pack}
			}},
		{"overlapping pointers masked differently", config.RuleConflict,
			[]string{"mask.json.response./card/number", "mask.json.response./card"}, simple(func(fault bool) map[string]any {
				masks := map[string]any{"/card/number": "withheld", "/email": "hidden"}
				if fault {
					masks = map[string]any{"/card/number": "withheld", "/card": "hidden"}
				}
				return map[string]any{"mask": map[string]any{"json": map[string]any{"response": masks}}}
			})},
		{"a limit a user can reach", config.LimitExceeded,
			[]string{fmt.Sprintf("remove.headers[%d]", config.MaxRemovedHeaders)}, simple(func(fault bool) map[string]any {
				n := config.MaxRemovedHeaders
				if fault {
					n++
				}
				return map[string]any{"remove": map[string]any{"headers": headers(n)}}
			})},
		{"a malformed pointer", config.InvalidValue, []string{"remove.json.request[0]"}, simple(func(fault bool) map[string]any {
			pointer := map[bool]string{true: "card/number", false: "/card/number"}[fault]
			return map[string]any{"remove": map[string]any{"json": map[string]any{"request": []string{pointer}}}}
		})},
		// A configured name is any printable ASCII byte except space.
		{"a malformed parameter name", config.InvalidValue, []string{"remove.query[0]"}, simple(func(fault bool) map[string]any {
			name := map[bool]string{true: "tok en", false: "tok&en"}[fault]
			return map[string]any{"remove": map[string]any{"query": []string{name}}}
		})},
		{"a relative output", config.InvalidValue, []string{"output"},
			func(t *testing.T, c configured, watch []map[string]any, fault bool) ([]byte, []config.Supplied) {
				document := t30Document(c, watch, base)
				if fault {
					document["output"] = "state"
				}
				return t30Encoded(t, document), nil
			}},
		{"an old-format file", config.UnknownVersion, []string{config.FileVersion},
			func(t *testing.T, c configured, watch []map[string]any, fault bool) ([]byte, []config.Supplied) {
				document := t30Document(c, watch, base)
				if fault {
					document["version"] = "observer.config/draft"
				}
				return t30Encoded(t, document), nil
			}},
	}
}

// Row 11 (b): every refusal the format has happens at live activation, before
// capture: the program is started in an envelope that would let it activate,
// so only the file can stop it; it exits non-zero naming what the user wrote,
// creates no output directory, and is never an internal defect. The published
// reader refuses the same file for the same reason. Beside each is the
// neighbouring file one change away, which activates and writes the exchange -
// or a program refusing everything would pass.
func TestT30EveryRefusalHappensAtActivationBesideANeighbourThatWrites(t *testing.T) {
	binary := built(t)
	port := t30Serving(t)
	right := map[string]string{"memory.max": "1073741824", "memory.swap.max": "0"}
	for _, tc := range t30Refusals() {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("refused", func(t *testing.T) {
				client := speaking(t, port)
				c := configuring(t, target("client", client.process))
				content, packs := tc.build(t, c, []map[string]any{t30Watch("client", client.process)}, true)
				t30Written(t, c, content)
				compiled, findings := config.Compile(content, packs)
				text := fmt.Sprint(findings)
				if unnamed := t30Unnamed(text, tc.named); compiled != nil || !strings.Contains(text, string(tc.reason)) || len(unnamed) != 0 {
					t.Fatalf("the published reader does not refuse the fixture as %s naming %q - a fixture without the "+
						"fault, or a reader missing it; nothing below is measured: %s", tc.reason, unnamed, text)
				}
				launched := t18Launch(t, binary, t18Envelope(t, right), "start", c.path)
				if _, activated := launched.activation(t, 30*time.Second); activated {
					t.Fatalf("the program activated over %s", tc.name)
				}
				err := launched.exit(t, 30*time.Second)
				said := launched.stderr.String()
				if unnamed := t30Unnamed(said, tc.named); err == nil || len(unnamed) != 0 {
					t.Errorf("the start ended %v, not naming %q:\n%s", err, unnamed, said)
				}
				if strings.Contains(said, string(config.InternalDefect)) {
					t.Errorf("a user's error is reported as an internal defect:\n%s", said)
				}
				if _, err := os.Stat(c.directory); !os.IsNotExist(err) {
					t.Errorf("the refused start made its output directory (%v)", err)
				}
			})
			t.Run("neighbour", func(t *testing.T) {
				client := speaking(t, port)
				c := configuring(t, target("client", client.process))
				content, packs := tc.build(t, c, []map[string]any{t30Watch("client", client.process)}, false)
				t30Written(t, c, content)
				t30Admitted(t, binary, c, content, packs, "the neighbour one change from the refused file is refused "+
					"too, so the refusal beside it may be a program refusing everything")
				w := t30Started(t, binary, c)
				t30Send(t, client, t30Get("/t30-neighbour", "X-Public: "+t30Permitted))
				t30Find(t, t30Finished(t, binary, c, w, client, 2), "/t30-neighbour")
			})
		})
	}
}

// Removal wins over every other rule and is never a conflict: the operator
// removes x-api-key while a pack masks it, and the request removes /card while
// it masks /card/number. Both files activate, and what is removed is absent -
// no mask value in its place - with the protected marker crossing no write. A
// reader that refuses too much fails here.
func TestT30RemovalWinsAndIsNeverAConflict(t *testing.T) {
	binary := built(t)
	port := t30Serving(t)
	t.Run("the operator removes a header a pack masks", func(t *testing.T) {
		client := speaking(t, port)
		c := configuring(t, target("client", client.process))
		pack := t30PackBytes(t, c, "t30-masking", map[string]any{"mask": map[string]any{"headers": map[string]any{"x-api-key": "withheld"}}})
		content := t30Written(t, c, t30Encoded(t, t30Document(c, []map[string]any{t30Watch("client", client.process)}, map[string]any{
			"packs": []string{"t30-masking"}, "remove": map[string]any{"headers": []string{"x-api-key"}},
		})))
		t30Admitted(t, binary, c, content, []config.Supplied{pack}, "removal is refused where it wins over a mask")
		w := t30Started(t, binary, c)
		t30Send(t, client, t30Get("/t30-removed", "X-Api-Key: "+t30Protected, "X-Public: "+t30Permitted))
		one := t30Find(t, t30Finished(t, binary, c, w, client, 2), "/t30-removed")
		if got := one.Request.header("x-api-key"); len(got) != 0 || !one.excluded("request", "message.headers.x-api-key", "removed") {
			t.Errorf("x-api-key is %q with exclusions %v, want removed", got, one.Exclusions)
		}
		t25Clean(t, w)
	})
	t.Run("the request removes /card and masks /card/number", func(t *testing.T) {
		client := speaking(t, port)
		c := configuring(t, target("client", client.process))
		content := t30Written(t, c, t30Encoded(t, t30Document(c, []map[string]any{t30Watch("client", client.process)}, map[string]any{
			"remove": map[string]any{"json": map[string]any{"request": []string{"/card"}}},
			"mask":   map[string]any{"json": map[string]any{"request": map[string]any{"/card/number": "withheld"}}},
		})))
		t30Admitted(t, binary, c, content, nil, "removal is refused where it wins over a mask")
		w := t30Started(t, binary, c)
		t30Send(t, client, t30Post("/t30-card", []string{"application/json"},
			`{"card":{"number":"`+t30Protected+`"},"note":"`+t30Permitted+`"}`))
		one := t30Find(t, t30Finished(t, binary, c, w, client, 2), "/t30-card")
		kept := one.Request.kept(t)
		if strings.Contains(kept, `"card"`) || strings.Contains(kept, "withheld") || !strings.Contains(kept, t30Permitted) ||
			!one.excluded("request", "message.body.json/card", "removed") {
			t.Errorf("the body kept is %q with exclusions %v, want /card removed and note kept", kept, one.Exclusions)
		}
		if n := t30Crossed(w, t30Protected); n != 0 {
			t.Errorf("the protected marker crossed a write %d times", n)
		}
		t25Clean(t, w)
	})
}
